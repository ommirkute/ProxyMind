import { useEffect, useState } from "react";
import { api, toast } from "../api";
import { Chip, Empty, ErrorBox, ExchangeLink, Panel, copyText, useAction, useNav } from "../components";

interface ParamSummary { name: string; locations: string[]; requests: number; distinct_values: number; examples: string[]; paths: string[] }
interface Analysis {
  requests: number; urls: number; static_urls: number; dynamic_urls: string[];
  methods: Record<string, number>; statuses: Record<string, number>; content_types: Record<string, number>; params: ParamSummary[];
}
interface Comment { kind: string; text: string; url: string; exchange_id: number; line: number; count: number }
interface Script { kind: string; src?: string; snippet: string; length: number; url: string; exchange_id: number; count: number }
interface Summary { id: number; method: string; host: string; path: string; status: number | null }
interface Clickjack { framable: boolean; reasons: string[]; poc: string }

const TOOLS = [
  ["analyze", "Analyze target"],
  ["comments", "Find comments"],
  ["scripts", "Find scripts"],
  ["refs", "Find references"],
  ["csrf", "CSRF PoC"],
  ["clickjack", "Clickjacking"],
  ["dom", "DOM test"],
] as const;
type Tool = (typeof TOOLS)[number][0];

function download(name: string, text: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/html" }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/** Engagement tools over recorded traffic: nothing is sent. Route arg: "<tool>:<exchange id>". */
export default function Engage() {
  const { arg } = useNav();
  const [tool, setTool] = useState<Tool>("analyze");
  const [exchange, setExchange] = useState("");
  const [host, setHost] = useState("");
  const [inScope, setInScope] = useState(true);
  useEffect(() => {
    const [t, id] = String(arg ?? "").split(":");
    if (TOOLS.some(([k]) => k === t)) setTool(t as Tool);
    if (id) setExchange(id);
  }, [arg]);
  const filter = { host: host || undefined, in_scope: inScope };
  return (
    <div className="content">
      <Panel title="Engagement tools">
        <div className="tabs" role="tablist">
          {TOOLS.map(([k, label]) => (
            <button key={k} role="tab" className={`tab ${tool === k ? "active" : ""}`} onClick={() => setTool(k)} data-testid={`engage-tab-${k}`}>{label}</button>
          ))}
        </div>
        {["analyze", "comments", "scripts"].includes(tool) && (
          <div className="row small">
            <input aria-label="Engage host" placeholder="host contains (optional)" value={host} onChange={(e) => setHost(e.target.value)} style={{ width: 220 }} />
            <label><input type="checkbox" checked={inScope} onChange={(e) => setInScope(e.target.checked)} /> in scope only</label>
          </div>
        )}
        {["refs", "csrf", "clickjack", "dom"].includes(tool) && (
          <div className="row small">
            <span>Exchange</span>
            <input aria-label="Engage exchange" value={exchange} onChange={(e) => setExchange(e.target.value)} style={{ width: 90 }} />
            <span className="muted">(or right-click a row in HTTP history)</span>
          </div>
        )}
        <p className="small muted">These tools read recorded traffic; they send nothing.</p>
      </Panel>
      {tool === "analyze" && <AnalyzeTarget filter={filter} />}
      {tool === "comments" && <Comments filter={filter} />}
      {tool === "scripts" && <Scripts filter={filter} />}
      {tool === "refs" && <References exchange={exchange} />}
      {tool === "csrf" && <CsrfPoc exchange={exchange} />}
      {tool === "clickjack" && <ClickjackTest exchange={exchange} />}
      {tool === "dom" && <DomTest exchange={exchange} />}
    </div>
  );
}

function Counts({ title, m }: { title: string; m: Record<string, number> }) {
  return (
    <div className="small">
      <strong>{title}:</strong>{" "}
      {Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, v]) => <span key={k} style={{ marginRight: 8 }}><code>{k}</code> {v}</span>)}
    </div>
  );
}

function AnalyzeTarget({ filter }: { filter: object }) {
  const [r, setR] = useState<Analysis | null>(null);
  const action = useAction();
  const run = () => action.run(async () => setR(await api.post<Analysis>("/engage/analyze", filter)));
  return (
    <Panel title="Analyze target" actions={<button className="btn primary" onClick={run} disabled={action.busy} data-testid="engage-analyze">{action.busy ? "Analyzing…" : "Analyze"}</button>}>
      <ErrorBox error={action.error} />
      {r && (
        <div data-testid="engage-analysis">
          <p className="small">{r.requests} requests · {r.urls} URLs ({r.static_urls} static, {r.dynamic_urls.length} take input) · {r.params.length} parameters</p>
          <Counts title="Methods" m={r.methods} />
          <Counts title="Statuses" m={r.statuses} />
          <Counts title="Content types" m={r.content_types} />
          <h3>Parameters</h3>
          <table className="grid">
            <thead><tr><th>Name</th><th>Where</th><th>Requests</th><th>Values</th><th>Examples</th><th>Sent to</th></tr></thead>
            <tbody>
              {r.params.slice(0, 300).map((p) => (
                <tr key={p.name}>
                  <td className="mono">{p.name}</td>
                  <td>{p.locations.map((l) => <Chip key={l} value={l} />)}</td>
                  <td>{p.requests}</td>
                  <td>{p.distinct_values}</td>
                  <td className="small mono">{p.examples.join(", ")}</td>
                  <td className="small mono">{p.paths.join(" ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3>URLs that take input</h3>
          <ul className="small mono">{r.dynamic_urls.map((u) => <li key={u}>{u}</li>)}</ul>
        </div>
      )}
    </Panel>
  );
}

function Comments({ filter }: { filter: object }) {
  const [r, setR] = useState<Comment[] | null>(null);
  const action = useAction();
  const run = () => action.run(async () => setR(await api.post<Comment[]>("/engage/comments", filter)));
  return (
    <Panel title="Comments" actions={<button className="btn primary" onClick={run} disabled={action.busy} data-testid="engage-comments">Find comments</button>}>
      <ErrorBox error={action.error} />
      {r && (r.length === 0 ? <Empty>No comments in recorded HTML, JavaScript or CSS.</Empty> : (
        <table className="grid" data-testid="engage-comment-list">
          <thead><tr><th>Kind</th><th>Comment</th><th>First seen</th><th>Pages</th></tr></thead>
          <tbody>
            {r.map((c, i) => (
              <tr key={i}>
                <td><Chip value={c.kind} /></td>
                <td className="mono small">{c.text}</td>
                <td className="small"><ExchangeLink id={c.exchange_id} /> {c.url} <span className="muted">line {c.line}</span></td>
                <td>{c.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </Panel>
  );
}

function Scripts({ filter }: { filter: object }) {
  const [r, setR] = useState<Script[] | null>(null);
  const action = useAction();
  const run = () => action.run(async () => setR(await api.post<Script[]>("/engage/scripts", filter)));
  return (
    <Panel title="Scripts" actions={<button className="btn primary" onClick={run} disabled={action.busy} data-testid="engage-scripts">Find scripts</button>}>
      <ErrorBox error={action.error} />
      {r && (r.length === 0 ? <Empty>No scripts in recorded pages.</Empty> : (
        <table className="grid">
          <thead><tr><th>Kind</th><th>Script</th><th>First seen</th><th>Pages</th></tr></thead>
          <tbody>
            {r.map((s, i) => (
              <tr key={i}>
                <td><Chip value={s.kind} /></td>
                <td className="mono small">{s.src ?? s.snippet}{s.length > 0 && <span className="muted"> ({s.length} chars)</span>}</td>
                <td className="small"><ExchangeLink id={s.exchange_id} /> {s.url}</td>
                <td>{s.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </Panel>
  );
}

function References({ exchange }: { exchange: string }) {
  const [r, setR] = useState<Summary[] | null>(null);
  const action = useAction();
  const run = () => action.run(async () => setR(await api.post<Summary[]>("/engage/references", { exchange_id: Number(exchange) })));
  return (
    <Panel title="References" actions={<button className="btn primary" onClick={run} disabled={!exchange || action.busy} data-testid="engage-refs">Find references</button>}>
      <ErrorBox error={action.error} />
      {r && (r.length === 0 ? <Empty>No recorded response mentions this page.</Empty> : (
        <ul className="small">{r.map((e) => <li key={e.id}><ExchangeLink id={e.id} /> {e.method} {e.host}{e.path}</li>)}</ul>
      ))}
    </Panel>
  );
}

function CodeOut({ name, html }: { name: string; html: string }) {
  return (
    <>
      <div className="row small">
        <button className="btn" onClick={() => copyText(html).then(() => toast("Copied"))}>Copy</button>
        <button className="btn" onClick={() => download(name, html)}>Download .html</button>
      </div>
      <textarea readOnly className="mono" rows={14} value={html} style={{ width: "100%" }} data-testid="engage-code" />
    </>
  );
}

function CsrfPoc({ exchange }: { exchange: string }) {
  const [technique, setTechnique] = useState("auto");
  const [auto, setAuto] = useState(false);
  const [html, setHtml] = useState<string | null>(null);
  const action = useAction();
  const run = () =>
    action.run(async () =>
      setHtml((await api.post<{ html: string }>("/engage/csrf", { exchange_id: Number(exchange), technique, auto_submit: auto })).html),
    );
  return (
    <Panel title="CSRF proof of concept">
      <div className="row small">
        <select aria-label="CSRF technique" value={technique} onChange={(e) => setTechnique(e.target.value)}>
          <option value="auto">Auto (from the content type)</option>
          <option value="form">HTML form</option>
          <option value="multipart">Multipart form</option>
          <option value="text_plain">text/plain form (JSON bodies)</option>
          <option value="fetch">fetch with credentials</option>
        </select>
        <label><input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> submit automatically</label>
        <button className="btn primary" disabled={!exchange || action.busy} onClick={run} data-testid="engage-csrf">Generate</button>
      </div>
      <ErrorBox error={action.error} />
      {html && <CodeOut name={`csrf-poc-${exchange}.html`} html={html} />}
      {html && <p className="small muted">Open the page in a browser logged in to the target. It only works if the target accepts the request without an unpredictable token, and if its cookies are sent cross-site (SameSite).</p>}
    </Panel>
  );
}

function ClickjackTest({ exchange }: { exchange: string }) {
  const [r, setR] = useState<Clickjack | null>(null);
  const action = useAction();
  const run = () => action.run(async () => setR(await api.post<Clickjack>("/engage/clickjacking", { exchange_id: Number(exchange) })));
  return (
    <Panel title="Clickjacking" actions={<button className="btn primary" onClick={run} disabled={!exchange || action.busy} data-testid="engage-clickjack">Check</button>}>
      <ErrorBox error={action.error} />
      {r && (
        <>
          <p data-testid="engage-clickjack-verdict"><Chip value={r.framable ? "framable" : "protected"} /> {r.reasons.join("; ")}</p>
          <CodeOut name={`clickjacking-${exchange}.html`} html={r.poc} />
          <p className="small muted">The test page frames the target under a decoy button; lower the opacity to see what a click would hit. Browsers also block framing with SameSite cookies, so test it logged in.</p>
        </>
      )}
    </Panel>
  );
}

interface DomFlow { source: string; key?: string; sink: string; value: string; stack: string; exploitable: boolean }
interface DomResult { url: string; flows: DomFlow[]; pollution: string[]; scripts: [string, boolean][]; notes: string[] }

function DomTest({ exchange }: { exchange: string }) {
  const [storage, setStorage] = useState(false);
  const [pollution, setPollution] = useState(true);
  const [r, setR] = useState<DomResult | null>(null);
  const action = useAction();
  const run = () => action.run(async () => setR(await api.post<DomResult>("/dom/test", { exchange_id: Number(exchange), storage, pollution })));
  return (
    <Panel title="DOM sources and sinks" actions={<button className="btn primary" onClick={run} disabled={!exchange || action.busy} data-testid="engage-dom">{action.busy ? "Testing…" : "Test"}</button>}>
      <div className="row small">
        <label><input type="checkbox" checked={pollution} onChange={(e) => setPollution(e.target.checked)} /> try prototype pollution</label>
        <label><input type="checkbox" checked={storage} onChange={(e) => setStorage(e.target.checked)} /> seed web storage reads</label>
      </div>
      <p className="small muted">
        The recorded page runs offline with its recorded scripts (nothing is sent). Markers go into the URL query and fragment, window.name,
        postMessage, query parameters read by name and, if chosen, web storage; any marker that reaches a dangerous sink is listed.
      </p>
      <ErrorBox error={action.error} />
      {r && (
        <div data-testid="engage-dom-result">
          {r.notes.map((n) => <div key={n} className="notice small">{n}</div>)}
          {r.pollution.length > 0 && (
            <div className="error small" data-testid="engage-dom-pollution">Prototype pollution through the URL: {r.pollution.join(", ")}</div>
          )}
          {r.flows.length === 0 ? (
            <Empty>No marker reached a dangerous sink.</Empty>
          ) : (
            <table className="grid">
              <thead><tr><th>Source</th><th>Sink</th><th>Value</th><th>Where</th></tr></thead>
              <tbody>
                {r.flows.map((f, i) => (
                  <tr key={i}>
                    <td>{f.source}{f.key && <> <code>{f.key}</code></>}</td>
                    <td><Chip value={f.sink} /> {f.exploitable && <Chip value="exploitable" />}</td>
                    <td className="mono small" style={{ wordBreak: "break-all" }}>{f.value}</td>
                    <td className="mono small muted" style={{ wordBreak: "break-all" }}>{f.stack}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="small muted">Scripts: {r.scripts.map(([u, used]) => `${u}${used ? "" : " (not recorded)"}`).join(", ") || "inline only"}</p>
        </div>
      )}
    </Panel>
  );
}
