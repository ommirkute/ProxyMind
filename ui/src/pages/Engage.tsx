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
interface JsEndpoint { url: string; method?: string; params?: string[]; script?: boolean; known: boolean; external?: boolean; exchange_id: number; count: number }
interface Summary { id: number; method: string; host: string; path: string; status: number | null }
interface DnsRecord { name: string; type: string; ttl: number; value: string }
interface DnsReport { host: string; resolver: string; records: DnsRecord[]; notes: string[] }
interface Capture { url: string; status?: number; mime?: string; timestamp: string; note?: string; known: boolean }
interface WaybackReport { host: string; total: number; interesting: number; captures: Capture[] }
interface LogicCandidate { param: string; category: string; paths: string[]; examples: string[]; tests: string[] }
interface LogicReport { candidates: LogicCandidate[]; flow_paths: string[] }
interface Clickjack { framable: boolean; reasons: string[]; poc: string }

const TOOLS = [
  ["analyze", "Analyze target"],
  ["comments", "Find comments"],
  ["scripts", "Find scripts"],
  ["endpoints", "JS endpoints"],
  ["logic", "Logic tests"],
  ["refs", "Find references"],
  ["csrf", "CSRF PoC"],
  ["clickjack", "Clickjacking"],
  ["dom", "DOM test"],
  ["dns", "DNS records"],
  ["wayback", "Wayback URLs"],
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
        {["analyze", "comments", "scripts", "endpoints", "logic"].includes(tool) && (
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
        {["dns", "wayback"].includes(tool) ? (
          <p className="small muted">
            Passive recon for a host in scope: asks {tool === "dns" ? "the DNS resolver" : "the Internet Archive"}, never the target.
          </p>
        ) : (
          <p className="small muted">These tools read recorded traffic; they send nothing.</p>
        )}
      </Panel>
      {tool === "analyze" && <AnalyzeTarget filter={filter} />}
      {tool === "comments" && <Comments filter={filter} />}
      {tool === "scripts" && <Scripts filter={filter} />}
      {tool === "endpoints" && <JsEndpoints filter={filter} />}
      {tool === "logic" && <LogicTests filter={filter} />}
      {tool === "refs" && <References exchange={exchange} />}
      {tool === "csrf" && <CsrfPoc exchange={exchange} />}
      {tool === "clickjack" && <ClickjackTest exchange={exchange} />}
      {tool === "dom" && <DomTest exchange={exchange} />}
      {tool === "dns" && <DnsRecords />}
      {tool === "wayback" && <WaybackUrls />}
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

/** Endpoints the app's JavaScript mentions, new ones (not seen in traffic) first. */
function JsEndpoints({ filter }: { filter: object }) {
  const [r, setR] = useState<JsEndpoint[] | null>(null);
  const [onlyNew, setOnlyNew] = useState(true);
  const action = useAction();
  const run = () => action.run(async () => setR(await api.post<JsEndpoint[]>("/engage/js-endpoints", filter)));
  const shown = (r ?? []).filter((e) => !onlyNew || (!e.known && !e.script));
  const fresh = (r ?? []).filter((e) => !e.known && !e.script && !e.external).length;
  return (
    <Panel
      title="Endpoints in JavaScript"
      actions={<>
        <label className="small"><input type="checkbox" checked={onlyNew} onChange={(e) => setOnlyNew(e.target.checked)} /> new only</label>
        <button className="btn primary" onClick={run} disabled={action.busy} data-testid="engage-endpoints">Find endpoints</button>
      </>}
    >
      <p className="small muted">
        API paths and URLs mentioned in recorded scripts and inline page scripts. <b>New</b> ones haven't appeared in
        traffic yet: often routes no page links to. <code>{"{id}"}</code> marks a value the script fills in. The
        automatic pass (<code>proxymind bench auto</code>) also fetches the scripts pages reference and checks the new
        ones for you.
      </p>
      <ErrorBox error={action.error} />
      {r && (
        <p className="small" data-testid="engage-endpoint-summary">
          {r.length} endpoint(s), <b>{fresh}</b> new on the same site, {r.filter((e) => e.script).length} script(s).
        </p>
      )}
      {r && (shown.length === 0 ? <Empty>{r.length === 0 ? "No endpoints in recorded scripts. Browse the app first (scripts load as you go)." : "Nothing new: every endpoint has been seen in traffic."}</Empty> : (
        <table className="grid" data-testid="engage-endpoint-list">
          <thead><tr><th>Method</th><th>Endpoint</th><th>Parameters</th><th></th><th>Mentioned in</th><th></th></tr></thead>
          <tbody>
            {shown.map((e, i) => (
              <tr key={i}>
                <td className="mono small">{e.method ?? "?"}</td>
                <td className="mono small" style={{ wordBreak: "break-all" }}>{e.url}</td>
                <td className="mono small">{(e.params ?? []).join(", ")}</td>
                <td>
                  {e.script ? <Chip value="script" /> : e.known ? <Chip value="seen" /> : <Chip value="new" />}
                  {e.external && <> <Chip value="other site" /></>}
                </td>
                <td className="small"><ExchangeLink id={e.exchange_id} />{e.count > 1 && <span className="muted"> +{e.count - 1}</span>}</td>
                <td><button className="btn" onClick={() => { copyText(e.url); toast("URL copied"); }}>Copy URL</button></td>
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

function DnsRecords() {
  const [host, setHost] = useState("");
  const [r, setR] = useState<DnsReport | null>(null);
  const action = useAction();
  const run = () => action.run(async () => setR(await api.post<DnsReport>("/recon/dns", { host: host.trim() })));
  return (
    <Panel
      title="DNS records"
      actions={<>
        <input aria-label="DNS host" placeholder="shop.example.com" value={host} onChange={(e) => setHost(e.target.value)} style={{ width: 220 }} />
        <button className="btn primary" onClick={run} disabled={action.busy || !host.trim()} data-testid="recon-dns">Look up</button>
      </>}
    >
      <p className="small muted">
        A, AAAA, CNAME, MX, TXT, NS, SOA, CAA and DMARC records of a host in scope or a parent domain, with notes on
        mail spoofing (SPF, DMARC), certificate issuance (CAA) and CNAMEs to services where a deleted resource can be
        claimed.
      </p>
      <ErrorBox error={action.error} />
      {r && (
        <>
          <p className="small">{r.records.length} record(s) for <b>{r.host}</b> from {r.resolver}.</p>
          {r.notes.length > 0 && (
            <ul className="small" data-testid="recon-dns-notes">{r.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
          )}
          {r.records.length === 0 ? <Empty>No records.</Empty> : (
            <table className="grid" data-testid="recon-dns-list">
              <thead><tr><th>Type</th><th>Name</th><th>TTL</th><th>Value</th></tr></thead>
              <tbody>
                {r.records.map((x, i) => (
                  <tr key={i}>
                    <td><Chip value={x.type} /></td>
                    <td className="mono small">{x.name}</td>
                    <td className="small">{x.ttl}</td>
                    <td className="mono small" style={{ wordBreak: "break-all" }}>{x.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </Panel>
  );
}

function WaybackUrls() {
  const [host, setHost] = useState("");
  const [r, setR] = useState<WaybackReport | null>(null);
  const [onlyInteresting, setOnlyInteresting] = useState(false);
  const action = useAction();
  const run = () => action.run(async () => setR(await api.post<WaybackReport>("/recon/wayback", { host: host.trim(), limit: 1000 })));
  const shown = (r?.captures ?? []).filter((c) => !onlyInteresting || c.note);
  const date = (t: string) => (t.length >= 8 ? `${t.slice(0, 4)}-${t.slice(4, 6)}-${t.slice(6, 8)}` : t);
  return (
    <Panel
      title="Wayback Machine URLs"
      actions={<>
        <label className="small"><input type="checkbox" checked={onlyInteresting} onChange={(e) => setOnlyInteresting(e.target.checked)} /> interesting only</label>
        <input aria-label="Wayback host" placeholder="shop.example.com" value={host} onChange={(e) => setHost(e.target.value)} style={{ width: 220 }} />
        <button className="btn primary" onClick={run} disabled={action.busy || !host.trim()} data-testid="recon-wayback">Fetch history</button>
      </>}
    >
      <p className="small muted">
        URLs the Internet Archive has captured for a host in scope, interesting ones first (backups, configs, APIs,
        admin pages, parameters). Old endpoints often still answer: open one in Replay to check. The request goes
        through the upstream proxy settings.
      </p>
      <ErrorBox error={action.error} />
      {r && <p className="small">{r.total} archived URL(s), <b>{r.interesting}</b> interesting{r.captures.length < r.total ? `, first ${r.captures.length} shown` : ""}.</p>}
      {r && (shown.length === 0 ? <Empty>No archived URLs.</Empty> : (
        <table className="grid" data-testid="recon-wayback-list">
          <thead><tr><th>Status</th><th>URL</th><th>Why</th><th>Captured</th><th></th></tr></thead>
          <tbody>
            {shown.map((c, i) => (
              <tr key={i}>
                <td className="small">{c.status ?? "-"}</td>
                <td className="mono small" style={{ wordBreak: "break-all" }}>{c.url}</td>
                <td>{c.note && <Chip value={c.note} />} {c.known && <Chip value="seen" />}</td>
                <td className="small">{date(c.timestamp)}</td>
                <td><button className="btn" onClick={() => { copyText(c.url); toast("URL copied"); }}>Copy URL</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </Panel>
  );
}

function LogicTests({ filter }: { filter: object }) {
  const [r, setR] = useState<LogicReport | null>(null);
  const action = useAction();
  const run = () => action.run(async () => setR(await api.post<LogicReport>("/engage/logic", filter)));
  return (
    <Panel title="Business-logic tests" actions={<button className="btn primary" onClick={run} disabled={action.busy} data-testid="engage-logic">Find candidates</button>}>
      <p className="small muted">
        Parameters that look like prices, quantities, discounts, limits, identities, roles or workflow state, with abuse
        cases to try in Replay, and URLs that look like steps of a flow (for skipping, repeating or reversing steps).
        Scanners can't judge these: compare the resulting state (the order, the balance) with what the business allows.
        Agents get the same list (<code>engage_logic</code>) and the <code>business_logic</code> skill.
      </p>
      <ErrorBox error={action.error} />
      {r && (r.candidates.length === 0 ? <Empty>No candidates in recorded traffic. Walk through the cart, checkout, coupons and profile first.</Empty> : (
        <table className="grid" data-testid="engage-logic-list">
          <thead><tr><th>Parameter</th><th>Kind</th><th>Sent to</th><th>Try</th></tr></thead>
          <tbody>
            {r.candidates.map((c, i) => (
              <tr key={i}>
                <td className="mono small">{c.param}{c.examples.length > 0 && <div className="muted">e.g. {c.examples.join(", ")}</div>}</td>
                <td><Chip value={c.category} /></td>
                <td className="mono small" style={{ wordBreak: "break-all" }}>{c.paths.join(" ")}</td>
                <td className="small"><ul style={{ margin: 0, paddingLeft: 16 }}>{c.tests.map((t, j) => <li key={j}>{t}</li>)}</ul></td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
      {r && r.flow_paths.length > 0 && (
        <p className="small" data-testid="engage-logic-flows">Flow steps: {r.flow_paths.map((p) => <code key={p} style={{ marginRight: 6 }}>{p}</code>)}</p>
      )}
    </Panel>
  );
}
