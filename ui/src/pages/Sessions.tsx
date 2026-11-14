import { useState } from "react";
import { api, ExchangeDetail } from "../api";
import { b64ToBytes, Empty, ErrorBox, Panel, useAction, useLoad } from "../components";

type ExtractKind = "regex" | "json" | "header" | "cookie";
type SetWhere = "header" | "cookie" | "param";

interface Extraction {
  name: string;
  kind: ExtractKind;
  expr: string;
}

interface MacroStep {
  url: string;
  request: string;
  extract: Extraction[];
}

interface Macro {
  name: string;
  steps: MacroStep[];
  use_cookie_jar: boolean;
}

interface SetValue {
  where: SetWhere;
  name: string;
  value: string;
}

interface Rule {
  name: string;
  enabled: boolean;
  tools: string[];
  hosts: string[];
  use_cookie_jar: boolean;
  macro: string;
  run: "always" | "when_invalid";
  invalid: { statuses: number[]; contains: string };
  set: SetValue[];
}

interface SessionView {
  macros: Macro[];
  rules: Rule[];
  saved_by: string;
  variables: Record<string, string>;
}

interface JarCookie {
  domain: string;
  host_only: boolean;
  name: string;
  value: string;
}

interface MacroRun {
  name: string;
  exchange_ids: number[];
  variables: Record<string, string>;
}

const TOOLS = ["replay", "fuzzer", "scan", "crawl", "discover", "token_analyzer", "proof", "authz", "graphql", "openapi"];
const TOOL_LABEL: Record<string, string> = { replay: "Replay", scan: "Scanner", discover: "Discovery" };

const NEW_RULE: Rule = {
  name: "Stay logged in",
  enabled: true,
  tools: [],
  hosts: [],
  use_cookie_jar: true,
  macro: "",
  run: "when_invalid",
  invalid: { statuses: [], contains: "" },
  set: [],
};

const NEW_STEP: MacroStep = { url: "https://", request: "GET / HTTP/1.1\nHost: \n\n", extract: [] };

const list = (s: string) => s.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);

/** Session handling: cookie jar, macros and the rules that keep tool traffic logged in. */
export default function Sessions() {
  const saved = useLoad(() => api.get<SessionView>("/session"), []);
  const [draft, setDraft] = useState<{ macros: Macro[]; rules: Rule[] } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const action = useAction();
  const cfg = draft ?? (saved.data ? { macros: saved.data.macros, rules: saved.data.rules } : null);
  if (!cfg) return <div className="content">{saved.error ? <ErrorBox error={saved.error} /> : <span className="muted">Loading…</span>}</div>;

  const edit = (patch: Partial<typeof cfg>) => {
    setNotice(null);
    setDraft({ ...cfg, ...patch });
  };
  const setRule = (i: number, patch: Partial<Rule>) => edit({ rules: cfg.rules.map((r, j) => (j === i ? { ...r, ...patch } : r)) });
  const setMacro = (i: number, patch: Partial<Macro>) => edit({ macros: cfg.macros.map((m, j) => (j === i ? { ...m, ...patch } : m)) });
  const save = () =>
    action.run(async () => {
      const r = await api.put<SessionView>("/session", cfg);
      saved.setData(r);
      setDraft(null);
      setNotice("Saved. Rules apply to the next request a tool sends.");
    });

  return (
    <div className="content">
      <p className="muted small" style={{ marginTop: 0 }}>
        Keep Replay, Fuzzer, scans and agents logged in. Rules cover requests sent as recorded (not as a test
        identity: identities have their own login recipes). Macro requests go through the rules of engagement as{" "}
        {saved.data?.saved_by || "you"} and appear in HTTP history as <code>macro</code>.
      </p>
      <Panel title="Session rules" actions={<button className="btn" data-testid="add-rule" onClick={() => edit({ rules: [...cfg.rules, { ...NEW_RULE }] })}>Add rule</button>}>
        {cfg.rules.length === 0 && <Empty>No rules: requests are sent exactly as written.</Empty>}
        {cfg.rules.map((r, i) => (
          <div key={i} className="session-card" data-testid="session-rule">
            <div className="row">
              <input type="checkbox" aria-label={`Rule ${i + 1} enabled`} checked={r.enabled} onChange={(e) => setRule(i, { enabled: e.target.checked })} />
              <input aria-label={`Rule ${i + 1} name`} className="grow" value={r.name} onChange={(e) => setRule(i, { name: e.target.value })} />
              <button className="btn" aria-label={`Delete rule ${i + 1}`} onClick={() => edit({ rules: cfg.rules.filter((_, j) => j !== i) })}>✕</button>
            </div>
            <div className="form-grid" style={{ marginTop: 8 }}>
              <label>Tools</label>
              <div className="row small" style={{ flexWrap: "wrap", gap: 8 }}>
                <label><input type="checkbox" checked={r.tools.length === 0} onChange={(e) => setRule(i, { tools: e.target.checked ? [] : ["replay"] })} /> all</label>
                {r.tools.length > 0 &&
                  TOOLS.map((t) => (
                    <label key={t}>
                      <input type="checkbox" checked={r.tools.includes(t)} onChange={(e) => setRule(i, { tools: e.target.checked ? [...r.tools, t] : r.tools.filter((x) => x !== t) })} />{" "}
                      {TOOL_LABEL[t] ?? t[0].toUpperCase() + t.slice(1)}
                    </label>
                  ))}
              </div>
              <label>Hosts</label>
              <input aria-label={`Rule ${i + 1} hosts`} placeholder="all hosts (or: app.example.com, *.example.com)" value={r.hosts.join(", ")} onChange={(e) => setRule(i, { hosts: list(e.target.value) })} />
              <label>Cookie jar</label>
              <label className="small"><input type="checkbox" aria-label={`Rule ${i + 1} cookie jar`} checked={r.use_cookie_jar} onChange={(e) => setRule(i, { use_cookie_jar: e.target.checked })} /> put the latest cookies from the jar into each request</label>
              <label>Macro</label>
              <div className="row">
                <select aria-label={`Rule ${i + 1} macro`} value={r.macro} onChange={(e) => setRule(i, { macro: e.target.value })}>
                  <option value="">none</option>
                  {cfg.macros.map((m) => <option key={m.name} value={m.name}>{m.name || "(unnamed)"}</option>)}
                </select>
                {r.macro && (
                  <select aria-label={`Rule ${i + 1} run`} value={r.run} onChange={(e) => setRule(i, { run: e.target.value as Rule["run"] })}>
                    <option value="when_invalid">when the session looks logged out, then send again</option>
                    <option value="always">before every request</option>
                  </select>
                )}
              </div>
              {r.macro && r.run === "when_invalid" && (
                <>
                  <label>Logged out when</label>
                  <div className="row">
                    <input aria-label={`Rule ${i + 1} statuses`} placeholder="status codes, e.g. 401 403" value={r.invalid.statuses.join(" ")} onChange={(e) => setRule(i, { invalid: { ...r.invalid, statuses: list(e.target.value).map(Number).filter((n) => n > 0) } })} style={{ width: 170 }} />
                    <input aria-label={`Rule ${i + 1} logged-out text`} className="grow" placeholder="or the response contains… (empty: 401, or a redirect to a login page)" value={r.invalid.contains} onChange={(e) => setRule(i, { invalid: { ...r.invalid, contains: e.target.value } })} />
                  </div>
                </>
              )}
              <label>Set</label>
              <div>
                {r.set.map((v, k) => (
                  <div key={k} className="row" style={{ marginBottom: 4 }}>
                    <select aria-label={`Rule ${i + 1} set ${k + 1} where`} value={v.where} onChange={(e) => setRule(i, { set: r.set.map((x, j) => (j === k ? { ...x, where: e.target.value as SetWhere } : x)) })}>
                      <option value="header">header</option>
                      <option value="cookie">cookie</option>
                      <option value="param">parameter</option>
                    </select>
                    <input aria-label={`Rule ${i + 1} set ${k + 1} name`} placeholder="name" value={v.name} onChange={(e) => setRule(i, { set: r.set.map((x, j) => (j === k ? { ...x, name: e.target.value } : x)) })} style={{ width: 150 }} />
                    <input aria-label={`Rule ${i + 1} set ${k + 1} value`} className="grow mono" placeholder="value, e.g. {{csrf}}" value={v.value} onChange={(e) => setRule(i, { set: r.set.map((x, j) => (j === k ? { ...x, value: e.target.value } : x)) })} />
                    <button className="btn" aria-label={`Remove set ${k + 1}`} onClick={() => setRule(i, { set: r.set.filter((_, j) => j !== k) })}>×</button>
                  </div>
                ))}
                <button className="btn small" onClick={() => setRule(i, { set: [...r.set, { where: "header", name: "", value: "" }] })}>Add value</button>
                <span className="small muted"> parameters are only replaced where the request already has them</span>
              </div>
            </div>
          </div>
        ))}
      </Panel>
      <Panel title="Macros" actions={<button className="btn" data-testid="add-macro" onClick={() => edit({ macros: [...cfg.macros, { name: `macro${cfg.macros.length + 1}`, steps: [{ ...NEW_STEP }], use_cookie_jar: false }] })}>Add macro</button>}>
        {cfg.macros.length === 0 && <Empty>A macro is a few recorded requests, such as a login or the page that holds a CSRF token.</Empty>}
        {cfg.macros.map((m, i) => (
          <MacroEditor
            key={i}
            index={i}
            macro={m}
            dirty={!!draft}
            onChange={(p) => setMacro(i, p)}
            onDelete={() => edit({ macros: cfg.macros.filter((_, j) => j !== i) })}
            onRan={() => saved.reload()}
          />
        ))}
        {saved.data && Object.keys(saved.data.variables).length > 0 && (
          <p className="small" data-testid="session-variables">
            Variables now:{" "}
            {Object.entries(saved.data.variables).map(([k, v]) => (
              <span key={k} className="chip mono" title={v}>{k} = {v.length > 24 ? v.slice(0, 24) + "…" : v}</span>
            ))}
          </p>
        )}
      </Panel>
      <ErrorBox error={action.error} />
      {notice && <div className="notice" role="status">{notice}</div>}
      <div className="row">
        <button className="btn primary" data-testid="session-save" disabled={!draft || action.busy} onClick={save}>Save</button>
        {draft && <button className="btn" onClick={() => setDraft(null)}>Discard changes</button>}
      </div>
      <Jar />
    </div>
  );
}

function MacroEditor({ index, macro, dirty, onChange, onDelete, onRan }: { index: number; macro: Macro; dirty: boolean; onChange: (p: Partial<Macro>) => void; onDelete: () => void; onRan: () => void }) {
  const [fromId, setFromId] = useState("");
  const [result, setResult] = useState<MacroRun | null>(null);
  const action = useAction();
  const setStep = (k: number, p: Partial<MacroStep>) => onChange({ steps: macro.steps.map((s, j) => (j === k ? { ...s, ...p } : s)) });
  const fromHistory = () =>
    action.run(async () => {
      const d = await api.get<ExchangeDetail>(`/exchanges/${Number(fromId)}?bytes=1`);
      const s = d.summary;
      const url = `${s.scheme}://${s.host.includes(":") ? `[${s.host}]` : s.host}:${s.port}`;
      const request = d.request_b64 ? new TextDecoder().decode(b64ToBytes(d.request_b64)) : d.request;
      onChange({ steps: [...macro.steps, { url, request, extract: [] }] });
      setFromId("");
    });
  const run = () =>
    action.run(async () => {
      setResult(await api.post<MacroRun>(`/session/macros/${encodeURIComponent(macro.name)}/run`));
      onRan();
    });

  return (
    <div className="session-card" data-testid="session-macro">
      <div className="row">
        <input aria-label={`Macro ${index + 1} name`} value={macro.name} onChange={(e) => onChange({ name: e.target.value })} style={{ width: 180 }} />
        <label className="small"><input type="checkbox" checked={macro.use_cookie_jar} onChange={(e) => onChange({ use_cookie_jar: e.target.checked })} /> start with the cookie jar</label>
        <span className="grow" />
        <button className="btn" data-testid="macro-run" disabled={dirty || action.busy} title={dirty ? "Save first" : "Send the steps now"} onClick={run}>Run now</button>
        <button className="btn" aria-label={`Delete macro ${index + 1}`} onClick={onDelete}>✕</button>
      </div>
      {macro.steps.map((s, k) => (
        <div key={k} className="macro-step">
          <div className="row small">
            <strong>Step {k + 1}</strong>
            <input aria-label={`Macro ${index + 1} step ${k + 1} target`} className="grow mono" placeholder="https://host:port" value={s.url} onChange={(e) => setStep(k, { url: e.target.value })} />
            <button className="btn" aria-label={`Remove step ${k + 1}`} disabled={macro.steps.length < 2} onClick={() => onChange({ steps: macro.steps.filter((_, j) => j !== k) })}>×</button>
          </div>
          <textarea aria-label={`Macro ${index + 1} step ${k + 1} request`} className="mono" rows={5} spellCheck={false} value={s.request} onChange={(e) => setStep(k, { request: e.target.value })} />
          {s.extract.map((x, n) => (
            <div key={n} className="row small" style={{ marginTop: 4 }}>
              <span className="muted">set</span>
              <input aria-label={`Step ${k + 1} variable ${n + 1}`} className="mono" placeholder="variable" value={x.name} onChange={(e) => setStep(k, { extract: s.extract.map((y, j) => (j === n ? { ...y, name: e.target.value } : y)) })} style={{ width: 110 }} />
              <span className="muted">from</span>
              <select aria-label={`Step ${k + 1} variable ${n + 1} source`} value={x.kind} onChange={(e) => setStep(k, { extract: s.extract.map((y, j) => (j === n ? { ...y, kind: e.target.value as ExtractKind } : y)) })}>
                <option value="regex">regex (group 1)</option>
                <option value="json">JSON pointer</option>
                <option value="header">response header</option>
                <option value="cookie">cookie set</option>
              </select>
              <input aria-label={`Step ${k + 1} variable ${n + 1} expression`} className="grow mono" placeholder={{ regex: 'name="csrf" value="([^"]+)"', json: "/data/token", header: "X-CSRF-Token", cookie: "XSRF-TOKEN" }[x.kind]} value={x.expr} onChange={(e) => setStep(k, { extract: s.extract.map((y, j) => (j === n ? { ...y, expr: e.target.value } : y)) })} />
              <button className="btn" aria-label={`Remove variable ${n + 1}`} onClick={() => setStep(k, { extract: s.extract.filter((_, j) => j !== n) })}>×</button>
            </div>
          ))}
          <button className="btn small" style={{ marginTop: 4 }} onClick={() => setStep(k, { extract: [...s.extract, { name: "", kind: "regex", expr: "" }] })}>Extract a variable</button>
        </div>
      ))}
      <div className="row small" style={{ marginTop: 6 }}>
        <button className="btn small" onClick={() => onChange({ steps: [...macro.steps, { ...NEW_STEP }] })}>Add step</button>
        <span className="muted">or from HTTP history #</span>
        <input aria-label={`Macro ${index + 1} exchange id`} type="number" min={1} value={fromId} onChange={(e) => setFromId(e.target.value)} style={{ width: 80 }} />
        <button className="btn small" data-testid="macro-from-history" disabled={!fromId || action.busy} onClick={fromHistory}>Add</button>
      </div>
      <ErrorBox error={action.error} />
      {result && (
        <div className="notice small" role="status" data-testid="macro-result">
          Sent {result.exchange_ids.length} request(s) (#{result.exchange_ids.join(", #")}).{" "}
          {Object.keys(result.variables).length ? `Set ${Object.entries(result.variables).map(([k, v]) => `${k} = ${v}`).join(", ")}.` : "No variables set."}
        </div>
      )}
    </div>
  );
}

function Jar() {
  const jar = useLoad(() => api.get<{ cookies: JarCookie[] }>("/session/jar"), []);
  const action = useAction();
  const cookies = jar.data?.cookies ?? [];
  return (
    <Panel
      title="Cookie jar"
      actions={
        <div className="row">
          <button className="btn" onClick={() => jar.reload()}>Refresh</button>
          <button className="btn" data-testid="jar-clear" disabled={!cookies.length || action.busy} onClick={() => action.run(async () => { await api.del("/session/jar"); jar.reload(); })}>Clear</button>
        </div>
      }
    >
      <p className="small muted" style={{ marginTop: 0 }}>Cookies set in responses to the proxy, tools and macros (not test identities), newest value wins.</p>
      <ErrorBox error={jar.error ?? action.error} />
      {cookies.length === 0 ? (
        <Empty>Empty.</Empty>
      ) : (
        <table className="grid" data-testid="jar">
          <thead>
            <tr><th>Domain</th><th>Name</th><th>Value</th></tr>
          </thead>
          <tbody>
            {cookies.map((c) => (
              <tr key={`${c.domain}|${c.name}`}>
                <td className="mono">{c.host_only ? c.domain : `*.${c.domain}`}</td>
                <td className="mono">{c.name}</td>
                <td className="mono" style={{ maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={c.value}>{c.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
