import { useEffect, useState } from "react";
import { api, originOf, type ExchangeDetail, type IdentityInfo } from "../api";
import { ErrorBox, ExchangeLink, Panel, StatusCode, useAction, useLoad, useNav } from "../components";

interface Row {
  exchange_id: number;
  payloads: (string | null)[];
  status?: number;
  body_length: number;
  elapsed_ms: number;
  matches?: string[];
  reflected: boolean;
  error?: string;
}
interface Anomaly {
  index: number;
  reasons: string[];
}
type Result =
  | { status: "done"; baseline: Row; results: Row[]; anomalies: Anomaly[] }
  | { status: "pending_approval"; approval_id: string; summary: string; reasons: string[] }
  | { status: "denied"; reasons: string[] };

const MODES = ["sniper", "battering_ram", "pitchfork", "cluster_bomb"] as const;
const BUILTINS = ["", "ids", "sqli", "xss", "traversal", "ssti", "methods_override"];

/** Payload sets typed one per line; a line with only --- starts the next set. */
function parseSets(text: string, numbers: string, builtin: string, urlEncode: boolean) {
  const sets = text
    .split(/^---$/m)
    .map((block) => block.split("\n").filter((l) => l.length > 0))
    .filter((l) => l.length > 0)
    .map((list) => ({ list, url_encode: urlEncode }));
  if (numbers || builtin) sets.push({ list: [], url_encode: urlEncode, ...(numbers ? { numbers } : {}), ...(builtin ? { builtin } : {}) } as never);
  return sets;
}

export default function Intruder() {
  const { arg, go } = useNav();
  const [url, setUrl] = useState("");
  const [raw, setRaw] = useState("GET /api/items/§1§ HTTP/1.1\nHost: example.com\n\n");
  const [mode, setMode] = useState<(typeof MODES)[number]>("sniper");
  const [payloads, setPayloads] = useState("");
  const [numbers, setNumbers] = useState("");
  const [builtin, setBuiltin] = useState("");
  const [urlEncode, setUrlEncode] = useState(false);
  const [grep, setGrep] = useState("");
  const [identity, setIdentity] = useState("");
  const [approval, setApproval] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const [onlyAnomalies, setOnlyAnomalies] = useState(false);
  const ids = useLoad(() => api.get<IdentityInfo[]>("/identities"), []);
  const action = useAction();

  useEffect(() => {
    if (!arg) return;
    api
      .get<ExchangeDetail>(`/exchanges/${arg}`)
      .then((ex) => {
        setUrl(originOf(ex.summary));
        setRaw(ex.request.replace(/\r\n/g, "\n"));
      })
      .catch((e) => action.setError(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [arg]);

  // Wrap the selected text of the request in § markers.
  const mark = () => {
    const el = document.getElementById("intruder-raw") as HTMLTextAreaElement | null;
    if (!el || el.selectionStart === el.selectionEnd) return;
    const [a, b] = [el.selectionStart, el.selectionEnd];
    setRaw(raw.slice(0, a) + "§" + raw.slice(a, b) + "§" + raw.slice(b));
  };

  const run = () =>
    action.run(async () => {
      const r = await api.post<Result>("/intruder", {
        url,
        raw,
        mode,
        payload_sets: parseSets(payloads, numbers, builtin, urlEncode),
        grep: grep.split(",").map((g) => g.trim()).filter(Boolean),
        identity: identity || undefined,
        approval_id: approval || undefined,
      });
      setResult(r);
      setApproval(r.status === "pending_approval" ? r.approval_id : null);
    });

  const positions = (raw.match(/§/g)?.length ?? 0) / 2;
  const anomalyFor = (i: number) => (result?.status === "done" ? result.anomalies.find((a) => a.index === i) : undefined);

  return (
    <div className="content">
      <div className="split">
        <Panel title="Intruder">
          <div className="row">
            <input aria-label="Target" className="grow mono" placeholder="http://host:port" value={url} onChange={(e) => setUrl(e.target.value)} />
            <select aria-label="Mode" value={mode} onChange={(e) => setMode(e.target.value as (typeof MODES)[number])}>
              {MODES.map((m) => <option key={m}>{m}</option>)}
            </select>
            <select aria-label="Send as" value={identity} onChange={(e) => setIdentity(e.target.value)}>
              <option value="">as recorded</option>
              {ids.data?.map((i) => <option key={i.name} value={i.name}>{i.name}</option>)}
            </select>
          </div>
          <textarea id="intruder-raw" aria-label="Request" className="mono" rows={10} value={raw} onChange={(e) => setRaw(e.target.value)} style={{ marginTop: 6, width: "100%" }} />
          <div className="row small">
            <button className="btn" onClick={mark}>Add § around selection</button>
            <button className="btn" onClick={() => setRaw(raw.replace(/§/g, ""))}>Clear §</button>
            <span className="muted">{Number.isInteger(positions) ? `${positions} position(s)` : "unbalanced § markers"}</span>
          </div>
          <h3>Payloads</h3>
          <textarea aria-label="Payloads" className="mono" rows={6} placeholder={"one payload per line\n---\nnext set (pitchfork / cluster bomb)"} value={payloads} onChange={(e) => setPayloads(e.target.value)} style={{ width: "100%" }} />
          <div className="row small" style={{ marginTop: 6 }}>
            <input aria-label="Numbers" placeholder="numbers e.g. 1000-1050" value={numbers} onChange={(e) => setNumbers(e.target.value)} style={{ width: 170 }} />
            <select aria-label="Built-in list" value={builtin} onChange={(e) => setBuiltin(e.target.value)}>
              {BUILTINS.map((b) => <option key={b} value={b}>{b || "no built-in list"}</option>)}
            </select>
            <label><input type="checkbox" checked={urlEncode} onChange={(e) => setUrlEncode(e.target.checked)} /> URL-encode</label>
            <input aria-label="Grep" className="grow" placeholder="flag responses containing (comma-separated)" value={grep} onChange={(e) => setGrep(e.target.value)} />
          </div>
          <div className="row" style={{ marginTop: 8 }}>
            <button className="btn primary" disabled={!url || action.busy} onClick={run} data-testid="intruder-run">
              {action.busy ? "Running…" : approval ? "Run (approved)" : "Start attack"}
            </button>
          </div>
          <ErrorBox error={action.error} />
          {result?.status === "pending_approval" && (
            <div className="notice">
              Needs approval: {result.summary}. Approve it on the{" "}
              <a href="#" onClick={(e) => { e.preventDefault(); go("approvals"); }}>Approvals</a> page, then press Run again.
            </div>
          )}
          {result?.status === "denied" && <div className="error">Denied: {result.reasons.join("; ")}</div>}
        </Panel>
        <Panel
          title="Results"
          actions={result?.status === "done" && (
            <label className="small"><input type="checkbox" checked={onlyAnomalies} onChange={(e) => setOnlyAnomalies(e.target.checked)} /> only anomalies</label>
          )}
        >
          {result?.status !== "done" ? (
            <span className="muted small">Mark positions with §, add payloads and start the attack. Every request goes through the policy gate and into History.</span>
          ) : (
            <>
              <div className="small muted" data-testid="intruder-summary">
                {result.results.length} requests · {result.anomalies.length} anomalies
              </div>
              <table className="grid" data-testid="intruder-results">
                <thead><tr><th>#</th><th>Payload</th><th>Status</th><th>Length</th><th>ms</th><th>Notes</th></tr></thead>
                <tbody>
                  <tr>
                    <td className="muted">base</td>
                    <td className="muted">original</td>
                    <td><StatusCode status={result.baseline.status ?? null} /></td>
                    <td>{result.baseline.body_length}</td>
                    <td>{result.baseline.elapsed_ms}</td>
                    <td><ExchangeLink id={result.baseline.exchange_id} /></td>
                  </tr>
                  {result.results.map((r, i) => {
                    const a = anomalyFor(i);
                    if (onlyAnomalies && !a) return null;
                    return (
                      <tr key={r.exchange_id} style={a ? { background: "var(--accent-soft)" } : undefined} data-testid={a ? "anomaly" : undefined}>
                        <td className="muted">{i + 1}</td>
                        <td className="mono small">{r.payloads.map((p) => p ?? "·").join(" | ")}</td>
                        <td><StatusCode status={r.status ?? null} /></td>
                        <td>{r.body_length}</td>
                        <td>{r.elapsed_ms}</td>
                        <td className="small">
                          <ExchangeLink id={r.exchange_id} /> {r.error && <span className="error">{r.error}</span>}
                          {a && <div>{a.reasons.join("; ")}</div>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </>
          )}
        </Panel>
      </div>
    </div>
  );
}
