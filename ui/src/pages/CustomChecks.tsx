import { useEffect, useState } from "react";
import { api, toast } from "../api";
import { Chip, Empty, ErrorBox, ExchangeLink, Panel, useAction, useLoad, useNav } from "../components";

interface Saved { id: string; yaml: string; check: { id: string; title: string; severity: string; run: string; description: string } }
interface Finding { check: string; title: string; severity: string; point: string; payload?: string; evidence: string; exchange_id: number }
type RunResult =
  | { status: "done"; baseline_exchange_id: number; requests: number; findings: Finding[] }
  | { status: "pending_approval"; approval_id: string; summary: string; reasons: string[] }
  | { status: "denied"; reasons: string[] };

const EXAMPLE = `# A custom check: what to send, and what in the response counts as a hit.
id: debug-switch
title: Hidden debug switch
severity: high            # info, low, medium or high
description: A debug parameter shows internal settings.
run: per_request          # or per_insertion_point (with payloads)
request:
  add_query: { debug: "1" }
  # method: POST
  # path: /admin
  # add_headers: { X-Forwarded-For: "127.0.0.1" }
  # remove_headers: [Cookie]
# payloads: ["'", "<pm-x>"]
# payload_mode: replace   # or append
# points: [query, form, json, path, cookie, header]
match:                    # every condition given must hold
  status: [200]
  body_regex: "password|secret|stack trace"
  not_in_baseline: true   # the match came from this request
  # body_contains: ["..."]
  # body_contains_any: ["...", "..."]
  # header_contains: ["access-control-allow-origin: *"]
  # status_differs: true
  # reflected: true
  # min_time_ms: 3000
`;

/** Scan checks written as YAML: save them, then run them on any recorded request. */
export default function CustomChecks() {
  const { arg } = useNav();
  const list = useLoad(() => api.get<Saved[]>("/scan/custom-checks"), []);
  const [yaml, setYaml] = useState(EXAMPLE);
  const [exchange, setExchange] = useState(arg ? String(arg) : "");
  const [picked, setPicked] = useState<string[]>([]);
  const [approval, setApproval] = useState<string | undefined>();
  const [result, setResult] = useState<RunResult | null>(null);
  const action = useAction();
  useEffect(() => {
    if (arg) setExchange(String(arg));
  }, [arg]);

  const save = () =>
    action.run(async () => {
      const s = await api.post<Saved>("/scan/custom-checks", { yaml });
      toast(`Saved ${s.id}`);
      list.reload();
    });
  const remove = (id: string) =>
    action.run(async () => {
      await api.del(`/scan/custom-checks/${encodeURIComponent(id)}`);
      list.reload();
    });
  const run = (body: object) =>
    action.run(async () => {
      const r = await api.post<RunResult>("/scan/custom", { exchange_id: Number(exchange), approval_id: approval, ...body });
      setResult(r);
      setApproval(r.status === "pending_approval" ? r.approval_id : undefined);
    });

  return (
    <div className="content">
      <Panel title="Custom checks" actions={<button className="btn primary" onClick={save} disabled={action.busy} data-testid="check-save">Save check</button>}>
        <p className="small muted" style={{ marginTop: 0 }}>
          Write a check in YAML, save it, and run it on recorded requests. Requests go through the rules of engagement; one approval covers a run.
        </p>
        <textarea aria-label="Check YAML" className="editor mono" rows={18} value={yaml} onChange={(e) => setYaml(e.target.value)} spellCheck={false} style={{ width: "100%" }} />
        <ErrorBox error={action.error ?? list.error} />
      </Panel>
      <Panel title="Run">
        <div className="row small">
          <span>Exchange</span>
          <input aria-label="Check exchange" value={exchange} onChange={(e) => { setExchange(e.target.value); setApproval(undefined); }} style={{ width: 90 }} />
          <button className="btn" disabled={!exchange || action.busy} onClick={() => run({ yaml })} data-testid="check-try">Try the check above</button>
          <button className="btn primary" disabled={!exchange || action.busy || !list.data?.length} onClick={() => run({ checks: picked })} data-testid="check-run">
            {approval ? "Run approved" : picked.length ? `Run ${picked.length} saved` : "Run all saved"}
          </button>
          <span className="muted">(right-click a row in HTTP history: Run custom checks)</span>
        </div>
        {list.data && list.data.length === 0 && <Empty>No saved checks yet.</Empty>}
        {list.data && list.data.length > 0 && (
          <table className="grid">
            <thead><tr><th /><th>Check</th><th>Severity</th><th>Runs</th><th /></tr></thead>
            <tbody>
              {list.data.map((c) => (
                <tr key={c.id}>
                  <td><input type="checkbox" aria-label={`Pick ${c.id}`} checked={picked.includes(c.id)} onChange={() => setPicked((p) => (p.includes(c.id) ? p.filter((x) => x !== c.id) : [...p, c.id]))} /></td>
                  <td><strong>{c.check.title}</strong> <span className="muted mono small">{c.id}</span>{c.check.description && <div className="small muted">{c.check.description}</div>}</td>
                  <td><Chip value={c.check.severity} /></td>
                  <td className="small">{c.check.run.replace(/_/g, " ")}</td>
                  <td className="row small">
                    <button className="btn" onClick={() => setYaml(c.yaml)}>Edit</button>
                    <button className="btn" onClick={() => remove(c.id)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {result?.status === "denied" && <div className="error">Denied by the rules of engagement: {result.reasons.join("; ")}</div>}
        {result?.status === "pending_approval" && <div className="notice small">{result.summary} needs approval ({result.reasons.join("; ")}): approve <strong>{result.approval_id}</strong> on the Approvals page, then run again.</div>}
        {result?.status === "done" && (
          <div data-testid="check-result">
            <p className="small">{result.requests} request(s) sent, baseline <ExchangeLink id={result.baseline_exchange_id} />. {result.findings.length} hit(s).</p>
            {result.findings.length > 0 && (
              <table className="grid">
                <thead><tr><th>Check</th><th>Severity</th><th>Where</th><th>Evidence</th><th>Exchange</th></tr></thead>
                <tbody>
                  {result.findings.map((f, i) => (
                    <tr key={i}>
                      <td>{f.title}</td>
                      <td><Chip value={f.severity} /></td>
                      <td className="small mono">{f.point}{f.payload ? ` ← ${f.payload}` : ""}</td>
                      <td className="small mono" style={{ wordBreak: "break-all" }}>{f.evidence}</td>
                      <td><ExchangeLink id={f.exchange_id} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}
