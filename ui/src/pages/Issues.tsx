import { useState } from "react";
import { api } from "../api";
import { Chip, Empty, ErrorBox, ExchangeLink, Panel, useAction, useLoad, useNav } from "../components";

interface Issue {
  check: string;
  title: string;
  severity: "info" | "low" | "medium" | "high";
  origin: string;
  path: string;
  evidence: string;
  count: number;
  exchange_ids: number[];
}

/** Passive issues in recorded traffic: leads to test, not findings. */
export default function Issues() {
  const { counters, go, arg } = useNav();
  const [min, setMin] = useState("info");
  const [host, setHost] = useState("");
  const issues = useLoad(
    () => api.get<Issue[]>(`/scan/issues?min_severity=${min}${host ? `&host=${encodeURIComponent(host)}` : ""}`),
    [min, host, counters?.exchanges],
  );
  const action = useAction();
  const toFinding = (i: Issue) =>
    action.run(async () => {
      const f = await api.post<{ id: number }>("/findings", {
        title: i.title,
        vuln_class: i.check,
        severity: i.severity === "info" ? "info" : i.severity,
        description: `Passive check ${i.check} on ${i.origin}${i.path === "*" ? "" : i.path} (${i.count} responses).\n\nEvidence: ${i.evidence}`,
        evidence: i.exchange_ids,
      });
      go("findings", f.id);
    });

  return (
    <div className="content">
      <ActiveScan key={String(arg ?? "")} initial={arg === undefined ? undefined : String(arg)} />
      <Panel
        title="Issues (passive)"
        actions={
          <>
            <input aria-label="Host filter" placeholder="host…" value={host} onChange={(e) => setHost(e.target.value)} />
            <select aria-label="Minimum severity" value={min} onChange={(e) => setMin(e.target.value)}>
              {["info", "low", "medium", "high"].map((s) => <option key={s}>{s}</option>)}
            </select>
          </>
        }
      >
        <p className="small muted">Checks run over recorded traffic and send nothing. They are leads to test: a finding is proven only by a proof.</p>
        <ErrorBox error={issues.error ?? action.error} />
        {issues.data && issues.data.length === 0 && <Empty>No issues in recorded traffic.</Empty>}
        {issues.data && issues.data.length > 0 && (
          <table className="grid" data-testid="issues">
            <thead><tr><th>Severity</th><th>Issue</th><th>Where</th><th>Seen</th><th>Evidence</th><th></th></tr></thead>
            <tbody>
              {issues.data.map((i) => (
                <tr key={`${i.check}${i.origin}${i.path}${i.evidence}`}>
                  <td><Chip value={i.severity} /></td>
                  <td>{i.title}</td>
                  <td className="mono small">{i.origin}{i.path === "*" ? " (site-wide)" : i.path}</td>
                  <td className="small">{i.count}× {i.exchange_ids.slice(0, 3).map((e) => <span key={e}><ExchangeLink id={e} /> </span>)}</td>
                  <td className="small" style={{ maxWidth: 360, wordBreak: "break-word" }}>{i.evidence}</td>
                  <td><button className="btn" disabled={action.busy} onClick={() => toFinding(i)}>Make finding</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

interface ActiveFinding {
  check: string;
  title: string;
  severity: string;
  point: string;
  payload: string;
  evidence: string;
  prove_with?: string;
  exchange_id: number;
}
type ActiveResult =
  | { status: "done"; baseline_exchange_id: number; requests: number; issues: ActiveFinding[]; insertion_points: { kind: string; name: string }[] }
  | { status: "pending_approval"; approval_id: string; summary: string; reasons: string[] }
  | { status: "denied"; reasons: string[] };

/** Active checks on one recorded request. */
function ActiveScan({ initial }: { initial?: string }) {
  const { go } = useNav();
  const [ex, setEx] = useState(initial ?? "");
  const [result, setResult] = useState<ActiveResult | null>(null);
  const action = useAction();
  const run = () =>
    action.run(async () => {
      setResult(await api.post<ActiveResult>("/scan/active", { exchange_id: Number(ex) }));
    });
  return (
    <Panel title="Active scan">
      <div className="row">
        <span className="small">Probe every parameter of exchange</span>
        <input aria-label="Exchange to scan" value={ex} onChange={(e) => setEx(e.target.value)} style={{ width: 80 }} />
        <button className="btn primary" disabled={!ex || action.busy} onClick={run} data-testid="active-scan">{action.busy ? "Scanning…" : "Scan"}</button>
        <span className="small muted">SQL errors, unencoded reflection, open redirect, path traversal, template injection. Sends requests; goes through the policy gate.</span>
      </div>
      <ErrorBox error={action.error} />
      {result?.status === "pending_approval" && (
        <div className="notice">Needs approval: {result.summary}. <a href="#" onClick={(e) => { e.preventDefault(); go("approvals"); }}>Approvals</a></div>
      )}
      {result?.status === "denied" && <div className="error">Denied: {result.reasons.join("; ")}</div>}
      {result?.status === "done" && (
        <>
          <div className="small" data-testid="active-summary">
            {result.insertion_points.length} insertion points · {result.requests} probes · {result.issues.length} leads
          </div>
          {result.issues.length > 0 && (
            <table className="grid small">
              <thead><tr><th>Severity</th><th>Lead</th><th>Where</th><th>Evidence</th><th>Prove with</th></tr></thead>
              <tbody>
                {result.issues.map((i) => (
                  <tr key={i.exchange_id}>
                    <td><Chip value={i.severity} /></td>
                    <td>{i.title}</td>
                    <td className="mono">{i.point} = {i.payload}</td>
                    <td style={{ maxWidth: 320, wordBreak: "break-word" }}>{i.evidence} <ExchangeLink id={i.exchange_id} /></td>
                    <td className="muted">{i.prove_with ?? "–"}</td>
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
