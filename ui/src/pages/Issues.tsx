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
  const { counters, go } = useNav();
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
