import { useState } from "react";
import { api, fmtDateTime, qs, type Approval } from "../api";
import { Chip, Empty, ErrorBox, Panel, useAction, useLoad, useNav } from "../components";

function requestPreview(params: string): string | null {
  try {
    const p = JSON.parse(params);
    return p.request ?? p.payload ?? p.raw ?? null;
  } catch {
    return null;
  }
}

export default function Approvals() {
  const { counters } = useNav();
  const [all, setAll] = useState(false);
  const list = useLoad(() => api.get<Approval[]>(`/approvals${qs({ status: all ? "all" : "pending" })}`), [
    all,
    counters?.pending_approvals,
    counters?.audit_records,
  ]);
  const action = useAction();

  const decide = (id: string, d: "approve" | "deny") =>
    action.run(async () => {
      await api.post(`/approvals/${id}/${d}`);
      list.reload();
    });

  return (
    <div className="content">
      <Panel
        title={all ? "All approvals" : "Waiting for you"}
        actions={
          <label className="row small">
            <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> show decided
          </label>
        }
      >
        <p className="muted small" style={{ marginTop: 0 }}>
          Agents ask here before risky actions. An approval covers exactly the request shown and can be used once.
        </p>
        <ErrorBox error={list.error ?? action.error} />
        {list.data?.length === 0 && <Empty>{all ? "No approvals yet." : "Nothing is waiting for approval."}</Empty>}
        {list.data?.map((a) => {
          const req = requestPreview(a.params);
          return (
            <div key={a.id} className="panel" style={{ background: "var(--panel-2)" }} data-testid={`approval-${a.id}`}>
              <div className="row">
                <strong className="grow">{a.summary}</strong>
                <Chip value={a.status} />
              </div>
              <div className="row small muted" style={{ margin: "4px 0 8px" }}>
                <span className="mono">{a.id}</span>
                <span>{a.actor}</span>
                <Chip value={a.tier} />
                <span>{fmtDateTime(a.created_ms)}</span>
                {a.decided_by && <span>decided by {a.decided_by}</span>}
              </div>
              {req && <pre className="raw" style={{ maxHeight: 240 }}>{req}</pre>}
              {a.status === "pending" && (
                <div className="row" style={{ marginTop: 8 }}>
                  <button className="btn primary" disabled={action.busy} onClick={() => decide(a.id, "approve")}>Approve</button>
                  <button className="btn bad" disabled={action.busy} onClick={() => decide(a.id, "deny")}>Deny</button>
                </div>
              )}
            </div>
          );
        })}
      </Panel>
    </div>
  );
}
