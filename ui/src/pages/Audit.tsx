import { api, fmtDateTime, type AuditRecord } from "../api";
import { Chip, ErrorBox, Panel, useLoad, useNav } from "../components";

export default function Audit() {
  const { counters } = useNav();
  const verify = useLoad(() => api.get<{ intact: boolean; records?: number; error?: string }>("/audit/verify"), [counters?.audit_records]);
  const list = useLoad(() => api.get<AuditRecord[]>("/audit?limit=300"), [counters?.audit_records]);
  return (
    <div className="content">
      <Panel title="Integrity">
        {verify.data && (
          <div className={verify.data.intact ? "notice" : "error"} data-testid="audit-verify">
            {verify.data.intact
              ? `Audit log intact: ${verify.data.records} records, hash chain verified.`
              : `Audit log verification FAILED: ${verify.data.error}`}
          </div>
        )}
        <p className="small muted">
          Every action by people and agents is appended to a hash chain. Changing, deleting or reordering any record
          breaks the chain from that point.
        </p>
      </Panel>
      <Panel title="Recent records">
        <ErrorBox error={list.error} />
        <table className="grid">
          <thead><tr><th>#</th><th>Time</th><th>Who</th><th>Action</th><th>Decision</th><th>Detail</th></tr></thead>
          <tbody>
            {list.data?.map((r) => (
              <tr key={r.seq}>
                <td className="muted">{r.seq}</td>
                <td className="small">{fmtDateTime(r.ts_ms)}</td>
                <td>{r.actor}</td>
                <td className="mono small">{r.action}</td>
                <td><Chip value={r.decision} /></td>
                <td className="small muted mono" style={{ maxWidth: 520, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={r.detail}>
                  {r.detail}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
