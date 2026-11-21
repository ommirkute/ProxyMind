import { api, fmtDateTime, type AuditRecord, type AuditVerification } from "../api";
import { Chip, ErrorBox, Panel, useLoad, useNav } from "../components";

export default function Audit() {
  const { counters } = useNav();
  const verify = useLoad(() => api.get<AuditVerification>("/audit/verify"), [counters?.audit_records]);
  const list = useLoad(() => api.get<AuditRecord[]>("/audit?limit=300"), [counters?.audit_records]);
  const rows = list.data ?? [];
  // Columns for the fields a version 2 record adds, shown only when some record has them.
  const hasUser = rows.some((r) => r.user_id);
  const hasToken = rows.some((r) => r.token_id);
  const hasAddr = rows.some((r) => r.client_addr);
  const v = verify.data;
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
        {v && (
          <ul className="small" data-testid="audit-verify-details">
            <li>
              {v.v1_records} version 1 and {v.v2_records} version 2 records ({v.keyed_records} keyed). Version 2
              records also carry who (account, token, session), the project and the address.
            </li>
            <li data-testid="audit-key-check">Key check {v.key_check.replace("_", " ")}: {v.key_note}</li>
            <li data-testid="audit-checkpoints">
              Checkpoints: {v.checkpoints.status}
              {v.checkpoints.status !== "none" &&
                ` (${v.checkpoints.stored} stored, newest covers record ${v.checkpoints.latest_seq}, signer ${v.checkpoints.fingerprint}${v.checkpoints.signer_pinned ? "" : ", signer not pinned"})`}
              {v.checkpoints.status === "none" && " (write one with `proxymind audit checkpoint -o FILE` and keep it elsewhere)"}
            </li>
          </ul>
        )}
        <p className="small muted">
          Every action by people and agents is appended to a hash chain. Changing, deleting or reordering any record
          breaks the chain from that point.
        </p>
      </Panel>
      <Panel title="Recent records">
        <ErrorBox error={list.error} />
        <table className="grid">
          <thead><tr><th>#</th><th>Time</th><th>Who</th>{hasUser && <th>User</th>}{hasToken && <th>Token</th>}{hasAddr && <th>Address</th>}<th>Action</th><th>Decision</th><th>Detail</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.seq}>
                <td className="muted">{r.seq}</td>
                <td className="small">{fmtDateTime(r.ts_ms)}</td>
                <td>{r.actor}</td>
                {hasUser && <td className="mono small">{r.user_id ?? ""}</td>}
                {hasToken && <td className="mono small">{r.token_id ?? ""}</td>}
                {hasAddr && <td className="mono small">{r.client_addr ?? ""}</td>}
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
