import { useState } from "react";
import { api, type IssueType } from "../api";
import { Chip, Empty, ErrorBox, Panel, useLoad } from "../components";
import { IssueCard } from "./Findings";

/** Every kind of issue ProxyMind reports: what it is, impact, fix, CWE and OWASP. */
export default function Library() {
  const list = useLoad(() => api.get<IssueType[]>("/library"), []);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const needle = q.trim().toLowerCase();
  const shown = (list.data ?? []).filter(
    (i) =>
      !needle ||
      [i.id, i.name, i.owasp, i.owasp_api ?? "", ...i.aliases, ...i.cwe.map((n) => `cwe-${n}`)].some((x) => x.toLowerCase().includes(needle)),
  );
  return (
    <div className="content">
      <Panel
        title="Issue library"
        actions={<input aria-label="Search the library" placeholder="Search: sql, CWE-79, A01…" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 240 }} />}
      >
        <p className="small muted" style={{ marginTop: 0 }}>
          What each kind of issue is, why it matters and how to fix it, with its CWE and OWASP Top 10 (2021) / API Top 10
          (2023) categories. Findings and reports are filled in from here.
        </p>
        <ErrorBox error={list.error} />
        {list.data && shown.length === 0 && <Empty>Nothing matches.</Empty>}
        <table className="grid" data-testid="library">
          <tbody>
            {shown.map((i) => (
              <tr key={i.id} className="clickable" onClick={() => setOpen(open === i.id ? null : i.id)}>
                <td style={{ width: "100%" }}>
                  <div className="row">
                    <strong>{i.name}</strong>
                    <Chip value={i.severity} />
                    <span className="small muted">{i.cwe.map((n) => `CWE-${n}`).join(", ")} · {i.owasp}</span>
                  </div>
                  {open === i.id && <IssueCard issue={i} />}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
