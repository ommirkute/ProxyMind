import { useEffect, useState } from "react";
import { api } from "../api";
import { Chip, ErrorBox, Panel, useAction, useLoad } from "../components";

interface Summary {
  engagement: { name: string | null; starts: string | null; ends: string | null };
  in_scope: string[];
  excluded: string[];
  denied_networks: string[];
  timezone: string | null;
  windows: number;
  limits: { max_requests_per_second_per_host: number; max_concurrency: number };
  data: { redact_before_llm: boolean; allow_cloud_models: boolean };
  permissions: Record<string, Record<string, string>>;
}

interface RoeView {
  text: string | null;
  summary: Summary;
}

const TIERS = ["read", "passive", "active_safe", "active_intrusive", "destructive"];

/** The rules of engagement: what is in scope and who may do what. Humans edit; agents only read. */
export default function Engagement() {
  const roe = useLoad(() => api.get<RoeView>("/roe"), []);
  const [text, setText] = useState("");
  const [preview, setPreview] = useState<Summary | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const action = useAction();

  useEffect(() => {
    if (roe.data?.text != null) setText(roe.data.text);
  }, [roe.data?.text]);

  const changed = roe.data != null && text !== (roe.data.text ?? "");
  const check = () =>
    action.run(async () => {
      setPreview(await api.post<Summary>("/roe/check", { text }));
      setNote(null);
    });
  const save = () =>
    action.run(async () => {
      const v = await api.put<RoeView>("/roe", { text });
      roe.reload();
      window.dispatchEvent(new Event("pm-status-changed"));
      setPreview(null);
      setNote(`Saved: "${v.summary.engagement.name ?? "unnamed engagement"}" is in force now.`);
    });

  const shown = preview ?? roe.data?.summary;
  return (
    <div className="content">
      <ErrorBox error={roe.error} />
      <div className="split">
        <Panel title={preview ? "Preview (not saved)" : "In force"}>
          {shown && <SummaryView s={shown} />}
        </Panel>
        <Panel
          title="Rules of engagement (YAML)"
          actions={
            <>
              <button className="btn" disabled={!text || action.busy} onClick={check} data-testid="roe-check">Validate</button>
              <button className="btn primary" disabled={!changed || action.busy} onClick={save} data-testid="roe-save">Save</button>
            </>
          }
        >
          <p className="small muted">
            Changes apply at once to the policy gate, rate limits and the proxy, are written to the audit log, and reach
            agents connected over MCP within seconds. Agents can read these rules but never change them.
          </p>
          <textarea aria-label="ROE YAML" className="mono" rows={22} style={{ width: "100%" }} value={text} onChange={(e) => { setText(e.target.value); setPreview(null); }} spellCheck={false} />
          <ErrorBox error={action.error} />
          {note && <div className="notice" data-testid="roe-note">{note}</div>}
        </Panel>
      </div>
    </div>
  );
}

function SummaryView({ s }: { s: Summary }) {
  const actors = Object.keys(s.permissions);
  return (
    <div className="small" data-testid="roe-summary">
      <p>
        <strong>{s.engagement.name ?? "Unnamed engagement"}</strong>
        {(s.engagement.starts || s.engagement.ends) && <span className="muted"> · {s.engagement.starts ?? "…"} to {s.engagement.ends ?? "…"}</span>}
        {s.timezone && <span className="muted"> · {s.timezone}</span>}
        {s.windows > 0 && <span className="muted"> · {s.windows} testing window(s)</span>}
      </p>
      <h4>In scope</h4>
      <ul className="mono">{s.in_scope.map((p) => <li key={p}>{p}</li>)}</ul>
      {s.excluded.length > 0 && (
        <>
          <h4>Excluded</h4>
          <ul className="mono">{s.excluded.map((p) => <li key={p}>{p}</li>)}</ul>
        </>
      )}
      {s.denied_networks.length > 0 && <p>Never contacted: <span className="mono">{s.denied_networks.join(", ")}</span></p>}
      <h4>Who may do what</h4>
      <table className="grid">
        <thead><tr><th></th>{TIERS.map((t) => <th key={t}>{t.replace("_", " ")}</th>)}</tr></thead>
        <tbody>
          {actors.map((a) => (
            <tr key={a}>
              <th>{a}</th>
              {TIERS.map((t) => <td key={t}><Chip value={s.permissions[a][t]} /></td>)}
            </tr>
          ))}
        </tbody>
      </table>
      <p>
        At most {s.limits.max_requests_per_second_per_host} requests per second and {s.limits.max_concurrency} at once per host.
        Secrets are {s.data.redact_before_llm ? "replaced before models see traffic" : "shown to models"}; cloud models are{" "}
        {s.data.allow_cloud_models ? "allowed" : "not allowed"}.
      </p>
    </div>
  );
}
