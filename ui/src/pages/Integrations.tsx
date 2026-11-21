import { useState } from "react";
import { api, fmtDateTime, toast, type IntegrationView } from "../api";
import type { IntegrationEvent, IntegrationInput, IntegrationKind } from "../api-types.gen";
import { Chip, Empty, ErrorBox, Panel, useAction, useLoad, useNav } from "../components";

interface Delivery {
  id: number;
  ts_ms: number;
  kind: string;
  event: string;
  finding_id: number | null;
  status: string;
  http_status: number | null;
  attempts: number;
  host: string;
  detail: string;
}

const KINDS: { id: IntegrationKind; label: string }[] = [
  { id: "jira", label: "Jira" },
  { id: "github", label: "GitHub" },
  { id: "gitlab", label: "GitLab" },
  { id: "slack", label: "Slack" },
  { id: "webhook", label: "Webhook" },
];
const EVENTS: { id: IntegrationEvent; label: string }[] = [
  { id: "finding_proven", label: "Finding proven" },
  { id: "finding_status_changed", label: "Finding status changed" },
  { id: "scan_finished", label: "Scan finished" },
  { id: "ci_summary", label: "Scan summary" },
];

interface Draft {
  name: string;
  kind: IntegrationKind;
  base_url: string;
  project: string;
  issue_type: string;
  email: string;
  labels: string;
  events: IntegrationEvent[];
  allow_private: boolean;
  token: string;
  webhook_url: string;
  signing_secret: string;
  headers: { name: string; value: string }[];
  editing: boolean;
}

const BLANK: Draft = {
  name: "", kind: "webhook", base_url: "", project: "", issue_type: "Bug", email: "", labels: "", events: ["finding_proven"],
  allow_private: false, token: "", webhook_url: "", signing_secret: "", headers: [], editing: false,
};

const isTracker = (k: IntegrationKind) => k === "jira" || k === "github" || k === "gitlab";

function draftOf(v: IntegrationView): Draft {
  return {
    name: v.name, kind: v.kind, base_url: v.kind === "slack" ? "" : v.base_url, project: v.project, issue_type: v.issue_type || "Bug",
    email: v.email, labels: v.labels.join(", "), events: v.events, allow_private: v.allow_private,
    token: "", webhook_url: "", signing_secret: "", headers: v.header_names.map((name) => ({ name, value: "" })), editing: true,
  };
}

/** Writes only what the person typed: a blank secret keeps the saved one. */
function inputOf(d: Draft): IntegrationInput {
  const body: IntegrationInput = {
    name: d.name.trim(),
    kind: d.kind,
    enabled: true,
    base_url: d.base_url.trim(),
    project: d.project.trim(),
    issue_type: d.issue_type.trim(),
    email: d.email.trim(),
    labels: d.labels.split(",").map((x) => x.trim()).filter(Boolean),
    events: isTracker(d.kind) ? [] : d.events,
    allow_private: d.allow_private,
  };
  if (d.token) body.token = d.token;
  if (d.webhook_url) body.webhook_url = d.webhook_url;
  if (d.signing_secret) body.signing_secret = d.signing_secret;
  if (d.kind === "webhook") body.headers = d.headers.filter((h) => h.name.trim()).map((h) => ({ name: h.name.trim(), ...(h.value ? { value: h.value } : {}) }));
  return body;
}

/** Settings → Integrations: Jira, GitHub, GitLab, Slack and webhooks. Secrets are write-only. */
export default function Integrations() {
  // Every send is audited, so the audit counter (live, from the event stream) says when to look again: no polling.
  const { counters } = useNav();
  const list = useLoad(() => api.get<IntegrationView[]>("/integrations"), [counters?.audit_records]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const action = useAction();
  const set = (p: Partial<Draft>) => setDraft((d) => (d ? { ...d, ...p } : d));
  const save = () =>
    action.run(async () => {
      if (!draft) return;
      await api.put(`/integrations/${encodeURIComponent(draft.name.trim())}`, inputOf(draft));
      toast(`Saved ${draft.name}`, "ok");
      setDraft(null);
      list.reload();
    });

  return (
    <div className="content">
      <p className="muted small" style={{ marginTop: 0 }}>
        Send findings to Jira, GitHub or GitLab as issues, and tell Slack or a webhook when something happens. Tokens are
        kept in your ProxyMind home folder (or read from an environment variable written as <code>env:NAME</code>), never in the
        project file, and are never shown again. Only you can set this up; agents can see the names. Everything sent is
        redacted and logged below (without bodies). An integration that came with a project file stays off until you turn it on here.
      </p>
      <ErrorBox error={list.error} />
      <Panel title="Integrations" actions={<button className="btn primary" data-testid="add-integration" onClick={() => setDraft({ ...BLANK })}>Add integration</button>}>
        {list.data?.length === 0 && !draft && <Empty>No integrations yet.</Empty>}
        {draft && (
          <div className="session-card" data-testid="integration-form">
            <div className="form-grid">
              <label>Kind</label>
              <select aria-label="Integration kind" value={draft.kind} disabled={draft.editing} onChange={(e) => set({ kind: e.target.value as IntegrationKind })}>
                {KINDS.map((k) => <option key={k.id} value={k.id}>{k.label}</option>)}
              </select>
              <label>Name</label>
              <input aria-label="Integration name" value={draft.name} disabled={draft.editing} placeholder="e.g. team-jira" onChange={(e) => set({ name: e.target.value })} />
              {(draft.kind === "jira" || draft.kind === "gitlab" || draft.kind === "webhook" || draft.kind === "github") && (
                <>
                  <label>{draft.kind === "webhook" ? "URL" : "Server URL"}</label>
                  <input aria-label="Integration URL" value={draft.base_url} placeholder={draft.kind === "github" ? "empty for github.com, or https://ghe.example.com/api/v3" : draft.kind === "gitlab" ? "empty for gitlab.com" : "https://"} onChange={(e) => set({ base_url: e.target.value })} />
                </>
              )}
              {isTracker(draft.kind) && (
                <>
                  <label>{draft.kind === "jira" ? "Project key" : draft.kind === "github" ? "Repository" : "Project"}</label>
                  <input aria-label="Integration project" value={draft.project} placeholder={draft.kind === "jira" ? "SEC" : draft.kind === "github" ? "owner/repo" : "group/project or id"} onChange={(e) => set({ project: e.target.value })} />
                </>
              )}
              {draft.kind === "jira" && (
                <>
                  <label>Issue type</label>
                  <input aria-label="Integration issue type" value={draft.issue_type} onChange={(e) => set({ issue_type: e.target.value })} />
                  <label>Email</label>
                  <input aria-label="Integration email" value={draft.email} placeholder="with an API token (Jira Cloud); empty for a personal access token" onChange={(e) => set({ email: e.target.value })} />
                </>
              )}
              {isTracker(draft.kind) && (
                <>
                  <label>Token</label>
                  <input aria-label="Integration token" type="password" autoComplete="off" value={draft.token} placeholder={draft.editing ? "leave empty to keep the saved token, or env:NAME" : "paste the token, or env:NAME"} onChange={(e) => set({ token: e.target.value })} />
                  <label>Labels</label>
                  <input aria-label="Integration labels" value={draft.labels} placeholder="optional, comma separated" onChange={(e) => set({ labels: e.target.value })} />
                </>
              )}
              {draft.kind === "slack" && (
                <>
                  <label>Webhook URL</label>
                  <input aria-label="Integration webhook URL" type="password" autoComplete="off" value={draft.webhook_url} placeholder={draft.editing ? "leave empty to keep the saved URL, or env:NAME" : "https://hooks.slack.com/services/…, or env:NAME"} onChange={(e) => set({ webhook_url: e.target.value })} />
                </>
              )}
              {draft.kind === "webhook" && (
                <>
                  <label>Signing secret</label>
                  <input aria-label="Integration signing secret" type="password" autoComplete="off" value={draft.signing_secret} placeholder="optional: HMAC-SHA256 key for X-ProxyMind-Signature, or env:NAME" onChange={(e) => set({ signing_secret: e.target.value })} />
                  <label>Headers</label>
                  <div>
                    {draft.headers.map((h, i) => (
                      <div key={i} className="row" style={{ marginBottom: 4 }}>
                        <input aria-label={`Header ${i + 1} name`} placeholder="name" value={h.name} onChange={(e) => set({ headers: draft.headers.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)) })} style={{ width: 160 }} />
                        <input aria-label={`Header ${i + 1} value`} type="password" autoComplete="off" className="grow" placeholder="value (kept secret; empty keeps the saved one)" value={h.value} onChange={(e) => set({ headers: draft.headers.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)) })} />
                        <button className="btn" aria-label={`Remove header ${i + 1}`} onClick={() => set({ headers: draft.headers.filter((_, j) => j !== i) })}>×</button>
                      </div>
                    ))}
                    <button className="btn small" onClick={() => set({ headers: [...draft.headers, { name: "", value: "" }] })}>Add header</button>
                  </div>
                </>
              )}
              {!isTracker(draft.kind) && (
                <>
                  <label>Send when</label>
                  <div className="row small" style={{ flexWrap: "wrap", gap: 8 }}>
                    {EVENTS.map((ev) => (
                      <label key={ev.id}>
                        <input type="checkbox" aria-label={`Event ${ev.label}`} checked={draft.events.includes(ev.id)} onChange={(e) => set({ events: e.target.checked ? [...draft.events, ev.id] : draft.events.filter((x) => x !== ev.id) })} /> {ev.label}
                      </label>
                    ))}
                  </div>
                </>
              )}
              <label>Network</label>
              <label className="small">
                <input type="checkbox" aria-label="Allow private destinations" checked={draft.allow_private} onChange={(e) => set({ allow_private: e.target.checked })} /> the address may be a private or loopback one (an office server, a test receiver). Off by default.
              </label>
            </div>
            <div className="row" style={{ marginTop: 8 }}>
              <button className="btn primary" disabled={action.busy || !draft.name.trim()} onClick={save} data-testid="save-integration">Save integration</button>
              <button className="btn" onClick={() => setDraft(null)}>Cancel</button>
              <span className="small muted">Saving turns it on in this installation.</span>
            </div>
            <ErrorBox error={action.error} />
          </div>
        )}
        {list.data?.map((v) => (
          <IntegrationCard key={v.name} v={v} onEdit={() => setDraft(draftOf(v))} onChange={list.reload} />
        ))}
      </Panel>
    </div>
  );
}

function IntegrationCard({ v, onEdit, onChange }: { v: IntegrationView; onEdit: () => void; onChange: () => void }) {
  const action = useAction();
  const { counters } = useNav();
  const log = useLoad(() => api.get<Delivery[]>(`/integrations/${encodeURIComponent(v.name)}/deliveries?limit=20`), [v.name, counters?.audit_records]);
  const test = () =>
    action.run(async () => {
      const r = await api.post<Delivery>(`/integrations/${encodeURIComponent(v.name)}/test`);
      toast(r.status === "ok" ? `${v.name}: it works` : `${v.name}: ${r.detail}`, r.status === "ok" ? "ok" : "bad");
      log.reload();
      onChange();
    });
  const toggle = (enabled: boolean) =>
    action.run(async () => {
      await api.put(`/integrations/${encodeURIComponent(v.name)}/enabled`, { enabled });
      onChange();
    });
  const remove = () =>
    action.run(async () => {
      if (!window.confirm(`Delete ${v.name}, its saved secrets and its delivery log?`)) return;
      await api.del(`/integrations/${encodeURIComponent(v.name)}`);
      onChange();
    });
  const target = v.kind === "slack" ? v.base_url : v.kind === "github" && !v.base_url ? "api.github.com" : v.base_url;
  return (
    <div className="session-card" data-testid={`integration-${v.name}`}>
      <div className="row">
        <strong className="grow">{v.name}</strong>
        <Chip value={v.kind} />
        <Chip value={v.needs_review ? "needs review" : v.active ? "on" : "off"} />
      </div>
      <div className="small muted mono">{target}{v.project ? ` · ${v.project}` : ""}{v.allow_private ? " · private destinations allowed" : ""}</div>
      {v.events.length > 0 && <div className="small">Sends: {v.events.map((e) => EVENTS.find((x) => x.id === e)?.label ?? e).join(", ")}</div>}
      <div className="small">
        Secrets:{" "}
        {Object.entries(v.secret_status).map(([slot, s]) => (
          <span key={slot} className="chip mono" title={s.reference ?? s.source}>{slot}: {s.source}{s.hint ? ` ${s.hint}` : ""}</span>
        ))}
      </div>
      {v.needs_review && (
        <div className="error" role="alert">
          This integration was not turned on in this installation (it may have come with the project file) and sends nothing.
          Check where it points ({target}) before you turn it on.
        </div>
      )}
      {v.problems.map((p) => <div key={p} className="small muted">{p}</div>)}
      {v.last_error && <div className="error" data-testid="integration-error">Last error: {v.last_error.message} <span className="muted">({fmtDateTime(v.last_error.ts_ms)})</span></div>}
      <div className="row" style={{ marginTop: 6 }}>
        {v.active ? (
          <button className="btn" disabled={action.busy} onClick={test} data-testid={`send-test-${v.name}`}>Send test</button>
        ) : null}
        <button className="btn" disabled={action.busy} onClick={() => toggle(!(v.enabled && !v.needs_review))}>
          {v.enabled && !v.needs_review ? "Turn off" : "Turn on"}
        </button>
        <button className="btn" onClick={onEdit}>Edit</button>
        <button className="btn" disabled={action.busy} onClick={remove}>Delete integration</button>
      </div>
      <ErrorBox error={action.error} />
      <table className="grid" data-testid={`deliveries-${v.name}`} style={{ marginTop: 6 }}>
        <thead><tr><th>When</th><th>What</th><th>Result</th><th>Detail</th></tr></thead>
        <tbody>
          {(log.data ?? []).map((d) => (
            <tr key={d.id}>
              <td className="small muted">{fmtDateTime(d.ts_ms)}</td>
              <td className="small">{d.event}{d.finding_id != null ? ` #${d.finding_id}` : ""}</td>
              <td><Chip value={d.status} /> <span className="small muted">{d.http_status ?? ""} · {d.attempts}×</span></td>
              <td className="small">{d.host} {d.detail}</td>
            </tr>
          ))}
          {log.data?.length === 0 && <tr><td colSpan={4} className="small muted">Nothing sent yet.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}
