import { useState } from "react";
import { api, fmtDateTime, type ExchangeSummary } from "../api";
import { Empty, ErrorBox, ExchangeLink, Panel, StatusCode, useLoad, useNav } from "../components";

interface Item {
  id: number; exchange_id: number; status: string; note: string; actor: string;
  created_ms: number; updated_ms: number; exchange?: ExchangeSummary;
}

const STATUSES = [
  ["new", "New"],
  ["in_progress", "In progress"],
  ["postponed", "Postponed"],
  ["done", "Done"],
  ["ignored", "Ignored"],
] as const;

/** Exchanges kept aside to come back to, with a status and notes. Add them from HTTP history (right-click). */
export default function Organizer() {
  const { go } = useNav();
  const [status, setStatus] = useState("");
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const list = useLoad(() => api.get<Item[]>(`/organizer${status ? `?status=${status}` : ""}`), [status]);
  const update = (id: number, change: { status?: string; note?: string }) =>
    api.patch(`/organizer/${id}`, change).then(list.reload).catch((e: Error) => setError(e.message));
  const remove = (id: number) => api.del(`/organizer/${id}`).then(list.reload).catch((e: Error) => setError(e.message));
  const t = text.toLowerCase();
  const items = (list.data ?? []).filter(
    (i) => !t || i.note.toLowerCase().includes(t) || `${i.exchange?.host}${i.exchange?.path}`.toLowerCase().includes(t),
  );
  const counts = (list.data ?? []).reduce<Record<string, number>>((m, i) => ((m[i.status] = (m[i.status] ?? 0) + 1), m), {});
  return (
    <div className="content">
      <Panel title="Organizer">
        <div className="row small">
          <select aria-label="Organizer status" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">all statuses</option>
            {STATUSES.map(([v, l]) => <option key={v} value={v}>{l}{!status && counts[v] ? ` (${counts[v]})` : ""}</option>)}
          </select>
          <input aria-label="Organizer filter" placeholder="filter by URL or note" value={text} onChange={(e) => setText(e.target.value)} style={{ width: 240 }} />
          <span className="muted">Right-click a request in HTTP history and pick “Send to Organizer”.</span>
        </div>
        <ErrorBox error={error ?? list.error} />
        {list.data && items.length === 0 && <Empty>Nothing here yet.</Empty>}
        {items.length > 0 && (
          <table className="grid" data-testid="organizer-list">
            <thead><tr><th>#</th><th>Request</th><th>Status</th><th>Note</th><th>Added</th><th /></tr></thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.id} data-testid="organizer-item">
                  <td><ExchangeLink id={i.exchange_id} /></td>
                  <td className="mono small" style={{ wordBreak: "break-all" }}>
                    {i.exchange ? <>{i.exchange.method} {i.exchange.host}{i.exchange.path} <StatusCode status={i.exchange.status} /></> : <span className="muted">deleted</span>}
                  </td>
                  <td>
                    <select aria-label={`Status of ${i.id}`} value={i.status} onChange={(e) => update(i.id, { status: e.target.value })}>
                      {STATUSES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                    </select>
                  </td>
                  <td>
                    <Note value={i.note} onSave={(note) => update(i.id, { note })} />
                  </td>
                  <td className="small muted">{fmtDateTime(i.created_ms)} · {i.actor}</td>
                  <td className="row small">
                    <button className="btn" onClick={() => go("replay", i.exchange_id)}>Replay</button>
                    <button className="btn" aria-label={`Remove ${i.id}`} onClick={() => remove(i.id)}>Remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

function Note({ value, onSave }: { value: string; onSave: (v: string) => void }) {
  const [v, setV] = useState(value);
  return (
    <textarea
      aria-label="Organizer note"
      rows={1}
      value={v}
      onChange={(e) => setV(e.target.value)}
      onBlur={() => v !== value && onSave(v)}
      style={{ width: "100%", minWidth: 200 }}
    />
  );
}
