import { useEffect, useState } from "react";
import { api } from "../api";
import { Chip, Empty, ErrorBox, Panel, useAction, useLoad, useNav } from "../components";

interface Settings {
  enabled: boolean;
  requests: boolean;
  responses: boolean;
  websocket: boolean;
  in_scope_only: boolean;
  host_contains: string;
  path_contains: string;
  skip_extensions: string[];
}

interface Held {
  id: number;
  kind: "request" | "response" | "ws_to_server" | "ws_to_client";
  scheme: string;
  host: string;
  port: number;
  method: string;
  path: string;
  raw: string;
  editable: boolean;
  held_ms: number;
}

const KIND_LABEL: Record<Held["kind"], string> = {
  request: "request",
  response: "response",
  ws_to_server: "WS → server",
  ws_to_client: "WS ← server",
};

const KIND_TITLE: Record<Held["kind"], string> = {
  request: "Request",
  response: "Response",
  ws_to_server: "WebSocket message to the server",
  ws_to_client: "WebSocket message to the browser",
};

interface State {
  attached: boolean;
  settings: Settings;
  held: Held[];
}

export default function Intercept() {
  const { counters } = useNav();
  const state = useLoad(() => api.get<State>("/intercept"), [counters?.intercepted]);
  const [draft, setDraft] = useState<Settings | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [text, setText] = useState("");
  const [fixCl, setFixCl] = useState(true);
  const action = useAction();

  const settings = draft ?? state.data?.settings ?? null;
  const held = state.data?.held ?? [];
  const current = held.find((h) => h.id === selected) ?? held[0];

  // Load the selected message into the editor when it changes.
  useEffect(() => {
    if (current) {
      setSelected(current.id);
      setText(current.raw.replace(/\r\n/g, "\n"));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [current?.id]);

  const save = (s: Settings) =>
    action.run(async () => {
      const r = await api.put<State>("/intercept/settings", s);
      setDraft(null);
      state.setData(r);
    });

  const forward = (edited: boolean) =>
    current &&
    action.run(async () => {
      const original = current.raw.replace(/\r\n/g, "\n");
      await api.post(`/intercept/${current.id}/forward`, {
        raw: edited && text !== original ? text : undefined,
        fix_content_length: fixCl,
      });
      setSelected(null);
      state.reload();
    });

  const drop = () =>
    current &&
    action.run(async () => {
      await api.post(`/intercept/${current.id}/drop`);
      setSelected(null);
      state.reload();
    });

  if (state.data && !state.data.attached) {
    return (
      <div className="content">
        <Panel>
          <Empty>Interception works when the proxy runs in the same process: start ProxyMind with <code>proxymind ui</code>.</Empty>
        </Panel>
      </div>
    );
  }
  if (!settings) return <div className="content muted">Loading…</div>;
  const set = (patch: Partial<Settings>) => setDraft({ ...settings, ...patch });

  return (
    <div className="content">
      <Panel
        title="Intercept"
        actions={
          <button
            className={`btn ${settings.enabled ? "primary" : ""}`}
            data-testid="intercept-toggle"
            disabled={action.busy}
            onClick={() => save({ ...settings, enabled: !settings.enabled })}
          >
            {settings.enabled ? "Intercept is ON" : "Intercept is OFF"}
          </button>
        }
      >
        <div className="row small">
          <label className="row" style={{ gap: 4 }}>
            <input type="checkbox" checked={settings.requests} onChange={(e) => set({ requests: e.target.checked })} /> requests
          </label>
          <label className="row" style={{ gap: 4 }}>
            <input type="checkbox" checked={settings.responses} onChange={(e) => set({ responses: e.target.checked })} /> responses
          </label>
          <label className="row" style={{ gap: 4 }} title="Applies to WebSocket connections opened while this is on (they are opened without compression so messages can be edited)">
            <input type="checkbox" aria-label="WebSocket messages" checked={settings.websocket} onChange={(e) => set({ websocket: e.target.checked })} /> WebSocket messages
          </label>
          <label className="row" style={{ gap: 4 }}>
            <input type="checkbox" checked={settings.in_scope_only} onChange={(e) => set({ in_scope_only: e.target.checked })} /> in scope only
          </label>
          <input aria-label="Host filter" placeholder="host contains…" value={settings.host_contains} onChange={(e) => set({ host_contains: e.target.value })} />
          <input aria-label="Path filter" placeholder="path contains…" value={settings.path_contains} onChange={(e) => set({ path_contains: e.target.value })} />
          <input
            aria-label="Skip extensions"
            className="grow"
            title="Paths ending in these extensions are never held"
            value={settings.skip_extensions.join(" ")}
            onChange={(e) => set({ skip_extensions: e.target.value.split(/[\s,]+/).filter(Boolean) })}
          />
          {draft && <button className="btn primary" onClick={() => save(draft)} disabled={action.busy}>Apply</button>}
        </div>
        <p className="small muted" style={{ marginBottom: 0 }}>
          While on, matching traffic waits here until you forward, edit or drop it. Turning it off lets everything waiting through
          unchanged. Edits and drops are recorded in the audit log; the project keeps the server's original responses. WebSocket
          messages are held on connections opened while that option is on; history records what was delivered.
        </p>
      </Panel>
      <ErrorBox error={state.error ?? action.error} />
      <div className="split">
        <Panel title={`Waiting (${held.length})`} actions={held.length > 1 && <button className="btn" onClick={() => action.run(async () => { await api.post("/intercept/forward-all"); state.reload(); })}>Forward all</button>}>
          {held.length === 0 && <Empty>{settings.enabled ? "Nothing waiting. Browse through the proxy." : "Intercept is off."}</Empty>}
          {held.length > 0 && (
            <table className="grid" data-testid="intercept-queue">
              <tbody>
                {held.map((h) => (
                  <tr key={h.id} className="clickable" onClick={() => setSelected(h.id)} style={current?.id === h.id ? { background: "var(--accent-soft)" } : undefined}>
                    <td><Chip value={KIND_LABEL[h.kind]} /></td>
                    <td>{h.method}</td>
                    <td className="mono small" style={{ wordBreak: "break-all" }}>{h.scheme}://{h.host}:{h.port}{h.path}</td>
                    <td className="small muted">{Math.max(0, Math.round((Date.now() - h.held_ms) / 1000))}s</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
        <Panel title={current ? `${KIND_TITLE[current.kind]} #${current.id}` : "Editor"}>
          {!current && <Empty>Select a held message.</Empty>}
          {current && (
            <>
              <textarea
                aria-label="Held message"
                rows={20}
                value={text}
                readOnly={!current.editable}
                onChange={(e) => setText(e.target.value)}
                spellCheck={false}
              />
              {!current.editable && <div className="notice">Binary content: forward or drop it as is.</div>}
              <div className="row" style={{ marginTop: 8 }}>
                <button className="btn primary" data-testid="intercept-forward" disabled={action.busy} onClick={() => forward(true)}>
                  Forward
                </button>
                <button className="btn" disabled={action.busy} onClick={() => forward(false)}>Forward original</button>
                <button className="btn bad" data-testid="intercept-drop" disabled={action.busy} onClick={drop}>Drop</button>
                {current.kind === "request" && (
                  <label className="small row" style={{ gap: 4 }}>
                    <input type="checkbox" checked={fixCl} onChange={(e) => setFixCl(e.target.checked)} /> fix Content-Length
                  </label>
                )}
              </div>
            </>
          )}
        </Panel>
      </div>
    </div>
  );
}
