import { useState } from "react";
import { api } from "../api";
import { ErrorBox, Panel, useAction, useLoad } from "../components";

interface ListenerConfig {
  bind: string;
  enabled: boolean;
  redirect_host: string;
  redirect_port: number;
  force_tls: boolean;
}

interface ListenerStatus {
  bind: string;
  running: boolean;
  error?: string;
}

interface ListenersView {
  primary: string | null;
  listeners: ListenerConfig[];
  status: ListenerStatus[];
}

const NEW: ListenerConfig = { bind: "127.0.0.1:8081", enabled: true, redirect_host: "", redirect_port: 0, force_tls: false };

/** Extra proxy listeners: more ports, other interfaces, and redirects for invisible clients. */
export default function Listeners() {
  const saved = useLoad(() => api.get<ListenersView>("/proxy/listeners"), []);
  const [draft, setDraft] = useState<ListenerConfig[] | null>(null);
  const action = useAction();
  const view = saved.data;
  const list = draft ?? view?.listeners ?? [];
  const set = (i: number, patch: Partial<ListenerConfig>) => setDraft(list.map((l, j) => (j === i ? { ...l, ...patch } : l)));
  const statusOf = (bind: string) => view?.status.find((s) => s.bind === bind.trim());
  const save = () =>
    action.run(async () => {
      const r = await api.put<ListenersView>("/proxy/listeners", { listeners: list });
      saved.setData(r);
      setDraft(null);
    });
  const exposed = list.some((l) => l.enabled && /^(0\.0\.0\.0|\[::\]|::):/.test(l.bind.trim()));

  return (
    <Panel
      title="3. Proxy listeners"
      actions={<button className="btn" data-testid="add-listener" onClick={() => setDraft([...list, { ...NEW, bind: `127.0.0.1:${8081 + list.length}` }])}>Add listener</button>}
    >
      <p className="small muted" style={{ marginTop: 0 }}>
        Main listener: <code>{view?.primary ?? "not running in this process"}</code>. Extra listeners take normal proxy
        clients and invisible ones (apps and devices that ignore proxy settings, sent here by DNS or a port forward:
        requests go where their Host header or TLS server name says). A redirect sends everything on that listener to one
        host, for clients that can't be pointed anywhere else. Use <code>0.0.0.0:port</code> for a phone on your network.
      </p>
      {list.length > 0 && (
        <table className="grid">
          <thead>
            <tr><th>On</th><th>Listen on</th><th>Redirect to (optional)</th><th>Force TLS</th><th>Status</th><th /></tr>
          </thead>
          <tbody>
            {list.map((l, i) => {
              const st = statusOf(l.bind);
              return (
                <tr key={i}>
                  <td><input type="checkbox" aria-label={`Listener ${i + 1} enabled`} checked={l.enabled} onChange={(e) => set(i, { enabled: e.target.checked })} /></td>
                  <td><input className="mono" aria-label={`Listener ${i + 1} address`} value={l.bind} onChange={(e) => set(i, { bind: e.target.value })} style={{ width: 160 }} /></td>
                  <td>
                    <div className="row">
                      <input className="mono" aria-label={`Listener ${i + 1} redirect host`} placeholder="host" value={l.redirect_host} onChange={(e) => set(i, { redirect_host: e.target.value })} style={{ width: 150 }} />
                      <input type="number" aria-label={`Listener ${i + 1} redirect port`} placeholder="port" min={0} max={65535} value={l.redirect_port || ""} onChange={(e) => set(i, { redirect_port: Number(e.target.value) })} style={{ width: 80 }} />
                    </div>
                  </td>
                  <td><input type="checkbox" aria-label={`Listener ${i + 1} force TLS`} checked={l.force_tls} disabled={!l.redirect_host} onChange={(e) => set(i, { force_tls: e.target.checked })} /></td>
                  <td className="small" data-testid="listener-status">
                    {draft ? <span className="muted">unsaved</span> : !l.enabled ? <span className="muted">off</span> : st?.running ? <span className="good">listening</span> : st?.error ? <span className="bad">{st.error}</span> : <span className="muted">starts with the proxy</span>}
                  </td>
                  <td><button className="btn" aria-label={`Delete listener ${i + 1}`} onClick={() => setDraft(list.filter((_, j) => j !== i))}>✕</button></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {exposed && (
        <div className="notice warn small" role="status">
          A listener on all interfaces lets other machines on your network use this proxy and see its traffic. Use it on a
          trusted network only, and turn it off when you're done.
        </div>
      )}
      <ErrorBox error={saved.error ?? action.error} />
      <div className="row" style={{ marginTop: 8 }}>
        <button className="btn primary" data-testid="listeners-save" disabled={!draft || action.busy} onClick={save}>Save listeners</button>
        {draft && <button className="btn" onClick={() => setDraft(null)}>Discard changes</button>}
      </div>
    </Panel>
  );
}
