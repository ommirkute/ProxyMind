import { useState } from "react";
import { api } from "../api";
import { ErrorBox, Panel, useAction, useLoad } from "../components";
import type { ListenerStatus } from "../api-types.gen";

interface ListenerConfig {
  bind: string;
  kind: "http" | "socks5";
  transparent: boolean;
  username: string;
  password: string;
  enabled: boolean;
  redirect_host: string;
  redirect_port: number;
  force_tls: boolean;
}


interface ListenersView {
  primary: string | null;
  listeners: ListenerConfig[];
  status: ListenerStatus[];
  transparent_supported: boolean;
}

const NEW: ListenerConfig = {
  bind: "127.0.0.1:8081",
  kind: "http",
  transparent: false,
  username: "",
  password: "",
  enabled: true,
  redirect_host: "",
  redirect_port: 0,
  force_tls: false,
};

/** Extra listeners: more HTTP proxy ports, SOCKS5 servers, transparent (redirected) traffic, other interfaces, redirects. */
export default function Listeners() {
  const saved = useLoad(() => api.get<ListenersView>("/proxy/listeners"), []);
  const [draft, setDraft] = useState<ListenerConfig[] | null>(null);
  const action = useAction();
  const view = saved.data;
  const list = (draft ?? view?.listeners ?? []).map((l) => ({ ...NEW, ...l }));
  const transparentOk = view?.transparent_supported ?? true;
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
        Main listener: <code>{view?.primary ?? "not running in this process"}</code>. An <b>HTTP</b> listener takes normal
        proxy clients and invisible ones (apps and devices that ignore proxy settings, sent here by DNS or a port forward:
        requests go where their Host header or TLS server name says). A <b>SOCKS5</b> listener is for clients that speak
        SOCKS (curl <code>--socks5-hostname</code>, browsers, Android apps through a SOCKS app): web traffic is recorded
        like proxy traffic and other protocols pass through unrecorded; it can ask for a username and password. A{" "}
        <b>transparent</b> HTTP listener takes traffic your operating system redirected here (Linux iptables/nftables, see
        docs/capture.md) and sends it where each client was going. A redirect sends everything on a listener to one host.
        Use <code>0.0.0.0:port</code> for a phone on your network.
      </p>
      {!transparentOk && (
        <p className="small muted" data-testid="transparent-unsupported">
          Transparent mode needs Linux. This computer can't take redirected traffic (macOS pf and Windows aren't supported
          yet), so the option is greyed out; use a proxy or SOCKS5 listener instead.
        </p>
      )}
      {list.length > 0 && (
        <table className="grid">
          <thead>
            <tr><th>On</th><th>Type</th><th>Listen on</th><th>Options</th><th>Redirect to (optional)</th><th>Force TLS</th><th>Status</th><th /></tr>
          </thead>
          <tbody>
            {list.map((l, i) => {
              const st = statusOf(l.bind);
              return (
                <tr key={i}>
                  <td><input type="checkbox" aria-label={`Listener ${i + 1} enabled`} checked={l.enabled} onChange={(e) => set(i, { enabled: e.target.checked })} /></td>
                  <td>
                    <select aria-label={`Listener ${i + 1} type`} value={l.kind} onChange={(e) => set(i, { kind: e.target.value as ListenerConfig["kind"], transparent: false, username: "", password: "" })}>
                      <option value="http">HTTP proxy</option>
                      <option value="socks5">SOCKS5</option>
                    </select>
                  </td>
                  <td><input className="mono" aria-label={`Listener ${i + 1} address`} value={l.bind} onChange={(e) => set(i, { bind: e.target.value })} style={{ width: 160 }} /></td>
                  <td>
                    {l.kind === "socks5" ? (
                      <div className="row">
                        <input aria-label={`Listener ${i + 1} username`} placeholder="username (optional)" autoComplete="off" value={l.username} onChange={(e) => set(i, { username: e.target.value })} style={{ width: 130 }} />
                        <input type="password" aria-label={`Listener ${i + 1} password`} placeholder="password" autoComplete="new-password" value={l.password} disabled={!l.username} onChange={(e) => set(i, { password: e.target.value })} style={{ width: 110 }} />
                      </div>
                    ) : (
                      <label className="row small" style={{ gap: 4 }} title={transparentOk ? "Take traffic the operating system redirected here" : "Needs Linux: not supported on this computer"}>
                        <input type="checkbox" aria-label={`Listener ${i + 1} transparent`} checked={l.transparent} disabled={!transparentOk || !!l.redirect_host} onChange={(e) => set(i, { transparent: e.target.checked })} />
                        transparent{!transparentOk && <span className="muted"> (Linux only)</span>}
                      </label>
                    )}
                  </td>
                  <td>
                    <div className="row">
                      <input className="mono" aria-label={`Listener ${i + 1} redirect host`} placeholder="host" value={l.redirect_host} disabled={l.transparent} onChange={(e) => set(i, { redirect_host: e.target.value })} style={{ width: 150 }} />
                      <input type="number" aria-label={`Listener ${i + 1} redirect port`} placeholder="port" min={0} max={65535} value={l.redirect_port || ""} onChange={(e) => set(i, { redirect_port: Number(e.target.value) })} style={{ width: 80 }} />
                    </div>
                  </td>
                  <td><input type="checkbox" aria-label={`Listener ${i + 1} force TLS`} checked={l.force_tls} disabled={!l.redirect_host} onChange={(e) => set(i, { force_tls: e.target.checked })} /></td>
                  <td className="small" data-testid="listener-status">
                    {draft ? <span className="muted">unsaved</span> : !l.enabled ? <span className="muted">off</span> : st?.running ? <span className="good">listening{l.kind === "socks5" ? " (SOCKS5)" : l.transparent ? " (transparent)" : ""}</span> : st?.error ? <span className="bad">{st.error}</span> : <span className="muted">starts with the proxy</span>}
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
