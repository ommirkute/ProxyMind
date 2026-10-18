import { useState } from "react";
import { api } from "../api";
import { ErrorBox, Panel, useAction, useLoad } from "../components";

interface Upstream {
  kind: "http" | "socks5";
  host: string;
  port: number;
  username: string;
  password: string;
  remote_dns: boolean;
  bypass: string[];
}

interface ClientCert {
  host: string;
  cert_file: string;
  key_file: string;
}

interface NetConfig {
  upstream: Upstream | null;
  client_certs: ClientCert[];
}

const DEFAULT_UPSTREAM: Upstream = {
  kind: "http",
  host: "",
  port: 8080,
  username: "",
  password: "",
  remote_dns: false,
  bypass: ["localhost", "127.0.0.1"],
};

export default function Network() {
  const saved = useLoad(() => api.get<NetConfig>("/network"), []);
  const [draft, setDraft] = useState<NetConfig | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const action = useAction();
  const cfg = draft ?? saved.data;
  if (!cfg) return <div className="content"><ErrorBox error={saved.error} /></div>;

  const set = (patch: Partial<NetConfig>) => {
    setNotice(null);
    setDraft({ ...cfg, ...patch });
  };
  const up = cfg.upstream;
  const setUp = (patch: Partial<Upstream>) => up && set({ upstream: { ...up, ...patch } });
  const setCert = (i: number, patch: Partial<ClientCert>) =>
    set({ client_certs: cfg.client_certs.map((c, j) => (j === i ? { ...c, ...patch } : c)) });
  const save = () =>
    action.run(async () => {
      const r = await api.put<NetConfig>("/network", cfg);
      saved.setData(r);
      setDraft(null);
      setNotice("Saved. The proxy, Repeater and agents use these settings from now on.");
    });

  return (
    <div className="content">
      <Panel
        title="Upstream proxy"
        actions={
          <label className="row small" style={{ gap: 4 }}>
            <input
              type="checkbox"
              data-testid="upstream-toggle"
              checked={!!up}
              onChange={(e) => set({ upstream: e.target.checked ? { ...DEFAULT_UPSTREAM } : null })}
            />
            Send traffic through another proxy
          </label>
        }
      >
        {!up && <p className="muted small" style={{ margin: 0 }}>Connecting directly to targets.</p>}
        {up && (
          <div className="form-grid">
            <label>Type</label>
            <select aria-label="Proxy type" value={up.kind} onChange={(e) => setUp({ kind: e.target.value as Upstream["kind"] })}>
              <option value="http">HTTP (CONNECT for HTTPS)</option>
              <option value="socks5">SOCKS5</option>
            </select>
            <label>Host and port</label>
            <div className="row">
              <input aria-label="Proxy host" className="grow" placeholder="proxy.corp.example" value={up.host} onChange={(e) => setUp({ host: e.target.value })} />
              <input aria-label="Proxy port" type="number" min={1} max={65535} style={{ width: 90 }} value={up.port} onChange={(e) => setUp({ port: Number(e.target.value) })} />
            </div>
            <label>Login (optional)</label>
            <div className="row">
              <input aria-label="Proxy username" placeholder="username" value={up.username} onChange={(e) => setUp({ username: e.target.value })} />
              <input aria-label="Proxy password" type="password" placeholder="password" value={up.password} onChange={(e) => setUp({ password: e.target.value })} />
            </div>
            {up.kind === "socks5" && (
              <>
                <label>DNS</label>
                <label className="row small" style={{ gap: 4 }}>
                  <input type="checkbox" checked={up.remote_dns} onChange={(e) => setUp({ remote_dns: e.target.checked })} />
                  Let the proxy resolve names (socks5h). Off: ProxyMind resolves and checks each address itself.
                </label>
              </>
            )}
            <label>Connect directly to</label>
            <textarea
              aria-label="Bypass list"
              rows={3}
              placeholder={"localhost\n*.internal.example"}
              value={up.bypass.join("\n")}
              onChange={(e) => setUp({ bypass: e.target.value.split(/\n/).map((x) => x.trim()).filter(Boolean) })}
            />
          </div>
        )}
      </Panel>
      <Panel
        title="Client certificates"
        actions={
          <button className="btn" onClick={() => set({ client_certs: [...cfg.client_certs, { host: "", cert_file: "", key_file: "" }] })}>
            Add certificate
          </button>
        }
      >
        <p className="small muted" style={{ marginTop: 0 }}>
          For servers that require mutual TLS. Paths to PEM files on this machine; the first matching host is used
          (<code>api.example.com</code>, <code>*.example.com</code> or <code>*</code>). Convert a .p12 with{" "}
          <code>openssl pkcs12 -in cert.p12 -out cert.pem -nodes</code>.
        </p>
        {cfg.client_certs.length > 0 && (
          <table className="grid">
            <thead>
              <tr><th>Host</th><th>Certificate (PEM)</th><th>Private key (PEM)</th><th /></tr>
            </thead>
            <tbody>
              {cfg.client_certs.map((c, i) => (
                <tr key={i}>
                  <td><input aria-label={`Certificate ${i + 1} host`} value={c.host} onChange={(e) => setCert(i, { host: e.target.value })} /></td>
                  <td><input className="mono wide" aria-label={`Certificate ${i + 1} file`} value={c.cert_file} onChange={(e) => setCert(i, { cert_file: e.target.value })} /></td>
                  <td><input className="mono wide" aria-label={`Certificate ${i + 1} key`} value={c.key_file} onChange={(e) => setCert(i, { key_file: e.target.value })} /></td>
                  <td>
                    <button className="btn" aria-label={`Delete certificate ${i + 1}`} onClick={() => set({ client_certs: cfg.client_certs.filter((_, j) => j !== i) })}>
                      ✕
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
      <ErrorBox error={saved.error ?? action.error} />
      {notice && <div className="notice" role="status">{notice}</div>}
      <div className="row">
        <button className="btn primary" data-testid="network-save" disabled={!draft || action.busy} onClick={save}>Save</button>
        {draft && <button className="btn" onClick={() => setDraft(null)}>Discard changes</button>}
      </div>
    </div>
  );
}
