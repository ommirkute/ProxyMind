import { useEffect, useState } from "react";
import { api } from "../api";
import { ErrorBox, Panel, useAction, useLoad } from "../components";
import type { ClientCert, HostOverride, UpstreamResolution } from "../api-types.gen";

/** One entry of the ordered upstream list (the shape of `UpstreamRule` with every field present). */
interface Rule {
  match: string[];
  via: string;
  username: string;
  password: string;
  remote_dns: boolean;
}

interface NetConfig {
  upstream_rules: Rule[];
  client_certs: ClientCert[];
  hosts: HostOverride[];
  tls_passthrough: string[];
}

type ViaKind = "direct" | "http" | "socks5";

/** Splits `http://host:port` into its parts for the editor ("direct" has none). */
function parseVia(via: string): { kind: ViaKind; host: string; port: string } {
  const m = /^(http|socks5):\/\/(.*?)(?::(\d+))?\/?$/i.exec(via.trim());
  if (!m) return { kind: "direct", host: "", port: "" };
  return { kind: m[1].toLowerCase() as ViaKind, host: m[2], port: m[3] ?? "" };
}

const viaOf = (kind: ViaKind, host: string, port: string) => (kind === "direct" ? "direct" : `${kind}://${host}${port ? `:${port}` : ""}`);

const NEW_RULE: Rule = { match: [], via: "http://:8080", username: "", password: "", remote_dns: false };

/** Match patterns as typed: comma or space separated. */
const splitMatch = (text: string) => text.split(/[\s,]+/).filter(Boolean);

function RuleTable({ rules, set }: { rules: Rule[]; set: (r: Rule[]) => void }) {
  const [typed, setTyped] = useState<Record<number, string>>({});
  const patch = (i: number, p: Partial<Rule>) => set(rules.map((r, j) => (j === i ? { ...r, ...p } : r)));
  const move = (i: number, d: number) => {
    const next = [...rules];
    [next[i], next[i + d]] = [next[i + d], next[i]];
    setTyped({});
    set(next);
  };
  return (
    <table className="grid">
      <thead>
        <tr><th>#</th><th>Match (hosts, * patterns, CIDR ranges)</th><th>Go via</th><th>Login (optional)</th><th>DNS</th><th /></tr>
      </thead>
      <tbody>
        {rules.map((r, i) => {
          const v = parseVia(r.via);
          const setVia = (p: Partial<{ kind: ViaKind; host: string; port: string }>) => {
            const n = { ...v, ...p };
            patch(i, { via: viaOf(n.kind, n.host, n.port), ...(n.kind === "direct" ? { username: "", password: "", remote_dns: false } : {}) });
          };
          return (
            <tr key={i} data-testid="upstream-rule">
              <td>{i + 1}</td>
              <td>
                <input
                  className="mono"
                  aria-label={`Rule ${i + 1} match`}
                  placeholder={i === rules.length - 1 ? "empty: all other hosts" : "*.corp.example, 10.0.0.0/8"}
                  style={{ width: 240 }}
                  value={typed[i] ?? r.match.join(", ")}
                  onChange={(e) => {
                    setTyped({ ...typed, [i]: e.target.value });
                    patch(i, { match: splitMatch(e.target.value) });
                  }}
                  onBlur={() => setTyped(({ [i]: _, ...rest }) => rest)}
                />
              </td>
              <td>
                <div className="row">
                  <select aria-label={`Rule ${i + 1} via`} value={v.kind} onChange={(e) => setVia({ kind: e.target.value as ViaKind })}>
                    <option value="direct">Direct</option>
                    <option value="http">HTTP proxy</option>
                    <option value="socks5">SOCKS5 proxy</option>
                  </select>
                  {v.kind !== "direct" && (
                    <>
                      <input className="mono" aria-label={`Rule ${i + 1} proxy host`} placeholder="proxy.corp.example" style={{ width: 150 }} value={v.host} onChange={(e) => setVia({ host: e.target.value })} />
                      <input className="mono" aria-label={`Rule ${i + 1} proxy port`} type="number" min={1} max={65535} style={{ width: 80 }} value={v.port} onChange={(e) => setVia({ port: e.target.value })} />
                    </>
                  )}
                </div>
              </td>
              <td>
                {v.kind !== "direct" && (
                  <div className="row">
                    <input aria-label={`Rule ${i + 1} username`} placeholder="username" autoComplete="off" style={{ width: 100 }} value={r.username} onChange={(e) => patch(i, { username: e.target.value })} />
                    <input aria-label={`Rule ${i + 1} password`} type="password" placeholder="password" autoComplete="new-password" style={{ width: 100 }} value={r.password} onChange={(e) => patch(i, { password: e.target.value })} />
                  </div>
                )}
              </td>
              <td>
                {v.kind !== "direct" && (
                  <label className="row small" style={{ gap: 4 }} title={v.kind === "socks5" ? "socks5h: the proxy resolves names. Off: ProxyMind resolves, checks the address and asks for it." : "CONNECT names the host. Off: CONNECT asks for the address ProxyMind resolved and checked."}>
                    <input type="checkbox" aria-label={`Rule ${i + 1} remote DNS`} checked={r.remote_dns} onChange={(e) => patch(i, { remote_dns: e.target.checked })} />
                    proxy resolves
                  </label>
                )}
              </td>
              <td style={{ whiteSpace: "nowrap" }}>
                <button className="btn" aria-label={`Move rule ${i + 1} up`} disabled={i === 0} onClick={() => move(i, -1)}>↑</button>{" "}
                <button className="btn" aria-label={`Move rule ${i + 1} down`} disabled={i === rules.length - 1} onClick={() => move(i, 1)}>↓</button>{" "}
                <button className="btn" aria-label={`Delete rule ${i + 1}`} onClick={() => { setTyped({}); set(rules.filter((_, j) => j !== i)); }}>✕</button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

/** Asks the server which rule decides for a host, using the rules as edited (saved or not). */
function ResolveTool({ rules }: { rules: Rule[] }) {
  const [host, setHost] = useState("");
  const [result, setResult] = useState<UpstreamResolution | null>(null);
  const action = useAction();
  // What the tool said is about the rules as they were: drop it when they change.
  const shape = JSON.stringify(rules);
  useEffect(() => setResult(null), [shape]);
  const run = () =>
    action.run(async () => {
      setResult(await api.post<UpstreamResolution>("/network/upstream/resolve", { host: host.trim(), rules }));
    });
  return (
    <div style={{ marginTop: 12 }}>
      <div className="row">
        <input aria-label="Host to test" className="mono" placeholder="api.corp.example or 10.1.2.3" style={{ width: 260 }} value={host} onChange={(e) => { setHost(e.target.value); setResult(null); }} onKeyDown={(e) => e.key === "Enter" && host.trim() && run()} />
        <button className="btn" data-testid="resolve-go" disabled={!host.trim() || action.busy} onClick={run}>Which rule matches?</button>
      </div>
      <ErrorBox error={action.error} />
      {result && (
        <div className="notice small" role="status" data-testid="resolve-result">
          {result.rule_index === null
            ? "No rule matches: this host is reached directly."
            : `Rule ${result.rule_index + 1}${result.pattern ? ` (matched ${result.pattern})` : " (matches every host)"}: ${result.direct ? "direct" : `via ${result.via}${result.remote_dns ? ", the proxy resolves names" : ""}`}.`}
        </div>
      )}
    </div>
  );
}

export default function Network() {
  const saved = useLoad(() => api.get<NetConfig>("/network"), []);
  const [draft, setDraft] = useState<NetConfig | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const action = useAction();
  const loaded = draft ?? saved.data;
  const cfg = loaded
    ? {
        ...loaded,
        upstream_rules: (loaded.upstream_rules ?? []).map((r) => ({ ...NEW_RULE, ...r })),
        hosts: loaded.hosts ?? [],
        tls_passthrough: loaded.tls_passthrough ?? [],
      }
    : null;
  if (!cfg) return <div className="content">{saved.error ? <ErrorBox error={saved.error} /> : <span className="muted">Loading…</span>}</div>;

  const set = (patch: Partial<NetConfig>) => {
    setNotice(null);
    setDraft({ ...cfg, ...patch });
  };
  const setHost = (i: number, patch: Partial<HostOverride>) =>
    set({ hosts: cfg.hosts.map((h, j) => (j === i ? { ...h, ...patch } : h)) });
  const setCert = (i: number, patch: Partial<ClientCert>) =>
    set({ client_certs: cfg.client_certs.map((c, j) => (j === i ? { ...c, ...patch } : c)) });
  const save = () =>
    action.run(async () => {
      const r = await api.put<NetConfig>("/network", { ...cfg, tls_passthrough: cfg.tls_passthrough.filter(Boolean) });
      saved.setData(r);
      setDraft(null);
      setNotice("Saved. The proxy, Replay and agents use these settings from now on.");
    });

  return (
    <div className="content">
      <Panel
        title="Upstream proxies"
        actions={
          <button
            className="btn"
            data-testid="add-upstream-rule"
            onClick={() => {
              // A new rule goes before the catch-all (a rule without a match, which must stay last).
              const last = cfg.upstream_rules[cfg.upstream_rules.length - 1];
              const rule = { ...NEW_RULE };
              set({ upstream_rules: last && last.match.length === 0 ? [...cfg.upstream_rules.slice(0, -1), rule, last] : [...cfg.upstream_rules, rule] });
            }}
          >
            Add rule
          </button>
        }
      >
        <p className="small muted" style={{ marginTop: 0 }}>
          Where outgoing connections go, per target host: directly, through an HTTP proxy (CONNECT for HTTPS) or through a
          SOCKS5 proxy. The first rule whose match fits the host wins; a host that fits no rule is reached directly. Matches
          are host names (<code>api.example.com</code>; <code>*.example.com</code> also covers <code>example.com</code>;{" "}
          <code>*</code> and <code>?</code> work inside names) and CIDR ranges such as <code>10.0.0.0/8</code> (for targets
          given as an IP address). A rule with no match covers every host, so it goes last. This applies to the proxy,
          SOCKS5 and transparent listeners, Replay, the scanner, the Fuzzer and agents. Unless "proxy resolves" is on,
          ProxyMind resolves each name, checks the address against the denied networks and asks the proxy for that address.
        </p>
        {cfg.upstream_rules.length === 0 && <p className="muted small" style={{ margin: 0 }}>No rules: connecting directly to targets.</p>}
        {cfg.upstream_rules.length > 0 && <RuleTable rules={cfg.upstream_rules} set={(upstream_rules) => set({ upstream_rules })} />}
        <ResolveTool rules={cfg.upstream_rules} />
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
      <Panel
        title="Hostname resolution"
        actions={
          <button className="btn" data-testid="add-host" onClick={() => set({ hosts: [...cfg.hosts, { host: "", address: "" }] })}>
            Add override
          </button>
        }
      >
        <p className="small muted" style={{ marginTop: 0 }}>
          Connect to a fixed address instead of what DNS says, like a hosts file (<code>*.example.com</code> works).
          TLS still uses the name. Applies to the proxy, Replay, Fuzzer, scans and agents; with an HTTP upstream
          proxy, plain-HTTP requests are resolved by that proxy.
        </p>
        {cfg.hosts.length > 0 && (
          <table className="grid">
            <thead>
              <tr><th>Host</th><th>Address</th><th /></tr>
            </thead>
            <tbody>
              {cfg.hosts.map((h, i) => (
                <tr key={i}>
                  <td><input aria-label={`Override ${i + 1} host`} placeholder="api.staging.example" value={h.host} onChange={(e) => setHost(i, { host: e.target.value })} /></td>
                  <td><input className="mono" aria-label={`Override ${i + 1} address`} placeholder="10.0.0.5" value={h.address} onChange={(e) => setHost(i, { address: e.target.value })} /></td>
                  <td>
                    <button className="btn" aria-label={`Delete override ${i + 1}`} onClick={() => set({ hosts: cfg.hosts.filter((_, j) => j !== i) })}>✕</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
      <Panel title="TLS pass-through">
        <p className="small muted" style={{ marginTop: 0 }}>
          The proxy tunnels HTTPS to these hosts without decrypting it: for apps that pin certificates, or noisy hosts
          you don't want in history. Nothing inside these tunnels is recorded. One per line; <code>*.example.com</code>{" "}
          also matches <code>example.com</code>.
        </p>
        <textarea
          aria-label="TLS pass-through hosts"
          rows={4}
          placeholder={"*.googleapis.com\nupdates.example.com"}
          value={cfg.tls_passthrough.join("\n")}
          onChange={(e) => set({ tls_passthrough: e.target.value.split(/\n/).map((x) => x.trim()) })}
          onBlur={() => set({ tls_passthrough: cfg.tls_passthrough.filter(Boolean) })}
        />
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
