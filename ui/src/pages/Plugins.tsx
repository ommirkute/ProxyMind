import { useEffect, useState } from "react";
import { api } from "../api";
import { Chip, Empty, ErrorBox, ExchangeLink, Panel, unwrapUntrusted, useAction, useLoad, useNav } from "../components";

interface PluginInfo {
  name: string;
  version: string;
  description: string;
  kinds: string[];
  enabled: boolean;
  dir: string;
  max_requests?: number;
  panels: [string, string][];
  signature: { state: "unsigned" } | { state: "signed"; signer: string; key: string; trusted: boolean };
}
interface PanelData { title: string; text: string; columns: string[]; rows: string[][] }
interface Sandbox { network_isolated: boolean; limits: boolean; summary: string }
interface PluginsView { plugins: PluginInfo[]; sandbox: Sandbox; registry?: string }
interface Probe { raw: string; note: string }
interface Issue { check: string; title: string; severity: string; evidence: string; exchange_id: number }
type CheckResult =
  | { status: "done"; issues: Issue[]; exchange_ids: number[]; notes: string[] }
  | { status: "pending_approval"; approval_id: string; summary: string; reasons: string[]; requests: Probe[] }
  | { status: "denied"; reasons: string[] };

/** Installed plugins (per user), the sandbox, and active checks on one recorded request. */
export default function Plugins() {
  const { data, error, reload } = useLoad(() => api.get<PluginsView>("/plugins"), []);
  const toggle = useAction();
  const set = (name: string, enabled: boolean) =>
    toggle.run(async () => {
      await api.put(`/plugins/${encodeURIComponent(name)}`, { enabled });
      reload();
    });
  return (
    <div className="content">
      <Panel title="Plugins">
        <ErrorBox error={error ?? toggle.error} />
        {data && (
          <>
            <div className={data.sandbox.network_isolated ? "notice" : "error"} data-testid="plugin-sandbox">
              Sandbox: {data.sandbox.summary}.
            </div>
            {data.plugins.length === 0 ? (
              <Empty>
                No plugins installed. Plugins are installed per user, never per project:{" "}
                <code>proxymind plugin add examples/plugins/debug-switch</code>.
              </Empty>
            ) : (
              <table className="grid" data-testid="plugin-table">
                <thead>
                  <tr><th>Plugin</th><th>Kind</th><th>Description</th><th>State</th></tr>
                </thead>
                <tbody>
                  {data.plugins.map((p) => (
                    <tr key={p.name}>
                      <td><strong>{p.name}</strong> <span className="small muted">{p.version}</span><div className="small muted mono">{p.dir}</div></td>
                      <td>
                        {p.kinds.map((k) => <Chip key={k} value={k} />)}{" "}
                        {p.signature.state === "signed" ? (
                          <span title={`key ${p.signature.key}`}><Chip value={p.signature.trusted ? `signed by ${p.signature.signer} (trusted)` : `signed by ${p.signature.signer}`} /></span>
                        ) : (
                          <span className="small muted">unsigned</span>
                        )}
                      </td>
                      <td className="small">{p.description}</td>
                      <td>
                        <button className="btn" disabled={toggle.busy} onClick={() => set(p.name, !p.enabled)} data-testid={`plugin-toggle-${p.name}`}>
                          {p.enabled ? "On · turn off" : "Off · turn on"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <p className="small muted">
              Passive plugins run with the passive scan (Scanner issues). Active plugins propose requests for one recorded
              request; ProxyMind sends them through the policy gate and the plugin judges the answers. Plugins run as you:
              install only code you trust.{data.registry ? ` Registry: ${data.registry}` : ""}
            </p>
          </>
        )}
      </Panel>
      {data && <Panels plugins={data.plugins.filter((p) => p.enabled && p.panels.length > 0)} />}
      {data && <ActiveCheck plugins={data.plugins.filter((p) => p.enabled && p.kinds.includes("active"))} />}
    </div>
  );
}

function ActiveCheck({ plugins }: { plugins: PluginInfo[] }) {
  const { arg } = useNav();
  const [plugin, setPlugin] = useState(plugins[0]?.name ?? "");
  const [exchange, setExchange] = useState(arg ? String(arg) : "");
  const [identity, setIdentity] = useState("");
  const [r, setR] = useState<CheckResult | null>(null);
  const action = useAction();
  useEffect(() => {
    if (!plugins.some((p) => p.name === plugin)) setPlugin(plugins[0]?.name ?? "");
  }, [plugins, plugin]);
  useEffect(() => {
    if (arg) setExchange(String(arg));
  }, [arg]);
  const run = (approval_id?: string) =>
    action.run(async () =>
      setR(await api.post<CheckResult>("/plugins/check", {
        plugin,
        exchange_id: Number(exchange),
        identity: identity || undefined,
        approval_id,
      })),
    );
  if (plugins.length === 0) {
    return <Panel title="Active check"><Empty>No active plugin is on.</Empty></Panel>;
  }
  return (
    <Panel title="Active check">
      <div className="row small">
        <select aria-label="Plugin" value={plugin} onChange={(e) => setPlugin(e.target.value)}>
          {plugins.map((p) => <option key={p.name} value={p.name}>{p.name}</option>)}
        </select>
        <span>on exchange</span>
        <input aria-label="Plugin exchange" value={exchange} onChange={(e) => setExchange(e.target.value)} style={{ width: 80 }} />
        <input aria-label="Plugin identity" placeholder="identity (optional)" value={identity} onChange={(e) => setIdentity(e.target.value)} style={{ width: 160 }} />
        <button className="btn primary" disabled={!plugin || !exchange || action.busy} onClick={() => run()} data-testid="plugin-run">
          {action.busy ? "Running…" : "Run check"}
        </button>
      </div>
      <ErrorBox error={action.error} />
      {r?.status === "denied" && <div className="error">Denied: {r.reasons.join("; ")}</div>}
      {r?.status === "pending_approval" && (
        <div className="notice">
          <div>Needs approval ({r.approval_id}): {r.summary}</div>
          <ol className="small mono">{r.requests.map((p, i) => <li key={i}>{p.raw.split(/\r?\n/)[0]} <span className="muted">— {p.note}</span></li>)}</ol>
          <button className="btn" onClick={() => run(r.approval_id)} disabled={action.busy}>Run the approved requests</button>
        </div>
      )}
      {r?.status === "done" && (
        <div data-testid="plugin-result">
          <p className="small muted">
            Sent {r.exchange_ids.length} request(s){r.exchange_ids.length ? ": " : "."}
            {r.exchange_ids.slice(0, 10).map((id) => <span key={id}><ExchangeLink id={id} /> </span>)}
          </p>
          {r.issues.length === 0 ? (
            <Empty>The plugin reported nothing.</Empty>
          ) : (
            <table className="grid">
              <thead><tr><th>Severity</th><th>Issue</th><th>Evidence</th><th>Exchange</th></tr></thead>
              <tbody>
                {r.issues.map((i, n) => (
                  <tr key={n}>
                    <td><Chip value={i.severity} /></td>
                    <td><strong>{i.title}</strong><div className="small muted">{i.check}</div></td>
                    <td className="small">{unwrapUntrusted(i.evidence)}</td>
                    <td><ExchangeLink id={i.exchange_id} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {r.notes.length > 0 && <ul className="small muted">{r.notes.map((n) => <li key={n}>{n}</li>)}</ul>}
          <p className="small muted">Plugin issues are leads: confirm one with a proof before it becomes a finding.</p>
        </div>
      )}
    </Panel>
  );
}

/** Views plugins add: their output shown as text and a table (never as markup). */
function Panels({ plugins }: { plugins: PluginInfo[] }) {
  const { go } = useNav();
  const [shown, setShown] = useState<{ key: string; data: PanelData } | null>(null);
  const action = useAction();
  if (plugins.length === 0) return null;
  const open = (plugin: string, id: string) =>
    action.run(async () => {
      const data = await api.get<PanelData>(`/plugins/${encodeURIComponent(plugin)}/panels/${encodeURIComponent(id)}`);
      setShown({ key: `${plugin}/${id}`, data });
    });
  const idCol = shown?.data.columns.findIndex((c) => c.toLowerCase() === "exchange_id") ?? -1;
  return (
    <Panel title="Plugin panels">
      <div className="row small">
        {plugins.flatMap((p) =>
          p.panels.map(([id, title]) => (
            <button key={`${p.name}/${id}`} className={`btn ${shown?.key === `${p.name}/${id}` ? "primary" : ""}`} disabled={action.busy} onClick={() => open(p.name, id)} data-testid={`panel-${p.name}-${id}`}>
              {title} <span className="muted">· {p.name}</span>
            </button>
          )),
        )}
      </div>
      <ErrorBox error={action.error} />
      {shown && (
        <div data-testid="plugin-panel">
          <h3>{shown.data.title}</h3>
          {shown.data.text && <pre className="raw small">{unwrapUntrusted(shown.data.text)}</pre>}
          {shown.data.rows.length > 0 && (
            <table className="grid">
              {shown.data.columns.length > 0 && <thead><tr>{shown.data.columns.map((c, i) => <th key={i}>{c}</th>)}</tr></thead>}
              <tbody>
                {shown.data.rows.map((r, i) => (
                  <tr key={i}>
                    {r.map((c, j) => (
                      <td key={j} className="small">
                        {j === idCol && /^\d+$/.test(c) ? <a href="#" onClick={(e) => { e.preventDefault(); go("history", Number(c)); }}>#{c}</a> : c}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="small muted">From the plugin: shown as plain text.</p>
        </div>
      )}
    </Panel>
  );
}
