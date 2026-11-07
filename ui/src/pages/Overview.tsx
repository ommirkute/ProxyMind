import { api, qs, type Approval, type ExchangePage, type Finding } from "../api";
import { Chip, ExchangeLink, Panel, StatusCode, useLoad, useNav } from "../components";
import { Icon } from "../icons";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

interface ScanTask {
  task_id: string;
  url: string;
  status: string;
  targets_total: number;
  targets_done: number;
  issues?: unknown[];
  created_ms: number;
}

const ago = (ms: number) => {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
};

/** The workspace at a glance: traffic, findings by severity, what needs a decision. */
export default function Overview() {
  const { counters, go } = useNav();
  const findings = useLoad(() => api.get<Finding[]>("/findings"), [counters?.findings, counters?.audit_records]);
  const approvals = useLoad(() => api.get<Approval[]>(`/approvals${qs({ status: "pending" })}`), [counters?.pending_approvals]);
  const recent = useLoad(() => api.get<ExchangePage>(`/exchanges${qs({ limit: 8 })}`), [counters?.last_exchange_id]);
  const tasks = useLoad(() => api.get<ScanTask[]>("/scan/tasks"), [counters?.findings]);

  const list = findings.data ?? [];
  const live = list.filter((f) => f.status !== "false_positive");
  const bySev = Object.fromEntries(SEVERITIES.map((s) => [s, live.filter((f) => f.severity === s).length]));
  const proven = live.filter((f) => ["proven", "confirmed", "reported"].includes(f.status)).length;
  const total = live.length || 1;
  const link = (page: Parameters<typeof go>[0], arg?: number | string) => (e: React.MouseEvent) => {
    e.preventDefault();
    go(page, arg);
  };

  return (
    <div className="content">
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <p>Everything this workspace has seen, found and is waiting on.</p>
        </div>
        <div className="actions">
          <a className="btn" href="#/history" onClick={link("history")}>
            <Icon name="list" size={15} /> Open traffic
          </a>
          <a className="btn primary" href="#/issues" onClick={link("issues")}>
            <Icon name="scan" size={15} /> New scan
          </a>
        </div>
      </div>

      <div className="stats">
        <a className="stat" href="#/history" onClick={link("history")}>
          <span className="stat-label"><span className="stat-icon"><Icon name="activity" size={15} /></span>Requests recorded</span>
          <span className="stat-value">{(counters?.exchanges ?? 0).toLocaleString()}</span>
          <span className="stat-foot">{counters?.intercepted ? `${counters.intercepted} held at intercept` : "Proxy, scanner and tools"}</span>
        </a>
        <a className="stat" href="#/findings" onClick={link("findings")}>
          <span className="stat-label"><span className="stat-icon bad"><Icon name="bug" size={15} /></span>Open issues</span>
          <span className="stat-value">{live.length}</span>
          <span className="stat-foot">{bySev.critical + bySev.high} critical or high</span>
        </a>
        <a className="stat" href="#/findings" onClick={link("findings")}>
          <span className="stat-label"><span className="stat-icon ok"><Icon name="shield" size={15} /></span>Proven</span>
          <span className="stat-value">{proven}</span>
          <span className="stat-foot">{live.length ? `${Math.round((100 * proven) / live.length)}% backed by a proof` : "No proof run yet"}</span>
        </a>
        <a className="stat" href="#/approvals" onClick={link("approvals")}>
          <span className="stat-label"><span className="stat-icon warn"><Icon name="clock" size={15} /></span>Awaiting approval</span>
          <span className="stat-value">{counters?.pending_approvals ?? 0}</span>
          <span className="stat-foot">{(counters?.audit_records ?? 0).toLocaleString()} audited actions</span>
        </a>
      </div>

      <div className="overview-grid">
        <div>
          <Panel title="Issues by severity">
            <div className="sev-bar" aria-hidden="true">
              {SEVERITIES.map((s) => (
                <span key={s} className={`sev-${s}`} style={{ width: `${(100 * bySev[s]) / total}%` }} />
              ))}
            </div>
            <div className="sev-legend">
              {SEVERITIES.map((s) => (
                <span key={s}>
                  <span className={`dot sev-${s}`} />
                  {s[0].toUpperCase() + s.slice(1)}
                  <b>{bySev[s]}</b>
                </span>
              ))}
            </div>
            <h3>Latest</h3>
            {list.length === 0 ? (
              <div className="empty">No issues yet. Scan a request or run a crawl and audit to find some.</div>
            ) : (
              [...list]
                .sort((a, b) => b.created_ms - a.created_ms)
                .slice(0, 6)
                .map((f) => (
                  <a key={f.id} className="list-row link" href={`#/findings/${f.id}`} onClick={link("findings", f.id)}>
                    <Chip value={f.severity} />
                    <span className="title" title={f.title}>{f.title}</span>
                    <Chip value={f.status} />
                    <span className="sub">{ago(f.created_ms)}</span>
                  </a>
                ))
            )}
          </Panel>
          <Panel title="Recent traffic" actions={<a href="#/history" onClick={link("history")} className="small">View all</a>}>
            {(recent.data?.exchanges ?? []).length === 0 ? (
              <div className="empty">Nothing recorded yet. Point a browser at the proxy to start.</div>
            ) : (
              <table className="grid">
                <thead>
                  <tr><th>#</th><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Source</th></tr>
                </thead>
                <tbody>
                  {recent.data?.exchanges.map((x) => (
                    <tr key={x.id}>
                      <td><ExchangeLink id={x.id} /></td>
                      <td className="mono">{x.method}</td>
                      <td className="muted">{x.host}</td>
                      <td className="mono" style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{x.path}</td>
                      <td><StatusCode status={x.status} error={x.error} /></td>
                      <td><span className="chip plain">{x.source}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        </div>
        <div>
          <Panel title="Start testing">
            <div className="quick">
              <a href="#/issues" onClick={link("issues")}><Icon name="scan" size={18} /><span>Crawl &amp; audit<small>Scan a whole site</small></span></a>
              <a href="#/replay" onClick={link("replay")}><Icon name="replay" size={18} /><span>Replay<small>Edit and resend</small></span></a>
              <a href="#/fuzzer" onClick={link("fuzzer")}><Icon name="fuzzer" size={18} /><span>Fuzzer<small>Fuzz parameters</small></span></a>
              <a href="#/authz" onClick={link("authz")}><Icon name="authz" size={18} /><span>Access control<small>Compare identities</small></span></a>
            </div>
          </Panel>
          <Panel title="Needs your decision" actions={<a href="#/approvals" onClick={link("approvals")} className="small">Open queue</a>}>
            {(approvals.data ?? []).length === 0 ? (
              <div className="row small muted"><Icon name="check" size={15} /> Nothing waiting. Risky actions by agents and scans land here.</div>
            ) : (
              approvals.data?.slice(0, 5).map((a) => (
                <a key={a.id} className="list-row link" href="#/approvals" onClick={link("approvals")}>
                  <Chip value={a.tier} />
                  <span className="title" title={a.summary}>{a.summary}</span>
                  <span className="sub">{a.actor}</span>
                </a>
              ))
            )}
          </Panel>
          <Panel title="Scans">
            {(tasks.data ?? []).length === 0 ? (
              <div className="small muted">No crawl-and-audit runs in this session.</div>
            ) : (
              tasks.data?.slice(0, 5).map((t) => (
                <div key={t.task_id} className="list-row">
                  <Icon name="scan" size={15} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="title" title={t.url}>{t.url}</div>
                    <div className="bar" style={{ marginTop: 6 }}>
                      <div style={{ width: `${t.targets_total ? (100 * t.targets_done) / t.targets_total : t.status === "done" ? 100 : 5}%` }} />
                    </div>
                  </div>
                  <Chip value={t.status} />
                </div>
              ))
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
