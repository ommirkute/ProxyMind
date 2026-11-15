import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { useLiveEvent } from "../live";
import { Chip, Empty, ErrorBox, ExchangeLink, Panel, useAction, useLoad, useNav } from "../components";

interface Issue {
  check: string;
  title: string;
  severity: "info" | "low" | "medium" | "high";
  origin: string;
  path: string;
  evidence: string;
  count: number;
  exchange_ids: number[];
}

/** Passive issues in recorded traffic: leads to test, not findings. */
export default function Issues() {
  const { counters, go, arg } = useNav();
  const [min, setMin] = useState("info");
  const [host, setHost] = useState("");
  const issues = useLoad(
    () => api.get<Issue[]>(`/scan/issues?min_severity=${min}${host ? `&host=${encodeURIComponent(host)}` : ""}`),
    [min, host, counters?.exchanges],
  );
  const action = useAction();
  const toFinding = (i: Issue) =>
    action.run(async () => {
      const f = await api.post<{ id: number }>("/findings", {
        title: i.title,
        vuln_class: i.check,
        severity: i.severity === "info" ? "info" : i.severity,
        description: `Passive check ${i.check} on ${i.origin}${i.path === "*" ? "" : i.path} (${i.count} responses).\n\nEvidence: ${i.evidence}`,
        evidence: i.exchange_ids,
      });
      go("findings", f.id);
    });

  return (
    <div className="content">
      <CrawlAudit />
      <ActiveScan key={String(arg ?? "")} initial={arg === undefined ? undefined : String(arg)} />
      <Panel
        title="Issues (passive)"
        actions={
          <>
            <input aria-label="Host filter" placeholder="host…" value={host} onChange={(e) => setHost(e.target.value)} />
            <select aria-label="Minimum severity" value={min} onChange={(e) => setMin(e.target.value)}>
              {["info", "low", "medium", "high"].map((s) => <option key={s}>{s}</option>)}
            </select>
          </>
        }
      >
        <p className="small muted">Checks run over recorded traffic and send nothing. They are leads to test: a finding is proven only by a proof.</p>
        <ErrorBox error={issues.error ?? action.error} />
        {issues.data && issues.data.length === 0 && <Empty>No issues in recorded traffic.</Empty>}
        {issues.data && issues.data.length > 0 && (
          <table className="grid" data-testid="issues">
            <thead><tr><th>Severity</th><th>Issue</th><th>Where</th><th>Seen</th><th>Evidence</th><th></th></tr></thead>
            <tbody>
              {issues.data.map((i) => (
                <tr key={`${i.check}${i.origin}${i.path}${i.evidence}`}>
                  <td><Chip value={i.severity} /></td>
                  <td>{i.title}</td>
                  <td className="mono small" style={{ overflowWrap: "anywhere", minWidth: 160 }}>{i.origin}{i.path === "*" ? " (site-wide)" : i.path}</td>
                  <td className="small">{i.count}× {i.exchange_ids.slice(0, 3).map((e) => <span key={e}><ExchangeLink id={e} /> </span>)}</td>
                  <td className="small" style={{ maxWidth: 360, wordBreak: "break-word" }}>{i.evidence}</td>
                  <td><button className="btn" disabled={action.busy} onClick={() => toFinding(i)}>Make finding</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

interface ActiveFinding {
  check: string;
  title: string;
  severity: string;
  point: string;
  payload: string;
  evidence: string;
  prove_with?: string;
  exchange_id: number;
}
type ActiveResult =
  | { status: "done"; baseline_exchange_id: number; requests: number; issues: ActiveFinding[]; insertion_points: { kind: string; name: string }[] }
  | { status: "pending_approval"; approval_id: string; summary: string; reasons: string[] }
  | { status: "denied"; reasons: string[] };

/** Active checks on one recorded request. */
function ActiveScan({ initial }: { initial?: string }) {
  const { go } = useNav();
  const [ex, setEx] = useState(initial ?? "");
  const [result, setResult] = useState<ActiveResult | null>(null);
  const action = useAction();
  const run = () =>
    action.run(async () => {
      setResult(await api.post<ActiveResult>("/scan/active", { exchange_id: Number(ex) }));
    });
  return (
    <Panel title="Active scan">
      <div className="row">
        <span className="small">Probe every parameter of exchange</span>
        <input aria-label="Exchange to scan" value={ex} onChange={(e) => setEx(e.target.value)} style={{ width: 80 }} />
        <button className="btn primary" disabled={!ex || action.busy} onClick={run} data-testid="active-scan">{action.busy ? "Scanning…" : "Scan"}</button>
        <span className="small muted">SQL errors, unencoded reflection, open redirect, path traversal, template injection. Sends requests; goes through the policy gate.</span>
      </div>
      <ErrorBox error={action.error} />
      {result?.status === "pending_approval" && (
        <div className="notice">Needs approval: {result.summary}. <a href="#" onClick={(e) => { e.preventDefault(); go("approvals"); }}>Approvals</a></div>
      )}
      {result?.status === "denied" && <div className="error">Denied: {result.reasons.join("; ")}</div>}
      {result?.status === "done" && (
        <>
          <div className="small" data-testid="active-summary">
            {result.insertion_points.length} insertion points · {result.requests} probes · {result.issues.length} leads
          </div>
          {result.issues.length > 0 && (
            <table className="grid small">
              <thead><tr><th>Severity</th><th>Lead</th><th>Where</th><th>Evidence</th><th>Prove with</th></tr></thead>
              <tbody>
                {result.issues.map((i) => (
                  <tr key={i.exchange_id}>
                    <td><Chip value={i.severity} /></td>
                    <td>{i.title}</td>
                    <td className="mono" style={{ overflowWrap: "anywhere", minWidth: 160 }}>{i.point} = {i.payload}</td>
                    <td style={{ maxWidth: 320, wordBreak: "break-word" }}>{i.evidence} <ExchangeLink id={i.exchange_id} /></td>
                    <td className="muted">{i.prove_with ?? "–"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </Panel>
  );
}

interface ScanTask {
  task_id: string;
  url: string;
  created_ms: number;
  status: "crawling" | "auditing" | "done" | "cancelled" | "failed";
  pages_crawled: number;
  targets_total: number;
  targets_done: number;
  requests: number;
  relogins?: number;
  current?: string;
  issues: (ActiveFinding & { operation: string; finding_id?: number })[];
  notes: string[];
  error?: string;
}

const QUICK = ["reflected_input", "sql_error", "open_redirect", "path_traversal", "ssti"];
const running = (t?: ScanTask | null) => t?.status === "crawling" || t?.status === "auditing";

/** Crawl a site, then run the active scanner over what was found, in the background. */
function CrawlAudit() {
  const { go } = useNav();
  const [url, setUrl] = useState("");
  const [pages, setPages] = useState("30");
  const [quick, setQuick] = useState(false);
  const [js, setJs] = useState(true);
  const [id, setId] = useState<string | null>(null);
  const [task, setTask] = useState<ScanTask | null>(null);
  const tasks = useLoad(() => api.get<ScanTask[]>("/scan/tasks"), [id, task?.status]);
  const action = useAction();

  // The task's progress arrives as `scans` events (ADR-0018): each one for this task, and every resync, refetches
  // it. Only the newest response is shown, so a slow reply cannot overwrite a newer one.
  const shown = useRef<{ id: string | null; req: number; failed: boolean }>({ id: null, req: 0, failed: false });
  const refresh = (taskId: string) => {
    const s = shown.current;
    const req = ++s.req;
    api
      .get<ScanTask>(`/scan/tasks/${taskId}`)
      .then((t) => {
        if (s.id !== taskId || s.req !== req) return;
        if (s.failed) action.setError(null);
        s.failed = false;
        setTask(t);
      })
      .catch((e: Error) => {
        if (s.id !== taskId || s.req !== req) return;
        s.failed = true;
        action.setError(e.message);
      });
  };
  useEffect(() => {
    shown.current = { id, req: 0, failed: false };
    if (id) refresh(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);
  useLiveEvent(["scans"], (e) => {
    if (id && (e.topic === "resync" || e.data.task === id)) refresh(id);
  });

  const start = () =>
    action.run(async () => {
      const t = await api.post<ScanTask>("/scan/tasks", {
        url,
        max_pages: Number(pages) || 30,
        checks: quick ? QUICK : [],
        browser: js,
      });
      setTask(t);
      setId(t.task_id);
    });
  const cancel = () => action.run(async () => setTask(await api.post<ScanTask>(`/scan/tasks/${id}/cancel`, {})));
  const pct = task && task.targets_total > 0 ? Math.round((100 * task.targets_done) / task.targets_total) : 0;

  return (
    <Panel
      title="Crawl and audit"
      actions={
        tasks.data && tasks.data.length > 0 ? (
          <select aria-label="Scan task" value={id ?? ""} onChange={(e) => setId(e.target.value || null)}>
            <option value="">Recent tasks…</option>
            {tasks.data.map((t) => (
              <option key={t.task_id} value={t.task_id}>{t.url} · {t.status}</option>
            ))}
          </select>
        ) : undefined
      }
    >
      <div className="row">
        <input aria-label="Start URL" placeholder="https://app.example/" value={url} onChange={(e) => setUrl(e.target.value)} style={{ minWidth: 260 }} />
        <label className="small">pages <input aria-label="Pages to crawl" value={pages} onChange={(e) => setPages(e.target.value)} style={{ width: 50 }} /></label>
        <label className="small"><input type="checkbox" checked={quick} onChange={(e) => setQuick(e.target.checked)} /> quick checks only</label>
        <label className="small" title="Crawl in a headless browser that runs the app's JavaScript (needs Chromium)"><input type="checkbox" checked={js} onChange={(e) => setJs(e.target.checked)} /> run JavaScript</label>
        <button className="btn primary" disabled={!url || action.busy || running(task)} onClick={start} data-testid="audit-start">Crawl and audit</button>
        {running(task) && <button className="btn" onClick={cancel}>Cancel</button>}
      </div>
      <p className="small muted">Crawls the start URL, then scans each recorded operation of that origin (submissions only get the stored XSS and CSRF checks). Runs in the background; every request goes through the policy gate, and strong issues become suspected findings.</p>
      <ErrorBox error={action.error} />
      {task && (
        <>
          <div className="small" data-testid="audit-progress">
            <b>{task.status}</b> · {task.pages_crawled} pages crawled · {task.targets_done}/{task.targets_total} operations · {task.requests} requests · {task.issues.length} issues{task.relogins ? ` · ${task.relogins} re-login(s)` : ""}
            {task.current && <span className="muted mono"> · {task.current}</span>}
          </div>
          {task.targets_total > 0 && (
            <div style={{ background: "var(--border, #ddd)", height: 6, borderRadius: 3, margin: "6px 0" }}>
              <div style={{ width: `${pct}%`, background: "var(--accent, #36c)", height: 6, borderRadius: 3 }} />
            </div>
          )}
          {task.error && <div className="error">{task.error}</div>}
          {task.notes.length > 0 && <ul className="small muted">{task.notes.map((n) => <li key={n}>{n}</li>)}</ul>}
          {task.issues.length > 0 && (
            <table className="grid small" data-testid="audit-issues">
              <thead><tr><th>Severity</th><th>Issue</th><th>Operation</th><th>Where</th><th>Evidence</th><th></th></tr></thead>
              <tbody>
                {task.issues.map((i) => (
                  <tr key={`${i.operation}${i.check}${i.point}`}>
                    <td><Chip value={i.severity} /></td>
                    <td>{i.title}</td>
                    <td className="mono">{i.operation}</td>
                    <td className="mono" style={{ overflowWrap: "anywhere", minWidth: 160 }}>{i.point} = {i.payload}</td>
                    <td style={{ maxWidth: 320, wordBreak: "break-word" }}>{i.evidence} <ExchangeLink id={i.exchange_id} /></td>
                    <td>
                      {i.finding_id !== undefined && (
                        <a href="#" onClick={(e) => { e.preventDefault(); go("findings", i.finding_id); }}>finding #{i.finding_id}</a>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </Panel>
  );
}
