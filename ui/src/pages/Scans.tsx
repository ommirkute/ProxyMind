import { useEffect, useState } from "react";
import { api, fmtDateTime, toast } from "../api";
import { Chip, Empty, ErrorBox, Panel, useAction, useLoad, useNav } from "../components";

export interface ScanProfile {
  name: string;
  description: string;
  checks: string[];
  approval_checks: boolean;
  crawl: boolean | null;
  max_pages: number | null;
  browser: boolean | null;
  max_targets: number | null;
  max_requests: number | null;
  builtin: boolean;
}

interface TaskRow {
  task_id: string;
  url: string;
  actor: string;
  created_ms: number;
  profile?: string;
  schedule_id?: number;
  status: "crawling" | "auditing" | "paused" | "done" | "cancelled" | "failed";
  pages_crawled: number;
  targets_total: number;
  targets_done: number;
  requests: number;
  relogins?: number;
  current?: string;
  notes: string[];
  error?: string;
}

type Every = { kind: "hourly" } | { kind: "daily"; at: string } | { kind: "weekly"; day: string; at: string };

interface Schedule {
  id: number;
  name: string;
  every: Every;
  request: { url: string; profile?: string | null; identity?: string | null };
  enabled: boolean;
  created_by: string;
  next_run_ms: number;
  last_run_ms: number | null;
  last_task: string | null;
  last_error: string | null;
}

const running = (t: TaskRow) => t.status === "crawling" || t.status === "auditing";
const DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

function describe(e: Every): string {
  if (e.kind === "hourly") return "every hour";
  if (e.kind === "daily") return `daily at ${e.at} UTC`;
  return `every ${e.day} at ${e.at} UTC`;
}

function Tasks({ profiles, bump }: { profiles: ScanProfile[]; bump: number }) {
  const { go } = useNav();
  const tasks = useLoad(() => api.get<TaskRow[]>("/scan/tasks"), [bump]);
  const action = useAction();
  const [url, setUrl] = useState("");
  const [profile, setProfile] = useState("default");

  const act = (id: string, verb: "pause" | "resume" | "cancel") =>
    action.run(async () => {
      await api.post(`/scan/tasks/${id}/${verb}`, {});
      tasks.reload();
      setTimeout(tasks.reload, 1500);
    });
  const start = () =>
    action.run(async () => {
      await api.post("/scan/tasks", { url, profile });
      toast("Scan started");
      tasks.reload();
    });
  const anyRunning = !!tasks.data?.some(running);
  useEffect(() => {
    if (!anyRunning) return;
    const t = setTimeout(tasks.reload, 2000);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tasks.data]);

  return (
    <Panel title="Scan tasks" actions={<button className="btn" onClick={tasks.reload}>Refresh</button>}>
      <div className="row">
        <input aria-label="Scan URL" placeholder="https://app.example/" value={url} onChange={(e) => setUrl(e.target.value)} style={{ minWidth: 260 }} />
        <select aria-label="Scan profile" value={profile} onChange={(e) => setProfile(e.target.value)}>
          {profiles.map((p) => <option key={p.name} value={p.name}>{p.name}</option>)}
        </select>
        <button className="btn primary" disabled={!url || action.busy} onClick={start} data-testid="scan-start">Start scan</button>
      </div>
      <p className="small muted">
        Tasks are saved in the project after each operation. A paused task, or one that was running when ProxyMind
        stopped, resumes where it left off.
      </p>
      <ErrorBox error={tasks.error ?? action.error} />
      {tasks.data?.length === 0 && <Empty>No scans yet.</Empty>}
      {!!tasks.data?.length && (
        <table className="grid" data-testid="scan-tasks">
          <thead>
            <tr><th>Started</th><th>Target</th><th>Profile</th><th>Status</th><th>Progress</th><th></th></tr>
          </thead>
          <tbody>
            {tasks.data.map((t) => (
              <tr key={t.task_id}>
                <td className="small">{fmtDateTime(t.created_ms)}{t.schedule_id ? <div className="muted">schedule #{t.schedule_id}</div> : null}</td>
                <td className="mono small">{t.url}</td>
                <td>{t.profile ?? "–"}</td>
                <td>
                  <Chip value={t.status} />
                  {t.error && <div className="small error">{t.error}</div>}
                  {t.notes.filter((n) => n.startsWith("interrupted") || n.startsWith("resumed")).map((n) => <div key={n} className="small muted">{n}</div>)}
                </td>
                <td className="small">
                  {t.targets_done}/{t.targets_total} operations · {t.requests} requests
                  {t.relogins ? ` · ${t.relogins} re-login(s)` : ""}
                  {t.current && <div className="muted mono">{t.current}</div>}
                </td>
                <td style={{ whiteSpace: "nowrap" }}>
                  {running(t) && <button className="btn" onClick={() => act(t.task_id, "pause")}>Pause</button>}{" "}
                  {(t.status === "paused" || t.status === "cancelled" || t.status === "failed") && (
                    <button className="btn primary" onClick={() => act(t.task_id, "resume")} data-testid={`resume-${t.task_id}`}>Resume</button>
                  )}{" "}
                  {(running(t) || t.status === "paused") && <button className="btn" onClick={() => act(t.task_id, "cancel")}>Cancel</button>}{" "}
                  <button className="btn" onClick={() => go("issues")}>Issues</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}

const EMPTY_PROFILE = { name: "", description: "", checks: "", max_pages: "", max_targets: "", max_requests: "", crawl: true };

function Profiles({ profiles, reload }: { profiles: ScanProfile[]; reload: () => void }) {
  const [form, setForm] = useState(EMPTY_PROFILE);
  const action = useAction();
  const num = (v: string) => (v.trim() ? Number(v) : null);
  const save = () =>
    action.run(async () => {
      await api.post("/scan/profiles", {
        name: form.name,
        description: form.description,
        checks: form.checks.split(",").map((c) => c.trim()).filter(Boolean),
        crawl: form.crawl,
        max_pages: num(form.max_pages),
        max_targets: num(form.max_targets),
        max_requests: num(form.max_requests),
      });
      setForm(EMPTY_PROFILE);
      reload();
      toast("Profile saved");
    });
  const remove = (name: string) =>
    action.run(async () => {
      await api.del(`/scan/profiles/${encodeURIComponent(name)}`);
      reload();
    });
  const edit = (p: ScanProfile) =>
    setForm({
      name: p.builtin ? `${p.name}-copy` : p.name,
      description: p.description,
      checks: p.checks.join(", "),
      max_pages: p.max_pages?.toString() ?? "",
      max_targets: p.max_targets?.toString() ?? "",
      max_requests: p.max_requests?.toString() ?? "",
      crawl: p.crawl ?? true,
    });

  return (
    <Panel title="Profiles">
      <ErrorBox error={action.error} />
      <table className="grid" data-testid="scan-profiles">
        <thead><tr><th>Name</th><th>What it runs</th><th>Limits</th><th></th></tr></thead>
        <tbody>
          {profiles.map((p) => (
            <tr key={p.name}>
              <td><strong>{p.name}</strong>{p.builtin && <div className="small muted">built-in</div>}</td>
              <td className="small">
                {p.description}
                <div className="muted">{p.checks.length ? p.checks.join(", ") : p.approval_checks ? "all checks, including those that need approval" : "all checks that don't need approval"}</div>
              </td>
              <td className="small muted">
                {p.crawl === false ? "no crawl" : `${p.max_pages ?? 30} pages`} · {p.max_targets ?? 30} operations · {p.max_requests ?? 150} req/op
              </td>
              <td style={{ whiteSpace: "nowrap" }}>
                <button className="btn" onClick={() => edit(p)}>{p.builtin ? "Copy" : "Edit"}</button>{" "}
                {!p.builtin && <button className="btn" onClick={() => remove(p.name)}>Delete</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <h3 style={{ margin: "16px 0 6px" }}>Save a profile</h3>
      <div className="row">
        <input aria-label="Profile name" placeholder="name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} style={{ width: 130 }} />
        <input aria-label="Profile description" placeholder="description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} style={{ minWidth: 220 }} />
      </div>
      <div className="row" style={{ marginTop: 6 }}>
        <input aria-label="Profile checks" placeholder="checks, comma-separated (empty: all safe checks)" value={form.checks} onChange={(e) => setForm({ ...form, checks: e.target.value })} style={{ minWidth: 340 }} />
      </div>
      <div className="row" style={{ marginTop: 6 }}>
        <label className="small"><input type="checkbox" checked={form.crawl} onChange={(e) => setForm({ ...form, crawl: e.target.checked })} /> crawl first</label>
        <label className="small">pages <input aria-label="Profile pages" value={form.max_pages} onChange={(e) => setForm({ ...form, max_pages: e.target.value })} style={{ width: 50 }} /></label>
        <label className="small">operations <input aria-label="Profile operations" value={form.max_targets} onChange={(e) => setForm({ ...form, max_targets: e.target.value })} style={{ width: 50 }} /></label>
        <label className="small">requests/op <input aria-label="Profile requests" value={form.max_requests} onChange={(e) => setForm({ ...form, max_requests: e.target.value })} style={{ width: 60 }} /></label>
        <button className="btn primary" disabled={!form.name.trim() || action.busy} onClick={save}>Save profile</button>
      </div>
    </Panel>
  );
}

function Schedules({ profiles, onStarted }: { profiles: ScanProfile[]; onStarted: () => void }) {
  const list = useLoad(() => api.get<Schedule[]>("/scan/schedules"), []);
  const action = useAction();
  const [form, setForm] = useState({ name: "", url: "", profile: "default", kind: "daily", at: "02:00", day: "mon" });

  const save = (s: Partial<Schedule>) =>
    action.run(async () => {
      await api.post("/scan/schedules", s);
      list.reload();
    });
  const add = () => {
    const every: Every =
      form.kind === "hourly" ? { kind: "hourly" } : form.kind === "daily" ? { kind: "daily", at: form.at } : { kind: "weekly", day: form.day, at: form.at };
    save({ name: form.name, every, request: { url: form.url, profile: form.profile }, enabled: true });
    setForm({ ...form, name: "" });
  };
  const runNow = (id: number) =>
    action.run(async () => {
      await api.post(`/scan/schedules/${id}/run`, {});
      toast("Scan started");
      list.reload();
      onStarted();
    });
  const remove = (id: number) =>
    action.run(async () => {
      await api.del(`/scan/schedules/${id}`);
      list.reload();
    });

  return (
    <Panel title="Schedules">
      <p className="small muted" style={{ marginTop: 0 }}>
        Scheduled scans run as the person who saved them, through the same rules as a scan started by hand, while
        ProxyMind's UI server or desktop app is running. Times are UTC.
      </p>
      <ErrorBox error={list.error ?? action.error} />
      {list.data?.length === 0 && <Empty>No schedules yet.</Empty>}
      {!!list.data?.length && (
        <table className="grid" data-testid="scan-schedules">
          <thead><tr><th>Name</th><th>When</th><th>What</th><th>Next run</th><th>Last run</th><th></th></tr></thead>
          <tbody>
            {list.data.map((s) => (
              <tr key={s.id}>
                <td><strong>{s.name}</strong> <Chip value={s.enabled ? "on" : "off"} /></td>
                <td className="small">{describe(s.every)}</td>
                <td className="small mono">{s.request.url}<div className="muted">{s.request.profile ?? "default"}</div></td>
                <td className="small">{s.enabled ? fmtDateTime(s.next_run_ms) : "–"}</td>
                <td className="small">
                  {s.last_run_ms ? fmtDateTime(s.last_run_ms) : "never"}
                  {s.last_error && <div className="error">{s.last_error}</div>}
                </td>
                <td style={{ whiteSpace: "nowrap" }}>
                  <button className="btn" onClick={() => runNow(s.id)}>Run now</button>{" "}
                  <button className="btn" onClick={() => save({ ...s, enabled: !s.enabled })}>{s.enabled ? "Turn off" : "Turn on"}</button>{" "}
                  <button className="btn" onClick={() => remove(s.id)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="row" style={{ marginTop: 12 }}>
        <input aria-label="Schedule name" placeholder="name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} style={{ width: 130 }} />
        <input aria-label="Schedule URL" placeholder="https://app.example/" value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} style={{ minWidth: 220 }} />
        <select aria-label="Schedule profile" value={form.profile} onChange={(e) => setForm({ ...form, profile: e.target.value })}>
          {profiles.map((p) => <option key={p.name} value={p.name}>{p.name}</option>)}
        </select>
        <select aria-label="Schedule frequency" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
          <option value="hourly">hourly</option>
          <option value="daily">daily</option>
          <option value="weekly">weekly</option>
        </select>
        {form.kind === "weekly" && (
          <select aria-label="Schedule day" value={form.day} onChange={(e) => setForm({ ...form, day: e.target.value })}>
            {DAYS.map((d) => <option key={d} value={d}>{d}</option>)}
          </select>
        )}
        {form.kind !== "hourly" && (
          <input aria-label="Schedule time" type="time" value={form.at} onChange={(e) => setForm({ ...form, at: e.target.value })} />
        )}
        <button className="btn primary" disabled={!form.name.trim() || !form.url || action.busy} onClick={add} data-testid="schedule-add">Add schedule</button>
      </div>
    </Panel>
  );
}

export default function Scans() {
  const profiles = useLoad(() => api.get<ScanProfile[]>("/scan/profiles"), []);
  const list = profiles.data ?? [];
  const [bump, setBump] = useState(0);
  return (
    <div className="content">
      <ErrorBox error={profiles.error} />
      <Tasks profiles={list} bump={bump} />
      <Schedules profiles={list} onStarted={() => setBump((b) => b + 1)} />
      <Profiles profiles={list} reload={profiles.reload} />
    </div>
  );
}
