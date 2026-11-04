import { useCallback, useEffect, useRef, useState } from "react";
import { api, originOf, type ExchangeDetail, type IdentityInfo, type ReplayResult } from "../api";
import { Chip, ErrorBox, ExchangeLink, MessageView, StatusCode, useAction, useLoad, useNav } from "../components";
import {
  cookies,
  decodeComponent,
  formParams,
  jsonParams,
  parseRequest,
  queryParams,
  redirectOf,
  setCookie,
  setFormParam,
  setHeader,
  setJsonParam,
  setQueryParam,
} from "../http";

interface RaceGroup {
  status?: number;
  body_length: number;
  count: number;
  exchange_ids: number[];
  error?: string;
}

type RaceResult =
  | { status: "done"; mode: "single_packet" | "last_byte"; count: number; groups: RaceGroup[]; successes: number; fastest_ms: number; slowest_ms: number; exchange_ids: number[] }
  | { status: "pending_approval"; approval_id: string; summary: string; reasons: string[] }
  | { status: "denied"; reasons: string[] };

/** One send in a tab's history. */
interface Step {
  url: string;
  raw: string;
  exchange_id?: number;
  status?: number | null;
  elapsed_ms?: number;
  error?: string;
  notes?: string[];
}

/** A Replay tab, saved in the project (`/api/v1/ui/replay`). */
interface RTab {
  id: string;
  name: string;
  url: string;
  raw: string;
  identity: string;
  fixCl: boolean;
  autoFollow: boolean;
  history: Step[];
  /** Which step the editor shows; -1 or past the end means "editing". */
  pos: number;
}

interface Saved {
  tabs: RTab[];
  active: string;
}

/** What only lives while the page is open: approvals, outcomes, race results. */
interface Transient {
  approval?: string;
  outcome?: ReplayResult;
  race?: RaceResult;
  raceApproval?: string;
}

const newId = () => Math.random().toString(36).slice(2, 10);
const blank = (n: number): RTab => ({
  id: newId(),
  name: String(n),
  url: "",
  raw: "GET / HTTP/1.1\nHost: example.com\n\n",
  identity: "",
  fixCl: true,
  autoFollow: false,
  history: [],
  pos: -1,
});

export default function Replay() {
  const { arg, go } = useNav();
  const [state, setState] = useState<Saved | null>(null);
  const [tmp, setTmp] = useState<Record<string, Transient>>({});
  const [details, setDetails] = useState<Record<number, ExchangeDetail>>({});
  const [inspector, setInspector] = useState(true);
  const [curlOpen, setCurlOpen] = useState(false);
  const [curlText, setCurlText] = useState("");
  const [curlWarnings, setCurlWarnings] = useState<string[]>([]);
  const [raceCount, setRaceCount] = useState(10);
  const [raceMode, setRaceMode] = useState<"auto" | "single_packet" | "last_byte">("auto");
  const ids = useLoad(() => api.get<IdentityInfo[]>("/identities"), []);
  const action = useAction();
  const loaded = useRef(false);

  // Load saved tabs once.
  useEffect(() => {
    api
      .get<Saved | null>("/ui/replay")
      // Tabs saved before the rename live under the old key.
      .then((s) => (s?.tabs?.length ? s : api.get<Saved | null>("/ui/repeater").catch(() => null)))
      .then((s) => {
        const tabs = s?.tabs?.length ? s.tabs : [blank(1)];
        setState({ tabs, active: tabs.some((t) => t.id === s?.active) ? s!.active : tabs[0].id });
        loaded.current = true;
      })
      .catch(() => {
        const t = blank(1);
        setState({ tabs: [t], active: t.id });
        loaded.current = true;
      });
  }, []);

  // Save (debounced) whenever tabs change.
  useEffect(() => {
    if (!state || !loaded.current) return;
    const t = setTimeout(() => api.put("/ui/replay", state).catch(() => {}), 600);
    return () => clearTimeout(t);
  }, [state]);

  const addTab = useCallback((t: Partial<RTab>) => {
    setState((s) => {
      if (!s) return s;
      const n = s.tabs.reduce((m, x) => Math.max(m, Number(x.name) || 0), 0) + 1;
      const tab = { ...blank(n), ...t, id: newId() };
      return { tabs: [...s.tabs, tab], active: tab.id };
    });
  }, []);

  // A request sent here from History (#/replay/<id>) or another page opens in a new tab.
  useEffect(() => {
    if (!state) return;
    if (arg) {
      window.history.replaceState(null, "", "#/replay");
      api
        .get<ExchangeDetail>(`/exchanges/${arg}`)
        .then((ex) => addTab({ name: `#${arg}`, url: originOf(ex.summary), raw: ex.request.replace(/\r\n/g, "\n") }))
        .catch((e) => action.setError(e.message));
      return;
    }
    try {
      const draft = sessionStorage.getItem("pm_replay_draft");
      if (draft) {
        sessionStorage.removeItem("pm_replay_draft");
        const d = JSON.parse(draft) as { url: string; raw: string; name?: string };
        addTab({ name: d.name ?? "draft", url: d.url, raw: d.raw.replace(/\r\n/g, "\n") });
      }
    } catch {
      /* storage blocked or bad draft */
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [arg, state === null]);

  const tab = state?.tabs.find((t) => t.id === state.active);
  const t = (tab && tmp[tab.id]) || {};
  const step = tab && tab.pos >= 0 && tab.pos < tab.history.length ? tab.history[tab.pos] : undefined;

  // Load the response shown for the current step.
  useEffect(() => {
    const id = step?.exchange_id;
    if (id == null || details[id]) return;
    api.get<ExchangeDetail>(`/exchanges/${id}`).then((d) => setDetails((m) => ({ ...m, [id]: d }))).catch(() => {});
  }, [step?.exchange_id, details]);

  if (!state || !tab) return <div className="content muted">Loading…</div>;

  const update = (patch: Partial<RTab>) =>
    setState((s) => (s ? { ...s, tabs: s.tabs.map((x) => (x.id === tab.id ? { ...x, ...patch } : x)) } : s));
  const setT = (patch: Partial<Transient>) => setTmp((m) => ({ ...m, [tab.id]: { ...m[tab.id], ...patch } }));
  const editRaw = (raw: string) => {
    update({ raw, pos: -1 });
    setT({ approval: undefined, raceApproval: undefined });
  };

  const sendOnce = async (url: string, raw: string, approval?: string): Promise<{ r: ReplayResult; d?: ExchangeDetail }> => {
    const r = await api.post<ReplayResult>("/replay", {
      url,
      raw,
      identity: tab.identity || undefined,
      fix_content_length: tab.fixCl,
      approval_id: approval,
    });
    if (r.status === "sent" || r.status === "failed") {
      const d = await api.get<ExchangeDetail>(`/exchanges/${r.exchange_id}`);
      setDetails((m) => ({ ...m, [r.exchange_id]: d }));
      return { r, d };
    }
    return { r };
  };

  const record = (url: string, raw: string, r: ReplayResult, d?: ExchangeDetail): Step | undefined =>
    r.status === "sent"
      ? { url, raw, exchange_id: r.exchange_id, status: d?.summary.status, elapsed_ms: r.elapsed_ms, notes: r.notes }
      : r.status === "failed"
        ? { url, raw, exchange_id: r.exchange_id, error: r.error }
        : undefined;

  const send = (url = tab.url, raw = tab.raw) =>
    action.run(async () => {
      let { r, d } = await sendOnce(url, raw, t.approval);
      setT({ outcome: r, approval: r.status === "pending_approval" ? r.approval_id : undefined, race: undefined });
      const steps: Step[] = [];
      const first = record(url, raw, r, d);
      if (first) steps.push(first);
      // Same-origin redirects, when asked, up to 5 hops.
      for (let hop = 0; tab.autoFollow && d && hop < 5; hop++) {
        const next = followTarget(url, raw, d.response);
        if (!next || new URL(next.url).origin !== new URL(url).origin) break;
        ({ r, d } = await sendOnce(next.url, next.raw));
        const s = record(next.url, next.raw, r, d);
        if (!s) break;
        steps.push(s);
        url = next.url;
        raw = next.raw;
      }
      if (steps.length) {
        const kept = tab.pos >= 0 ? tab.history.slice(0, tab.pos + 1) : tab.history;
        const history = [...kept, ...steps].slice(-100);
        const last = steps[steps.length - 1];
        update({ history, pos: history.length - 1, url: last.url, raw: last.raw });
      }
    });

  const follow = () => {
    const d = step?.exchange_id != null ? details[step.exchange_id] : undefined;
    const next = step && d ? followTarget(step.url, step.raw, d.response) : null;
    if (next) send(next.url, next.raw);
  };

  const runRace = () =>
    action.run(async () => {
      const r = await api.post<RaceResult>("/race", {
        url: tab.url,
        raw: tab.raw,
        count: raceCount,
        mode: raceMode,
        identity: tab.identity || undefined,
        fix_content_length: tab.fixCl,
        approval_id: t.raceApproval || undefined,
      });
      setT({ race: r, raceApproval: r.status === "pending_approval" ? r.approval_id : undefined, outcome: undefined });
    });

  const pasteCurl = () =>
    action.run(async () => {
      const r = await api.post<{ url: string; raw: string; warnings: string[] }>("/tools/curl", { command: curlText });
      update({ url: r.url, raw: r.raw.replace(/\r\n/g, "\n"), pos: -1 });
      setCurlWarnings(r.warnings);
      setCurlOpen(false);
    });

  const move = (by: number) => {
    const pos = Math.max(0, Math.min(tab.history.length - 1, (tab.pos < 0 ? tab.history.length : tab.pos) + by));
    const s = tab.history[pos];
    if (s) update({ pos, url: s.url, raw: s.raw });
  };

  const closeTab = (id: string) =>
    setState((s) => {
      if (!s) return s;
      const tabs = s.tabs.filter((x) => x.id !== id);
      if (!tabs.length) tabs.push(blank(1));
      return { tabs, active: s.active === id ? tabs[Math.max(0, s.tabs.findIndex((x) => x.id === id) - 1)].id : s.active };
    });

  const detail = step?.exchange_id != null ? details[step.exchange_id] : undefined;
  const redirect = redirectOf(detail?.response);
  const onKey = (e: React.KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === "Enter" || e.key === " ")) {
      e.preventDefault();
      if (!action.busy && tab.url) send();
    }
  };

  return (
    <div className="content replay">
      <div className="rtabs" role="tablist" aria-label="Replay tabs">
        {state.tabs.map((x) => (
          <div key={x.id} role="tab" aria-selected={x.id === tab.id} className={`rtab ${x.id === tab.id ? "active" : ""}`}
            onClick={() => setState({ ...state, active: x.id })}
            onDoubleClick={() => {
              const name = window.prompt("Tab name", x.name);
              if (name) setState({ ...state, tabs: state.tabs.map((y) => (y.id === x.id ? { ...y, name } : y)) });
            }}
            title="Double-click to rename"
          >
            <span>{x.name}</span>
            <button className="rtab-x" aria-label={`Close tab ${x.name}`} onClick={(e) => { e.stopPropagation(); closeTab(x.id); }}>×</button>
          </div>
        ))}
        <button className="rtab add" aria-label="New tab" onClick={() => addTab({})}>+</button>
        <button className="rtab add" title="Duplicate this tab" onClick={() => addTab({ name: `${tab.name} copy`, url: tab.url, raw: tab.raw, identity: tab.identity })}>⧉</button>
      </div>

      <div className="row replay-bar">
        <button className="btn primary" onClick={() => send()} disabled={action.busy || !tab.url} data-testid="send" title="Ctrl+Enter">
          {action.busy ? "Sending…" : t.approval ? "Send approved" : "Send"}
        </button>
        <button className="btn" onClick={() => move(-1)} disabled={!tab.history.length || tab.pos === 0} aria-label="Previous request" title="Previous in this tab">‹</button>
        <button className="btn" onClick={() => move(1)} disabled={tab.pos < 0 || tab.pos >= tab.history.length - 1} aria-label="Next request" title="Next in this tab">›</button>
        <span className="small muted">{tab.history.length ? `${tab.pos < 0 ? "edited" : tab.pos + 1} / ${tab.history.length}` : ""}</span>
        <input aria-label="Target" className="grow mono" placeholder="https://host:port" value={tab.url} onChange={(e) => update({ url: e.target.value })} />
        <select aria-label="Send as" value={tab.identity} onChange={(e) => update({ identity: e.target.value })}>
          <option value="">as written</option>
          <option value="anonymous">anonymous</option>
          {ids.data?.map((i) => (
            <option key={i.name} value={i.name}>as {i.name}</option>
          ))}
        </select>
        <label className="small row" style={{ gap: 4 }}>
          <input type="checkbox" checked={tab.fixCl} onChange={(e) => update({ fixCl: e.target.checked })} /> fix Content-Length
        </label>
        <label className="small row" style={{ gap: 4 }} title="Follow same-origin redirects automatically (up to 5)">
          <input type="checkbox" checked={tab.autoFollow} onChange={(e) => update({ autoFollow: e.target.checked })} /> follow redirects
        </label>
        <select
          aria-label="Change request"
          data-testid="request-transform"
          value=""
          onChange={(e) => {
            const v = e.target.value;
            if (!v) return;
            const body = v === "method" ? { op: "change_method", raw: tab.raw } : { op: "convert_body", raw: tab.raw, to: v };
            action.run(async () => editRaw((await api.post<{ raw: string }>("/tools/request-transform", body)).raw));
          }}
        >
          <option value="">Request…</option>
          <option value="method">Change method (GET ⇄ POST)</option>
          <option value="url_encoded">Body as URL-encoded form</option>
          <option value="multipart">Body as multipart form</option>
          <option value="json">Body as JSON</option>
        </select>
        <button className="btn" onClick={() => setCurlOpen((o) => !o)} data-testid="paste-curl">Paste cURL…</button>
        <button className="btn" onClick={() => setInspector((i) => !i)} aria-pressed={inspector}>Inspector</button>
      </div>
      {curlOpen && (
        <div style={{ marginBottom: 8 }}>
          <textarea aria-label="cURL command" className="mono" rows={4} style={{ width: "100%" }} placeholder="curl 'https://…' -H '…'" value={curlText} onChange={(e) => setCurlText(e.target.value)} />
          <button className="btn primary" disabled={!curlText.trim() || action.busy} onClick={pasteCurl} data-testid="parse-curl">Load into this tab</button>
          <span className="small muted"> Nothing is sent until you press Send.</span>
        </div>
      )}
      {curlWarnings.length > 0 && <div className="notice small">Ignored: {curlWarnings.join("; ")}</div>}
      <ErrorBox error={action.error} />

      <div className={`replay-grid ${inspector ? "" : "no-inspector"}`}>
        <section className="pane">
          <h3 className="pane-title">Request</h3>
          <textarea aria-label="Raw request" className="editor" value={tab.raw} onChange={(e) => editRaw(e.target.value)} onKeyDown={onKey} spellCheck={false} />
          <div className="row small race-bar">
            <strong>Race</strong>
            <label>
              send <input aria-label="Race count" type="number" min={2} max={50} value={raceCount} onChange={(e) => { setRaceCount(Number(e.target.value)); setT({ raceApproval: undefined }); }} style={{ width: 60 }} /> copies at once
            </label>
            <select aria-label="Race mode" value={raceMode} onChange={(e) => { setRaceMode(e.target.value as typeof raceMode); setT({ raceApproval: undefined }); }}>
              <option value="auto">auto (HTTP/2 single packet if possible)</option>
              <option value="single_packet">HTTP/2 single packet</option>
              <option value="last_byte">last-byte sync</option>
            </select>
            <button className="btn" data-testid="race" onClick={runRace} disabled={action.busy || !tab.url}>
              {t.raceApproval ? "Race approved" : "Race"}
            </button>
          </div>
        </section>

        <section className="pane">
          <h3 className="pane-title">Response</h3>
          {t.race && <RaceView race={t.race} goApprovals={() => go("approvals")} />}
          {!t.race && t.outcome?.status === "denied" && <div className="error">Denied by the rules of engagement: {t.outcome.reasons.join("; ")}</div>}
          {!t.race && t.outcome?.status === "pending_approval" && (
            <div className="notice">
              Needs approval ({t.outcome.reasons.join("; ")}). Approve <strong>{t.outcome.approval_id}</strong> on the{" "}
              <a href="#" onClick={(e) => { e.preventDefault(); go("approvals"); }}>Approvals</a> page, then press Send again.
            </div>
          )}
          {!t.race && step && (
            <>
              <div className="row small" style={{ marginBottom: 6 }} data-testid="replay-result">
                {step.error ? <span className="bad">Failed: {step.error}</span> : <StatusCode status={step.status ?? null} />}
                {step.elapsed_ms != null && <span className="muted">{step.elapsed_ms} ms</span>}
                {detail?.summary.resp_len != null && <span className="muted">{detail.summary.resp_len} bytes</span>}
                {step.exchange_id != null && <span className="muted">recorded as <ExchangeLink id={step.exchange_id} /></span>}
                {step.notes?.map((n) => <Chip key={n} value={n} />)}
                {redirect && <button className="btn" onClick={follow} disabled={action.busy} data-testid="follow-redirect">Follow redirect → {redirect}</button>}
              </div>
              <MessageView
                text={detail?.response ?? (step.error ? null : undefined) ?? null}
                decodedBody={detail?.view.response?.body?.text}
                loadB64={step.exchange_id != null ? () => api.get<ExchangeDetail>(`/exchanges/${step.exchange_id}?bytes=1`).then((d) => d.response_b64) : undefined}
                empty={step.error ? "No response" : "Loading…"}
                testid="replay-response"
              />
            </>
          )}
          {!t.race && !step && !t.outcome && <p className="muted">Nothing sent from this tab yet. Ctrl+Enter sends.</p>}
        </section>

        {inspector && <Inspector raw={tab.raw} onChange={editRaw} />}
      </div>
    </div>
  );
}

/** The request to send next when a response redirects, or null. */
function followTarget(url: string, raw: string, response: string | null | undefined): { url: string; raw: string } | null {
  const loc = redirectOf(response);
  if (!loc) return null;
  const p = parseRequest(raw);
  let next: URL;
  try {
    const base = new URL(p.target.startsWith("http") ? p.target : url.replace(/\/$/, "") + p.target);
    next = new URL(loc, base);
  } catch {
    return null;
  }
  // Like a browser: GET, same headers minus the body ones.
  const keep = p.headers.filter((h) => !["content-length", "content-type", "transfer-encoding", "host"].includes(h.name.toLowerCase()));
  const lines = [`GET ${next.pathname}${next.search} ${p.version}`, `Host: ${next.host}`, ...keep.map((h) => `${h.name}: ${h.value}`)];
  return { url: next.origin, raw: lines.join("\n") + "\n\n" };
}

/** Parameters, cookies and headers of the request, editable in place. */
function Inspector({ raw, onChange }: { raw: string; onChange: (raw: string) => void }) {
  const p = parseRequest(raw);
  const q = queryParams(p);
  const form = formParams(p);
  const json = jsonParams(p);
  const cs = cookies(p);
  const Field = ({ value, label, set }: { value: string; label: string; set: (v: string) => void }) => (
    <input aria-label={label} className="mono" defaultValue={value} key={value} onBlur={(e) => e.target.value !== value && set(e.target.value)}
      onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()} />
  );
  const section = (title: string, rows: { name: string; value: string; set: (v: string) => void; decoded?: string }[]) =>
    rows.length > 0 && (
      <details open key={title}>
        <summary>{title} ({rows.length})</summary>
        <table className="grid inspector-table">
          <tbody>
            {rows.map((r, i) => (
              <tr key={`${r.name}-${i}`}>
                <td className="mono" title={r.name}>{r.name}</td>
                <td>
                  <Field value={r.value} label={`${title} ${r.name}`} set={r.set} />
                  {r.decoded && r.decoded !== r.value && <div className="small muted mono" title="decoded">{r.decoded}</div>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    );
  return (
    <section className="pane inspector" aria-label="Inspector">
      <h3 className="pane-title">Inspector</h3>
      <div className="small mono" style={{ marginBottom: 6 }}>{p.method} {p.target.split("?")[0]}</div>
      {section("Query parameters", q.map((x, i) => ({ ...x, decoded: decodeComponent(x.value), set: (v: string) => onChange(setQueryParam(raw, i, v)) })))}
      {section("Body parameters", form.map((x, i) => ({ ...x, decoded: decodeComponent(x.value), set: (v: string) => onChange(setFormParam(raw, i, v)) })))}
      {section("JSON fields", json.map((x) => ({ ...x, set: (v: string) => onChange(setJsonParam(raw, x.name, v)) })))}
      {section("Cookies", cs.map((x) => ({ ...x, set: (v: string) => onChange(setCookie(raw, x.name, v)) })))}
      {section("Headers", p.headers.map((x, i) => ({ ...x, set: (v: string) => onChange(setHeader(raw, i, v)) })))}
    </section>
  );
}

function RaceView({ race, goApprovals }: { race: RaceResult; goApprovals: () => void }) {
  if (race.status === "denied") return <div className="error">Denied by the rules of engagement: {race.reasons.join("; ")}</div>;
  if (race.status === "pending_approval") {
    return (
      <div className="notice">
        {race.summary} needs approval ({race.reasons.join("; ")}). Approve <strong>{race.approval_id}</strong> on the{" "}
        <a href="#" onClick={(e) => { e.preventDefault(); goApprovals(); }}>Approvals</a> page, then press Race again.
      </div>
    );
  }
  return (
    <div data-testid="race-result">
      <div className="row small" style={{ marginBottom: 8 }}>
        <strong>{race.count} requests</strong>
        <Chip value={race.mode === "single_packet" ? "HTTP/2 single packet" : "last-byte sync"} />
        <span className="muted">responses in {race.fastest_ms}–{race.slowest_ms} ms</span>
        <span className={race.successes > 1 ? "bad" : "muted"}>{race.successes} succeeded (2xx)</span>
      </div>
      {race.successes > 1 && (
        <div className="notice">More than one request succeeded. If this action should only work once, that's a race condition: open the exchanges to compare.</div>
      )}
      <table className="grid">
        <thead>
          <tr><th>Status</th><th>Body</th><th>Count</th><th>Exchanges</th></tr>
        </thead>
        <tbody>
          {race.groups.map((g, i) => (
            <tr key={i}>
              <td>{g.error ? <span className="bad">error</span> : <StatusCode status={g.status ?? null} />}</td>
              <td className="small">{g.error ?? `${g.body_length} bytes`}</td>
              <td>{g.count}</td>
              <td className="small">{g.exchange_ids.slice(0, 8).map((id) => <span key={id} style={{ marginRight: 6 }}><ExchangeLink id={id} /></span>)}{g.exchange_ids.length > 8 ? "…" : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
