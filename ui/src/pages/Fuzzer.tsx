import { useEffect, useMemo, useRef, useState } from "react";
import { api, originOf, toast, type ExchangeDetail, type IdentityInfo } from "../api";
import { ErrorBox, ExchangeLink, MessageView, StatusCode, useAction, useLoad, useNav, usePref } from "../components";
import { autoMark } from "../http";

interface Row {
  index?: number;
  exchange_id: number;
  payloads: (string | null)[];
  status?: number;
  body_length: number;
  elapsed_ms: number;
  matches?: string[];
  extracted?: (string | null)[];
  reflected: boolean;
  error?: string;
}
interface Anomaly {
  index: number;
  reasons: string[];
}
type AttackStatus = "running" | "paused" | "cancelled" | "done" | "failed";
interface AttackView {
  attack_id: string;
  summary: string;
  status: AttackStatus;
  total: number;
  done: number;
  extract_columns: string[];
  baseline?: Row;
  rows: Row[];
  anomalies: Anomaly[];
  error?: string;
  note?: string;
}
interface AttackSummary {
  attack_id: string;
  summary: string;
  status: AttackStatus;
  total: number;
  done: number;
  created_ms: number;
}
type Start =
  | { status: "started"; attack_id: string; total: number }
  | { status: "pending_approval"; approval_id: string; summary: string; reasons: string[] }
  | { status: "denied"; reasons: string[] };

const MODES = ["one_at_a_time", "same_everywhere", "paired", "all_combinations"] as const;
const MODE_LABEL: Record<(typeof MODES)[number], string> = {
  one_at_a_time: "One at a time",
  same_everywhere: "Same everywhere",
  paired: "Paired",
  all_combinations: "All combinations",
};
const MODE_HELP: Record<(typeof MODES)[number], string> = {
  one_at_a_time: "one position at a time, one payload set",
  same_everywhere: "the same payload in every position",
  paired: "set i in position i, advancing together",
  all_combinations: "every combination of the sets",
};
const TYPES = ["list", "numbers", "brute", "null", "case", "builtin", "recursive"] as const;
type SetType = (typeof TYPES)[number];
const TYPE_LABEL: Record<SetType, string> = {
  list: "Simple list",
  numbers: "Numbers",
  brute: "Brute forcer",
  null: "Null payloads",
  case: "Case variants",
  builtin: "Built-in list",
  recursive: "Recursive grep",
};
const BUILTINS = ["ids", "sqli", "xss", "traversal", "ssti", "methods_override"];
const RULES = ["prefix", "suffix", "replace", "url_encode", "url_encode_all", "base64", "hex", "lower", "upper", "reverse", "sha1", "sha256"] as const;
type RuleOp = (typeof RULES)[number];
interface RuleCfg {
  op: RuleOp;
  value?: string;
  find?: string;
  with?: string;
}
interface SetCfg {
  type: SetType;
  list: string;
  numbers: string;
  charset: string;
  min: number;
  max: number;
  nulls: number;
  words: string;
  builtin: string;
  recFirst: string;
  recRegex: string;
  recCount: number;
  rules: RuleCfg[];
  urlEncode: boolean;
}
interface ExtractCfg {
  start: string;
  end: string;
  regex: string;
}
interface Config {
  url: string;
  raw: string;
  mode: (typeof MODES)[number];
  identity: string;
  sets: SetCfg[];
  grep: string;
  grepRegex: boolean;
  extract: ExtractCfg[];
  concurrency: number;
  throttle: number;
}

const newSet = (): SetCfg => ({
  type: "list",
  list: "",
  numbers: "1-10",
  charset: "abcdefghijklmnopqrstuvwxyz0123456789",
  min: 1,
  max: 2,
  nulls: 10,
  words: "",
  builtin: "ids",
  recFirst: "",
  recRegex: "",
  recCount: 20,
  rules: [],
  urlEncode: false,
});

const INITIAL: Config = {
  url: "",
  raw: "GET /api/items/§1§ HTTP/1.1\nHost: example.com\n\n",
  mode: "one_at_a_time",
  identity: "",
  sets: [newSet()],
  grep: "",
  grepRegex: false,
  extract: [],
  concurrency: 1,
  throttle: 0,
};

/** The API's payload set for a configured set. */
function toPayloadSet(s: SetCfg) {
  const rules = s.rules.map((r) =>
    r.op === "prefix" || r.op === "suffix" ? { op: r.op, value: r.value ?? "" } : r.op === "replace" ? { op: r.op, find: r.find ?? "", with: r.with ?? "" } : { op: r.op },
  );
  const base = { processing: rules, url_encode: s.urlEncode };
  switch (s.type) {
    case "list":
      return { ...base, list: s.list.split("\n").map((l) => l.replace(/\r$/, "")).filter((l) => l.length > 0) };
    case "numbers":
      return { ...base, numbers: s.numbers };
    case "brute":
      return { ...base, brute: { charset: s.charset, min: s.min, max: s.max } };
    case "null":
      return { ...base, null_payloads: s.nulls };
    case "case":
      return { ...base, case_variants: s.words.split("\n").map((w) => w.trim()).filter(Boolean) };
    case "builtin":
      return { ...base, builtin: s.builtin };
    case "recursive":
      return { recursive: { first: s.recFirst, extract: { regex: s.recRegex }, count: s.recCount } };
  }
}

/** Payloads a set gives, when it can be told without the server. */
function setSize(s: SetCfg): number | null {
  switch (s.type) {
    case "list":
      return s.list.split("\n").filter((l) => l.length > 0).length;
    case "null":
      return s.nulls;
    case "recursive":
      return s.recCount;
    case "brute": {
      const n = new Set(s.charset).size;
      let t = 0;
      for (let l = s.min; l <= s.max; l++) t += n ** l;
      return t;
    }
    case "numbers": {
      const m = s.numbers.match(/^\s*(-?\d+)\s*-\s*(-?\d+)\s*(?::\s*(\d+))?\s*$/);
      return m ? Math.floor(Math.abs(Number(m[2]) - Number(m[1])) / Number(m[3] ?? 1)) + 1 : null;
    }
    default:
      return null;
  }
}

export default function Fuzzer() {
  const { arg, go } = useNav();
  const [cfg, setCfgRaw] = usePref<Config>("pm.fuzzer", INITIAL);
  const setCfg = (p: Partial<Config>) => setCfgRaw({ ...cfg, ...p });
  const [active, setActive] = useState(0);
  const [approval, setApproval] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Start | null>(null);
  const [attackId, setAttackId] = useState<string | null>(null);
  const [view, setView] = useState<AttackView | null>(null);
  const [sel, setSel] = useState<Row | null>(null);
  const ids = useLoad(() => api.get<IdentityInfo[]>("/identities"), []);
  const attacks = useLoad(() => api.get<AttackSummary[]>("/fuzzer/attacks"), [attackId, view?.status]);
  const action = useAction();
  const editor = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (!arg) return;
    api
      .get<ExchangeDetail>(`/exchanges/${arg}`)
      .then((ex) => setCfg({ url: originOf(ex.summary), raw: ex.request.replace(/\r\n/g, "\n") }))
      .catch((e) => action.setError(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [arg]);

  const positions = (cfg.raw.match(/§/g)?.length ?? 0) / 2;
  const setsNeeded = cfg.mode === "paired" || cfg.mode === "all_combinations" ? Math.max(1, Math.floor(positions)) : 1;
  const sets = Array.from({ length: setsNeeded }, (_, i) => cfg.sets[i] ?? newSet());
  const cur = sets[Math.min(active, sets.length - 1)];
  const updateSet = (patch: Partial<SetCfg>) =>
    setCfg({ sets: sets.map((s, i) => (i === Math.min(active, sets.length - 1) ? { ...s, ...patch } : s)) });

  const total = useMemo(() => {
    const sizes = sets.map(setSize);
    if (sizes.some((s) => s === null) || !Number.isInteger(positions)) return null;
    const n = sizes as number[];
    switch (cfg.mode) {
      case "one_at_a_time":
        return positions * n[0];
      case "same_everywhere":
        return n[0];
      case "paired":
        return Math.min(...n);
      case "all_combinations":
        return n.reduce((a, b) => a * b, 1);
    }
  }, [sets, positions, cfg.mode]);

  // Wrap the selected text in § markers.
  const mark = () => {
    const el = editor.current;
    if (!el || el.selectionStart === el.selectionEnd) return;
    const [a, b] = [el.selectionStart, el.selectionEnd];
    setCfg({ raw: cfg.raw.slice(0, a) + "§" + cfg.raw.slice(a, b) + "§" + cfg.raw.slice(b) });
  };

  const start = () =>
    action.run(async () => {
      const r = await api.post<Start>("/fuzzer/attacks", {
        url: cfg.url,
        raw: cfg.raw,
        mode: cfg.mode,
        payload_sets: sets.map(toPayloadSet),
        grep: cfg.grep.split(",").map((g) => g.trim()).filter(Boolean),
        grep_regex: cfg.grepRegex,
        extract: cfg.extract
          .filter((e) => e.regex || e.start)
          .map((e) => (e.regex ? { regex: e.regex } : { start: e.start, end: e.end || undefined })),
        concurrency: cfg.concurrency,
        throttle_ms: cfg.throttle,
        identity: cfg.identity || undefined,
        approval_id: approval || undefined,
      });
      setOutcome(r);
      setApproval(r.status === "pending_approval" ? r.approval_id : null);
      if (r.status === "started") {
        setView(null);
        setSel(null);
        setAttackId(r.attack_id);
      }
    });

  // Poll the attack: new rows are appended (the server sends only what's new).
  useEffect(() => {
    if (!attackId) return;
    let stop = false;
    let have = 0;
    const tick = async () => {
      try {
        const v = await api.get<AttackView>(`/fuzzer/attacks/${attackId}?from=${have}`);
        if (stop) return;
        have += v.rows.length;
        setView((old) => (old && old.attack_id === v.attack_id ? { ...v, rows: [...old.rows, ...v.rows] } : v));
        if (v.status === "running" || v.status === "paused") setTimeout(tick, 500);
      } catch (e) {
        if (!stop) action.setError((e as Error).message);
      }
    };
    tick();
    return () => {
      stop = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attackId]);

  const control = (what: "pause" | "resume" | "cancel") =>
    attackId &&
    action.run(async () => {
      const r = await api.post<{ status: AttackStatus }>(`/fuzzer/attacks/${attackId}/${what}`);
      setView((v) => (v ? { ...v, status: r.status } : v));
      if (what === "resume") setAttackId((id) => id); // polling continues on its own
    });

  return (
    <div className="content fuzzer">
      <div className="fuzzer-config">
        <section className="pane">
          <h3 className="pane-title">1 · Positions</h3>
          <div className="row">
            <input aria-label="Target" className="grow mono" placeholder="http://host:port" value={cfg.url} onChange={(e) => setCfg({ url: e.target.value })} />
            <select aria-label="Mode" value={cfg.mode} onChange={(e) => setCfg({ mode: e.target.value as Config["mode"] })} title={MODE_HELP[cfg.mode]}>
              {MODES.map((m) => <option key={m} value={m}>{MODE_LABEL[m]}</option>)}
            </select>
            <select aria-label="Send as" value={cfg.identity} onChange={(e) => setCfg({ identity: e.target.value })}>
              <option value="">as recorded</option>
              {ids.data?.map((i) => <option key={i.name} value={i.name}>{i.name}</option>)}
            </select>
          </div>
          <textarea ref={editor} aria-label="Request" className="mono editor-small" value={cfg.raw} onChange={(e) => setCfg({ raw: e.target.value })} spellCheck={false} />
          <div className="row small">
            <button className="btn" onClick={mark}>Add §</button>
            <button className="btn" onClick={() => setCfg({ raw: cfg.raw.replace(/§/g, "") })}>Clear §</button>
            <button className="btn" onClick={() => setCfg({ raw: autoMark(cfg.raw) })} title="Mark query, form and JSON values and cookies" data-testid="auto-mark">Auto-mark</button>
            <button
              className="btn"
              title="Insert a new Collaborator URL at the cursor"
              onClick={() =>
                api
                  .post<{ http_url?: string; dns_name?: string; email?: string; token: string }>("/collaborator/payloads", { note: "Fuzzer request" })
                  .then((p) => {
                    const v = p.http_url ?? p.dns_name ?? p.email ?? p.token;
                    const el = editor.current;
                    const [a, b] = el ? [el.selectionStart, el.selectionEnd] : [cfg.raw.length, cfg.raw.length];
                    setCfg({ raw: cfg.raw.slice(0, a) + v + cfg.raw.slice(b) });
                  })
                  .catch((e: Error) => toast(e.message, "bad"))
              }
            >
              Insert Collaborator URL
            </button>
            <span className="muted">{Number.isInteger(positions) ? `${positions} position(s) · ${MODE_HELP[cfg.mode]}` : "unbalanced § markers"}</span>
          </div>
        </section>

        <section className="pane">
          <h3 className="pane-title">2 · Payloads</h3>
          {sets.length > 1 && (
            <div className="row small" role="tablist">
              {sets.map((_, i) => (
                <button key={i} role="tab" className={`seg ${i === Math.min(active, sets.length - 1) ? "on" : ""}`} onClick={() => setActive(i)}>Set {i + 1}</button>
              ))}
            </div>
          )}
          <div className="row small" style={{ margin: "6px 0" }}>
            <select aria-label="Payload type" value={cur.type} onChange={(e) => updateSet({ type: e.target.value as SetType })}>
              {TYPES.map((t) => <option key={t} value={t}>{TYPE_LABEL[t]}</option>)}
            </select>
            <span className="muted">{setSize(cur) ?? "?"} payloads{total != null ? ` · ${total} requests` : ""}</span>
          </div>
          {cur.type === "list" && (
            <>
              <textarea aria-label="Payloads" className="mono" rows={7} placeholder="one payload per line" value={cur.list} onChange={(e) => updateSet({ list: e.target.value })} />
              <div className="row small">
                <label className="btn">
                  Load file…
                  <input type="file" hidden onChange={(e) => e.target.files?.[0]?.text().then((t) => updateSet({ list: t }))} />
                </label>
                <button className="btn" onClick={() => updateSet({ list: "" })}>Clear</button>
              </div>
            </>
          )}
          {cur.type === "numbers" && <input aria-label="Numbers" placeholder="from-to or from-to:step, e.g. 1000-1050" value={cur.numbers} onChange={(e) => updateSet({ numbers: e.target.value })} />}
          {cur.type === "brute" && (
            <div className="row small">
              <input aria-label="Character set" className="grow mono" value={cur.charset} onChange={(e) => updateSet({ charset: e.target.value })} />
              <label>min <input type="number" min={0} max={8} value={cur.min} onChange={(e) => updateSet({ min: Number(e.target.value) })} style={{ width: 55 }} /></label>
              <label>max <input type="number" min={0} max={8} value={cur.max} onChange={(e) => updateSet({ max: Number(e.target.value) })} style={{ width: 55 }} /></label>
            </div>
          )}
          {cur.type === "null" && <label className="small">send <input aria-label="Null payload count" type="number" min={1} value={cur.nulls} onChange={(e) => updateSet({ nulls: Number(e.target.value) })} style={{ width: 80 }} /> times, unchanged</label>}
          {cur.type === "case" && <textarea aria-label="Words" className="mono" rows={5} placeholder="one word per line: as written, lower, UPPER and Capitalised" value={cur.words} onChange={(e) => updateSet({ words: e.target.value })} />}
          {cur.type === "recursive" && (
            <div className="small" style={{ display: "grid", gap: 6 }}>
              <span className="muted">Each payload comes from the previous response (for example a token that changes on every request). Use one marked position; requests go one at a time.</span>
              <input aria-label="First payload" className="mono" placeholder="first payload" value={cur.recFirst} onChange={(e) => updateSet({ recFirst: e.target.value })} />
              <input aria-label="Next payload regex" className="mono" placeholder='regex for the next payload, e.g. "csrf":"([^"]+)"' value={cur.recRegex} onChange={(e) => updateSet({ recRegex: e.target.value })} />
              <label>up to <input aria-label="Recursive count" type="number" min={1} max={1000} value={cur.recCount} onChange={(e) => updateSet({ recCount: Number(e.target.value) })} style={{ width: 80 }} /> requests</label>
            </div>
          )}
          {cur.type === "builtin" && (
            <select aria-label="Built-in list" value={cur.builtin} onChange={(e) => updateSet({ builtin: e.target.value })}>
              {BUILTINS.map((b) => <option key={b}>{b}</option>)}
            </select>
          )}
          <details className="small" style={{ marginTop: 6 }} open={cur.rules.length > 0}>
            <summary>Processing ({cur.rules.length} rule{cur.rules.length === 1 ? "" : "s"})</summary>
            {cur.rules.map((r, i) => (
              <div key={i} className="row" style={{ marginTop: 4 }}>
                <select aria-label={`Rule ${i + 1}`} value={r.op} onChange={(e) => updateSet({ rules: cur.rules.map((x, j) => (j === i ? { op: e.target.value as RuleOp } : x)) })}>
                  {RULES.map((o) => <option key={o} value={o}>{o.replace(/_/g, " ")}</option>)}
                </select>
                {(r.op === "prefix" || r.op === "suffix") && (
                  <input aria-label={`Rule ${i + 1} value`} value={r.value ?? ""} onChange={(e) => updateSet({ rules: cur.rules.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)) })} />
                )}
                {r.op === "replace" && (
                  <>
                    <input aria-label={`Rule ${i + 1} find`} placeholder="find" value={r.find ?? ""} onChange={(e) => updateSet({ rules: cur.rules.map((x, j) => (j === i ? { ...x, find: e.target.value } : x)) })} />
                    <input aria-label={`Rule ${i + 1} replace with`} placeholder="with" value={r.with ?? ""} onChange={(e) => updateSet({ rules: cur.rules.map((x, j) => (j === i ? { ...x, with: e.target.value } : x)) })} />
                  </>
                )}
                <button className="btn" aria-label={`Remove rule ${i + 1}`} onClick={() => updateSet({ rules: cur.rules.filter((_, j) => j !== i) })}>×</button>
              </div>
            ))}
            <button className="btn" style={{ marginTop: 4 }} onClick={() => updateSet({ rules: [...cur.rules, { op: "prefix", value: "" }] })}>Add rule</button>
          </details>
          <label className="small"><input type="checkbox" checked={cur.urlEncode} onChange={(e) => updateSet({ urlEncode: e.target.checked })} /> URL-encode payloads</label>
        </section>

        <section className="pane">
          <h3 className="pane-title">3 · Options</h3>
          <label className="small">Grep: flag responses containing</label>
          <div className="row">
            <input aria-label="Grep" className="grow" placeholder="comma-separated, e.g. error, admin" value={cfg.grep} onChange={(e) => setCfg({ grep: e.target.value })} />
            <label className="small"><input type="checkbox" checked={cfg.grepRegex} onChange={(e) => setCfg({ grepRegex: e.target.checked })} /> regex</label>
          </div>
          <label className="small" style={{ marginTop: 8, display: "block" }}>Extract a value from each response into a column</label>
          {cfg.extract.map((x, i) => (
            <div key={i} className="row small" style={{ marginTop: 4 }}>
              <input aria-label={`Extract ${i + 1} start`} placeholder="after…" value={x.start} onChange={(e) => setCfg({ extract: cfg.extract.map((y, j) => (j === i ? { ...y, start: e.target.value } : y)) })} style={{ width: 110 }} />
              <input aria-label={`Extract ${i + 1} end`} placeholder="…before" value={x.end} onChange={(e) => setCfg({ extract: cfg.extract.map((y, j) => (j === i ? { ...y, end: e.target.value } : y)) })} style={{ width: 90 }} />
              <span className="muted">or</span>
              <input aria-label={`Extract ${i + 1} regex`} className="grow mono" placeholder="regex (group 1)" value={x.regex} onChange={(e) => setCfg({ extract: cfg.extract.map((y, j) => (j === i ? { ...y, regex: e.target.value } : y)) })} />
              <button className="btn" aria-label={`Remove extract ${i + 1}`} onClick={() => setCfg({ extract: cfg.extract.filter((_, j) => j !== i) })}>×</button>
            </div>
          ))}
          <button className="btn small" style={{ marginTop: 4 }} onClick={() => setCfg({ extract: [...cfg.extract, { start: "", end: "", regex: "" }] })}>Add extract</button>
          <div className="row small" style={{ marginTop: 10 }}>
            <label>in flight <input aria-label="Concurrency" type="number" min={1} max={20} value={cfg.concurrency} onChange={(e) => setCfg({ concurrency: Number(e.target.value) })} style={{ width: 55 }} /></label>
            <label>delay <input aria-label="Throttle" type="number" min={0} step={50} value={cfg.throttle} onChange={(e) => setCfg({ throttle: Number(e.target.value) })} style={{ width: 75 }} /> ms</label>
          </div>
          <p className="small muted">The rules of engagement's rate limits apply on top. One approval covers the whole attack.</p>
          <button className="btn primary" disabled={action.busy || !cfg.url || !Number.isInteger(positions) || positions < 1} onClick={start} data-testid="fuzzer-run">
            {approval ? "Start approved attack" : `Start attack${total != null ? ` (${total})` : ""}`}
          </button>
          <ErrorBox error={action.error} />
          {outcome?.status === "pending_approval" && (
            <div className="notice">
              Needs approval: {outcome.summary}. Approve <strong>{outcome.approval_id}</strong> on the{" "}
              <a href="#" onClick={(e) => { e.preventDefault(); go("approvals"); }}>Approvals</a> page, then start again.
            </div>
          )}
          {outcome?.status === "denied" && <div className="error">Denied: {outcome.reasons.join("; ")}</div>}
          {(attacks.data?.length ?? 0) > 0 && (
            <select aria-label="Attacks" style={{ marginTop: 8, width: "100%" }} value={attackId ?? ""} onChange={(e) => { setView(null); setSel(null); setAttackId(e.target.value || null); }}>
              <option value="">earlier attacks…</option>
              {attacks.data!.map((a) => (
                <option key={a.attack_id} value={a.attack_id}>{a.status} {a.done}/{a.total} · {a.summary}</option>
              ))}
            </select>
          )}
        </section>
      </div>

      {view && <Results view={view} sel={sel} setSel={setSel} control={control} />}
    </div>
  );
}

type SortKey = "index" | "status" | "length" | "time";

function Results({
  view,
  sel,
  setSel,
  control,
}: {
  view: AttackView;
  sel: Row | null;
  setSel: (r: Row | null) => void;
  control: (w: "pause" | "resume" | "cancel") => void;
}) {
  const { go } = useNav();
  const [onlyAnomalies, setOnlyAnomalies] = useState(false);
  const [hideStatus, setHideStatus] = useState("");
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: "index", desc: false });
  const [detail, setDetail] = useState<ExchangeDetail | null>(null);
  const [tab, setTab] = useState<"response" | "request">("response");
  const reasons = new Map(view.anomalies.map((a) => [a.index, a.reasons]));
  const hidden = new Set(hideStatus.split(/[\s,]+/).filter(Boolean));
  const rows = view.rows
    .filter((r) => !onlyAnomalies || reasons.has(r.index ?? -1))
    .filter((r) => !hidden.has(String(r.status ?? "err")))
    .sort((a, b) => {
      const v = (r: Row) => (sort.key === "index" ? r.index ?? 0 : sort.key === "status" ? r.status ?? 0 : sort.key === "length" ? r.body_length : r.elapsed_ms);
      return (sort.desc ? -1 : 1) * (v(a) - v(b));
    });
  const multi = (view.baseline?.payloads.length ?? 1) > 1;
  const head = (k: SortKey, label: string) => (
    <th className="sortable" aria-sort={sort.key === k ? (sort.desc ? "descending" : "ascending") : undefined} onClick={() => setSort((s) => ({ key: k, desc: s.key === k ? !s.desc : k !== "index" }))}>
      {label}{sort.key === k ? (sort.desc ? " ▾" : " ▴") : ""}
    </th>
  );
  useEffect(() => {
    setDetail(null);
    if (sel) api.get<ExchangeDetail>(`/exchanges/${sel.exchange_id}`).then(setDetail).catch(() => {});
  }, [sel]);
  const running = view.status === "running" || view.status === "paused";

  return (
    <div className="fuzzer-results">
      <div className="row" style={{ marginBottom: 6 }}>
        <strong data-testid="fuzzer-summary">
          {view.total} requests · {view.status} · {view.done}/{view.total}
        </strong>
        <div className="bar grow" style={{ maxWidth: 300 }}><div style={{ width: `${(100 * view.done) / Math.max(1, view.total)}%` }} /></div>
        {view.status === "running" && <button className="btn" onClick={() => control("pause")}>Pause</button>}
        {view.status === "paused" && <button className="btn" onClick={() => control("resume")}>Resume</button>}
        {running && <button className="btn bad" onClick={() => control("cancel")}>Cancel</button>}
        <label className="small"><input type="checkbox" checked={onlyAnomalies} onChange={(e) => setOnlyAnomalies(e.target.checked)} /> only results that stand out ({view.anomalies.length})</label>
        <input aria-label="Hide statuses" className="small" placeholder="hide statuses, e.g. 404" value={hideStatus} onChange={(e) => setHideStatus(e.target.value)} style={{ width: 160 }} />
        {view.error && <span className="bad small">{view.error}</span>}
        {view.note && <span className="small muted" data-testid="attack-note">{view.note}</span>}
      </div>
      <div className={`fuzzer-split ${sel ? "" : "single"}`}>
        <div className="fuzzer-table">
          <table className="grid">
            <thead>
              <tr>
                {head("index", "#")}
                <th>{multi ? "Payloads" : "Payload"}</th>
                {head("status", "Status")}
                {head("length", "Length")}
                {head("time", "Time")}
                <th>Grep</th>
                {view.extract_columns.map((c) => <th key={c} className="mono">{c}</th>)}
                <th>Why it stands out</th>
              </tr>
            </thead>
            <tbody>
              {view.baseline && (
                <tr className={`clickable baseline ${sel === view.baseline ? "selected" : ""}`} onClick={() => setSel(view.baseline!)}>
                  <td className="muted">base</td>
                  <td className="muted">(original)</td>
                  <td><StatusCode status={view.baseline.status ?? null} /></td>
                  <td>{view.baseline.body_length}</td>
                  <td>{view.baseline.elapsed_ms} ms</td>
                  <td>{view.baseline.matches?.join(", ")}</td>
                  {view.extract_columns.map((c, i) => <td key={c} className="mono">{view.baseline!.extracted?.[i] ?? ""}</td>)}
                  <td />
                </tr>
              )}
              {rows.map((r) => {
                const why = reasons.get(r.index ?? -1);
                return (
                  <tr key={r.index} className={`clickable ${why ? "anomalous" : ""} ${sel === r ? "selected" : ""}`} data-testid={why ? "anomaly" : undefined} onClick={() => setSel(r)}>
                    <td className="muted">{(r.index ?? 0) + 1}</td>
                    <td className="mono" style={{ maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {r.payloads.map((p) => (p === null ? "–" : JSON.stringify(p))).join(" · ")}
                    </td>
                    <td>{r.error ? <span className="bad" title={r.error}>error</span> : <StatusCode status={r.status ?? null} />}</td>
                    <td>{r.body_length}</td>
                    <td>{r.elapsed_ms} ms</td>
                    <td>{r.matches?.join(", ")}{r.reflected ? " ↩" : ""}</td>
                    {view.extract_columns.map((c, i) => <td key={c} className="mono" data-testid="extract-cell">{r.extracted?.[i] ?? ""}</td>)}
                    <td className="small">{why?.join("; ")}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {sel && (
          <div className="pane">
            <div className="row small">
              <span>exchange <ExchangeLink id={sel.exchange_id} /></span>
              <button className="btn" onClick={() => go("replay", sel.exchange_id)}>Send to Replay</button>
              <button className="btn" onClick={() => setSel(null)}>Close</button>
            </div>
            <div className="tabs" role="tablist">
              {(["response", "request"] as const).map((t) => (
                <button key={t} role="tab" aria-selected={tab === t} className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>{t[0].toUpperCase() + t.slice(1)}</button>
              ))}
            </div>
            {!detail && <p className="muted">Loading…</p>}
            {detail && tab === "response" && (
              <MessageView text={detail.response} decodedBody={detail.view.response?.body?.text} empty="No response"
                loadB64={() => api.get<ExchangeDetail>(`/exchanges/${sel.exchange_id}?bytes=1`).then((d) => d.response_b64)} />
            )}
            {detail && tab === "request" && <MessageView text={detail.request} />}
          </div>
        )}
      </div>
    </div>
  );
}
