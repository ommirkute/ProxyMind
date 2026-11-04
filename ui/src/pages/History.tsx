import { useEffect, useMemo, useRef, useState } from "react";
import { api, fmtBytes, fmtTime, originOf, qs, saveText, type ExchangeDetail, type ExchangePage, type ExchangeSummary, type WsPage } from "../api";
import { Chip, ContextMenu, Empty, ErrorBox, HIGHLIGHTS, MessageView, StatusCode, copyText, useAction, useNav, usePref, type MenuItem } from "../components";

const ROW = 28;
/** Bytes of a message shown before "Show all". */
const MAX_SHOWN = 1_000_000;
/** Rows kept in the table while live updates arrive. */
const MAX_ROWS = 20_000;

const DEFAULT_HIDE = "png,jpg,jpeg,gif,svg,ico,webp,css,woff,woff2,ttf,eot,map";

interface Filters {
  text: string;
  method: string;
  source: string;
  classes: string;
  hideExt: boolean;
  hideList: string;
  inScope: boolean;
  annotated: boolean;
  /** Query language (see QueryHelp). */
  q: string;
}

interface SavedFilter {
  name: string;
  q: string;
}

/** Fields of the history query language (mirrors pm_tools::hql::FIELDS). */
const QUERY_FIELDS: [string, string][] = [
  ["host", "host name (glob with *)"],
  ["path", "path and query"],
  ["url", "scheme://host:port/path"],
  ["method", "GET, POST… (comma list)"],
  ["status", "200, 4xx, >=500, 300..399"],
  ["ext", "file extension (comma list)"],
  ["len", "response length in bytes"],
  ["reqlen", "request length in bytes"],
  ["time", "response time in ms"],
  ["id", "exchange number"],
  ["source", "proxy, replay, fuzzer…"],
  ["actor", "who sent it, e.g. agent:claude"],
  ["identity", "test identity used"],
  ["comment", "your comment"],
  ["highlight", "highlight colour"],
  ["mime", "response Content-Type"],
  ["req", "request text (head and decoded body)"],
  ["resp", "response text (head and decoded body)"],
  ["any", "request or response text"],
  ["reqheader", "request header name, or name=value"],
  ["respheader", "response header name, or name=value"],
  ["param", "query or form parameter name"],
  ["is", "error, annotated, inscope, response, redirect"],
];

function QueryHelp({ onPick }: { onPick: (q: string) => void }) {
  const examples = [
    'status:>=400 -ext:png,js,css',
    'resp:"stack trace" OR resp~"(?i)sql syntax"',
    "host:*.example.com method:POST param:id",
    "respheader:set-cookie -respheader:set-cookie=httponly",
    "len:>100000 time:>1000",
    "is:inscope -source:fuzzer comment:idor",
  ];
  return (
    <div className="query-help small" data-testid="query-help">
      <p style={{ marginTop: 0 }}>
        <code>field:value</code> terms side by side must all match; combine with <code>OR</code>, <code>-</code> (not) and
        parentheses. <code>field~regex</code> matches a regular expression (add <code>(?i)</code> to ignore case). Quote
        values with spaces. Numbers take <code>&gt;N</code>, <code>&lt;=N</code>, <code>N..M</code>; status also{" "}
        <code>4xx</code>. A bare word matches host, path or comment. Text terms (req, resp…) read the messages, so they
        take longer on big histories: results come in pages.
      </p>
      <div className="query-fields">
        {QUERY_FIELDS.map(([f, d]) => (
          <span key={f}><code>{f}</code> <span className="muted">{d}</span></span>
        ))}
      </div>
      <p className="muted" style={{ marginBottom: 2 }}>Examples (click to use):</p>
      {examples.map((e) => (
        <button key={e} className="btn small mono" style={{ margin: "2px 4px 2px 0" }} onClick={() => onPick(e)}>{e}</button>
      ))}
    </div>
  );
}

const INITIAL: Filters = {
  text: "",
  method: "",
  source: "",
  classes: "02345",
  hideExt: false,
  hideList: DEFAULT_HIDE,
  inScope: false,
  annotated: false,
  q: "",
};

type SortKey = "id" | "host" | "method" | "path" | "status" | "resp_len" | "ext" | "duration_ms" | "source" | "comment";

const extOf = (path: string) => {
  const p = path.split(/[?#]/)[0];
  const last = p.slice(p.lastIndexOf("/") + 1);
  const dot = last.lastIndexOf(".");
  return dot > 0 ? last.slice(dot + 1).toLowerCase() : "";
};

export default function History() {
  const { arg, counters, go } = useNav();
  const [filters, setFiltersRaw] = usePref<Filters>("pm.history.filters", INITIAL);
  const [rows, setRows] = useState<ExchangeSummary[]>([]);
  const [olderFrom, setOlderFrom] = useState<number | undefined>();
  const [scanned, setScanned] = useState<number | undefined>();
  const [qDraft, setQDraft] = useState(filters.q ?? "");
  const [help, setHelp] = useState(false);
  const [saved, setSaved] = useState<SavedFilter[]>([]);
  useEffect(() => {
    api.get<SavedFilter[] | null>("/ui/history-filters").then((v) => setSaved(Array.isArray(v) ? v : [])).catch(() => {});
  }, []);
  const storeSaved = (list: SavedFilter[]) => {
    setSaved(list);
    api.put("/ui/history-filters", list).catch((e) => setError(e.message));
  };
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: "id", desc: true });
  const [menu, setMenu] = useState<{ x: number; y: number; row: ExchangeSummary } | null>(null);
  const selected = arg ? Number(arg) : undefined;
  const setFilters = (f: Partial<Filters>) => setFiltersRaw({ ...filters, ...f });

  const query = useMemo(
    () => ({
      text: filters.text,
      method: filters.method,
      source: filters.source,
      status_class: filters.classes === "02345" ? "" : filters.classes || "9",
      hide_ext: filters.hideExt ? filters.hideList : "",
      in_scope: filters.inScope || undefined,
      annotated: filters.annotated || undefined,
      q: filters.q || undefined,
    }),
    [filters],
  );

  // (Re)load when filters change.
  useEffect(() => {
    const t = setTimeout(() => {
      api
        .get<ExchangePage>(`/exchanges${qs({ ...query, limit: 500 })}`)
        .then((p) => {
          setRows(p.exchanges);
          setOlderFrom(p.next_before_id);
          setScanned(p.scanned);
          setError(null);
        })
        .catch((e) => setError(e.message));
    }, 200);
    return () => clearTimeout(t);
  }, [query]);

  // Live: fetch newer rows when the server says there are some.
  const newest = rows.reduce((m, r) => Math.max(m, r.id), 0);
  useEffect(() => {
    if (!counters || counters.last_exchange_id <= newest) return;
    api
      .get<ExchangePage>(`/exchanges${qs({ ...query, after_id: newest, limit: 500 })}`)
      .then((p) => {
        if (!p.exchanges.length) return;
        if (p.exchanges.length >= 500) {
          // More arrived than one page: start again from the newest instead of leaving a gap.
          setRows(p.exchanges);
          setOlderFrom(p.exchanges[p.exchanges.length - 1].id);
          return;
        }
        setRows((r) => {
          const next = [...p.exchanges, ...r];
          if (next.length <= MAX_ROWS) return next;
          setOlderFrom(next[MAX_ROWS - 1].id);
          return next.slice(0, MAX_ROWS);
        });
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [counters?.last_exchange_id]);

  const loadOlder = () =>
    api
      .get<ExchangePage>(`/exchanges${qs({ ...query, before_id: olderFrom, limit: 500 })}`)
      .then((p) => {
        setRows((r) => [...r, ...p.exchanges]);
        setOlderFrom(p.next_before_id);
        setScanned((n) => (p.scanned === undefined ? undefined : (n ?? 0) + p.scanned));
      })
      .catch((e) => setError(e.message));

  const sorted = useMemo(() => {
    const val = (r: ExchangeSummary): string | number => {
      switch (sort.key) {
        case "ext":
          return extOf(r.path);
        case "status":
          return r.status ?? 0;
        case "resp_len":
          return r.resp_len ?? -1;
        case "duration_ms":
          return r.duration_ms ?? -1;
        case "comment":
          return r.comment ?? "";
        default:
          return r[sort.key] as string | number;
      }
    };
    const out = [...rows];
    out.sort((a, b) => {
      const x = val(a);
      const y = val(b);
      const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y));
      return (sort.desc ? -c : c) || b.id - a.id;
    });
    return out;
  }, [rows, sort]);

  const annotate = (row: ExchangeSummary, highlight: string | null | undefined, comment: string | null | undefined) =>
    api
      .put<ExchangeSummary>(`/exchanges/${row.id}/annotation`, { highlight: highlight || undefined, comment: comment || undefined })
      .then((r) => setRows((rs) => rs.map((x) => (x.id === r.id ? { ...x, highlight: r.highlight, comment: r.comment } : x))))
      .catch((e) => setError(e.message));

  const urlOf = (r: ExchangeSummary) => originOf(r) + r.path;

  const menuItems = (r: ExchangeSummary): MenuItem[] => [
    { label: "Send to Replay", hint: "Ctrl+R", onClick: () => go("replay", r.id) },
    { label: "Send to Fuzzer", hint: "Ctrl+I", onClick: () => go("fuzzer", r.id) },
    { label: "Active scan", onClick: () => go("issues", r.id) },
    { label: "Plugin check…", onClick: () => go("plugins", r.id) },
    { label: "Authorization check…", onClick: () => go("authz", r.id) },
    {
      label: "Send to Organizer",
      onClick: () =>
        api
          .post("/organizer", { exchange_id: r.id })
          .then(() => setNote(`#${r.id} sent to the Organizer.`))
          .catch((e) => setError(e.message)),
    },
    { label: "Generate CSRF PoC…", onClick: () => go("engage", `csrf:${r.id}`) },
    { label: "Find references", onClick: () => go("engage", `refs:${r.id}`) },
    { label: "Test clickjacking", onClick: () => go("engage", `clickjack:${r.id}`) },
    { label: "Copy URL", onClick: () => copyText(urlOf(r)).then(() => setNote("URL copied.")) },
    {
      label: "Copy as cURL",
      onClick: () =>
        api
          .get<{ command: string }>(`/exchanges/${r.id}/curl`)
          .then((c) => copyText(c.command))
          .then(() => setNote("cURL command copied."))
          .catch((e) => setError(e.message)),
    },
    ...(["python", "javascript", "powershell"] as const).map((lang) => ({
      label: `Copy as ${lang === "python" ? "Python requests" : lang === "javascript" ? "JavaScript fetch" : "PowerShell"}`,
      onClick: () =>
        api
          .get<{ code: string }>(`/exchanges/${r.id}/code?lang=${lang}`)
          .then((c) => copyText(c.code))
          .then(() => setNote("Code copied."))
          .catch((e) => setError(e.message)),
    })),
    {
      label: "Highlight",
      swatches: [null, ...HIGHLIGHTS].map((c) => ({ color: c, onClick: () => annotate(r, c, r.comment) })),
    },
    {
      label: r.comment ? "Edit comment…" : "Add comment…",
      onClick: () => {
        const c = window.prompt("Comment", r.comment ?? "");
        if (c !== null) annotate(r, r.highlight, c);
      },
    },
    { label: "Show only this host", onClick: () => setFilters({ text: r.host }) },
  ];

  // Keyboard: arrows move, Ctrl/Cmd+R and Ctrl/Cmd+I send the selected row.
  const onKey = (e: React.KeyboardEvent) => {
    const i = sorted.findIndex((r) => r.id === selected);
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const next = sorted[Math.max(0, Math.min(sorted.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
      if (next) go("history", next.id);
    } else if ((e.ctrlKey || e.metaKey) && selected && (e.key === "r" || e.key === "i")) {
      e.preventDefault();
      go(e.key === "r" ? "replay" : "fuzzer", selected);
    }
  };

  const importHar = (file: File | undefined) => {
    if (!file) return;
    file
      .text()
      .then((har) => api.post<{ imported: number; skipped: string[] }>("/import/har", { har }))
      .then((r) => {
        setNote(`Imported ${r.imported} exchanges${r.skipped.length ? `; skipped ${r.skipped.length}: ${r.skipped.slice(0, 3).join("; ")}` : ""}.`);
        setFilters({ source: "import", text: "", annotated: false });
      })
      .catch((e) => setError(e.message));
  };
  const exportHar = () =>
    api
      .post<unknown>("/export/har", {
        text: filters.text || undefined,
        method: filters.method || undefined,
        source: filters.source || undefined,
        status_class: query.status_class || undefined,
        hide_ext: query.hide_ext || undefined,
        annotated: query.annotated,
        in_scope: query.in_scope,
        q: query.q,
      })
      .then((har) => saveText("proxymind.har", JSON.stringify(har)))
      .catch((e) => setError(e.message));

  const toggleClass = (c: string) =>
    setFilters({ classes: filters.classes.includes(c) ? filters.classes.replace(c, "") : [...filters.classes + c].sort().join("") });

  return (
    <div className="content flush">
      <div className={`history ${selected ? "" : "single"}`}>
        <div className="history-list" tabIndex={0} onKeyDown={onKey}>
          <div className="filters" role="search">
            <input className="wide" aria-label="Filter" placeholder="host, path or comment contains…" value={filters.text} onChange={(e) => setFilters({ text: e.target.value })} />
            <select aria-label="Method" value={filters.method} onChange={(e) => setFilters({ method: e.target.value })}>
              <option value="">any method</option>
              {["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"].map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
            <select aria-label="Source" value={filters.source} onChange={(e) => setFilters({ source: e.target.value })}>
              <option value="">any source</option>
              {["proxy", "replay", "import", "crawl", "discover", "scan", "fuzzer", "authz", "proof", "login", "health"].map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
            <label className="btn" title="Add a HAR file (browser devtools export) to history; nothing is sent">
              Import HAR
              <input type="file" accept=".har,application/json" hidden data-testid="import-har" onChange={(e) => importHar(e.target.files?.[0])} />
            </label>
            <button className="btn" onClick={exportHar} title="Download the filtered history as a HAR file" data-testid="export-har">Export HAR</button>
            <div className="filter-group" role="group" aria-label="Status">
              {[["2", "2xx"], ["3", "3xx"], ["4", "4xx"], ["5", "5xx"], ["0", "no resp."]].map(([c, l]) => (
                <label key={c}><input type="checkbox" checked={filters.classes.includes(c)} onChange={() => toggleClass(c)} /> {l}</label>
              ))}
            </div>
            <div className="filter-group">
              <label title={filters.hideList}><input type="checkbox" checked={filters.hideExt} onChange={(e) => setFilters({ hideExt: e.target.checked })} data-testid="hide-ext" /> hide images, CSS, fonts</label>
              <label><input type="checkbox" checked={filters.inScope} onChange={(e) => setFilters({ inScope: e.target.checked })} data-testid="in-scope-only" /> in scope only</label>
              <label><input type="checkbox" checked={filters.annotated} onChange={(e) => setFilters({ annotated: e.target.checked })} data-testid="annotated-only" /> highlighted or commented</label>
              <span>{sorted.length}{olderFrom ? "+" : ""} shown</span>
            </div>
          </div>
          <div className="filters query-bar">
            <input
              className="grow mono"
              aria-label="Query"
              placeholder='query: status:>=400 -ext:png resp:"error"  (Enter to apply)'
              value={qDraft}
              onChange={(e) => setQDraft(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && setFilters({ q: qDraft.trim() })}
            />
            <button className="btn" data-testid="apply-query" onClick={() => setFilters({ q: qDraft.trim() })}>Apply</button>
            {filters.q && <button className="btn" data-testid="clear-query" onClick={() => { setQDraft(""); setFilters({ q: "" }); }}>Clear</button>}
            <select
              aria-label="Saved filters"
              value=""
              onChange={(e) => {
                const f = saved.find((x) => x.name === e.target.value);
                if (f) {
                  setQDraft(f.q);
                  setFilters({ q: f.q });
                }
              }}
            >
              <option value="">saved filters…</option>
              {saved.map((f) => <option key={f.name} value={f.name}>{f.name}</option>)}
            </select>
            <button
              className="btn"
              data-testid="save-filter"
              disabled={!qDraft.trim()}
              title="Save this query for the project"
              onClick={() => {
                const name = window.prompt("Name for this filter", saved.find((f) => f.q === qDraft.trim())?.name ?? "");
                if (name?.trim()) storeSaved([...saved.filter((f) => f.name !== name.trim()), { name: name.trim(), q: qDraft.trim() }]);
              }}
            >
              Save
            </button>
            {saved.some((f) => f.q === filters.q) && (
              <button className="btn" title="Delete this saved filter" onClick={() => storeSaved(saved.filter((f) => f.q !== filters.q))}>Delete</button>
            )}
            <button className="btn" aria-label="Query help" aria-pressed={help} onClick={() => setHelp(!help)}>?</button>
          </div>
          {help && <QueryHelp onPick={(q) => { setQDraft(q); setFilters({ q }); }} />}
          {filters.q && scanned !== undefined && (
            <div className="small muted" style={{ padding: "2px 8px" }} data-testid="query-scanned">
              {sorted.length} match{sorted.length === 1 ? "" : "es"} in {scanned.toLocaleString()} exchanges looked at{olderFrom ? " · Load older to keep looking" : ""}
            </div>
          )}
          <ErrorBox error={error} />
          {note && <div className="notice" data-testid="import-note">{note}</div>}
          <VirtualRows
            rows={sorted}
            selected={selected}
            onSelect={(id) => go("history", id)}
            sort={sort}
            onSort={(key) => setSort((s) => ({ key, desc: s.key === key ? !s.desc : key === "id" }))}
            onMenu={(e, row) => {
              e.preventDefault();
              go("history", row.id);
              setMenu({ x: e.clientX, y: e.clientY, row });
            }}
          />
          {olderFrom && (
            <div style={{ padding: 8, borderTop: "1px solid var(--border)" }}>
              <button className="btn" onClick={loadOlder}>Load older</button>
            </div>
          )}
        </div>
        {selected && <Detail key={selected} id={selected} live={rows.find((r) => r.id === selected)} onAnnotated={(r) => setRows((rs) => rs.map((x) => (x.id === r.id ? { ...x, highlight: r.highlight, comment: r.comment } : x)))} />}
      </div>
      {menu && <ContextMenu x={menu.x} y={menu.y} items={menuItems(menu.row)} onClose={() => setMenu(null)} />}
    </div>
  );
}

const COLUMNS: { key: SortKey; label: string }[] = [
  { key: "id", label: "#" },
  { key: "host", label: "Host" },
  { key: "method", label: "Method" },
  { key: "path", label: "URL" },
  { key: "status", label: "Status" },
  { key: "resp_len", label: "Length" },
  { key: "ext", label: "Ext" },
  { key: "duration_ms", label: "Time" },
  { key: "source", label: "Tool" },
  { key: "comment", label: "Comment" },
];

function VirtualRows({
  rows,
  selected,
  onSelect,
  sort,
  onSort,
  onMenu,
}: {
  rows: ExchangeSummary[];
  selected?: number;
  onSelect: (id: number) => void;
  sort: { key: SortKey; desc: boolean };
  onSort: (k: SortKey) => void;
  onMenu: (e: React.MouseEvent, r: ExchangeSummary) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [scroll, setScroll] = useState(0);
  const [height, setHeight] = useState(600);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setHeight(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  // Keep the selected row in view when moving with the keyboard.
  useEffect(() => {
    const el = ref.current;
    const i = rows.findIndex((r) => r.id === selected);
    if (!el || i < 0) return;
    const top = i * ROW;
    if (top < el.scrollTop) el.scrollTop = top;
    else if (top + ROW * 2 > el.scrollTop + el.clientHeight) el.scrollTop = top + ROW * 2 - el.clientHeight;
  }, [selected, rows]);
  if (rows.length === 0) return <Empty>No traffic matches. Point your browser at the proxy, or use the Replay.</Empty>;
  const first = Math.max(0, Math.floor(scroll / ROW) - 10);
  const last = Math.min(rows.length, Math.ceil((scroll + height) / ROW) + 10);
  return (
    <div className="vlist" ref={ref} onScroll={(e) => setScroll(e.currentTarget.scrollTop)} role="table" aria-label="History">
      <div className="vrow vhead" role="row">
        {COLUMNS.map((c) => (
          <span key={c.key} className="sortable" role="columnheader" onClick={() => onSort(c.key)} aria-sort={sort.key === c.key ? (sort.desc ? "descending" : "ascending") : undefined}>
            {c.label}
            {sort.key === c.key ? (sort.desc ? " ▾" : " ▴") : ""}
          </span>
        ))}
      </div>
      <div style={{ height: rows.length * ROW, position: "relative" }}>
        {rows.slice(first, last).map((r, i) => (
          <div
            key={r.id}
            role="row"
            data-testid={`row-${r.id}`}
            className={`vrow ${selected === r.id ? "selected" : ""} ${r.highlight ? `hl-${r.highlight}` : ""}`}
            style={{ top: (first + i) * ROW }}
            onClick={() => onSelect(r.id)}
            onContextMenu={(e) => onMenu(e, r)}
            title={`${fmtTime(r.ts_ms)} · ${r.source} · ${r.actor_id}${r.identity ? ` as ${r.identity}` : ""}`}
          >
            <span className="muted">{r.id}</span>
            <span>{r.host}{r.port !== 80 && r.port !== 443 ? `:${r.port}` : ""}</span>
            <span>{r.method}</span>
            <span>{r.path}</span>
            <span><StatusCode status={r.status} error={r.error} /></span>
            <span className="muted">{fmtBytes(r.resp_len)}</span>
            <span className="muted">{extOf(r.path)}</span>
            <span className="muted">{r.duration_ms != null ? `${r.duration_ms} ms` : ""}</span>
            <span className="muted">{r.source}</span>
            <span data-testid="comment-cell">{r.comment ?? ""}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Detail({ id, live, onAnnotated }: { id: number; live?: ExchangeSummary; onAnnotated: (r: ExchangeSummary) => void }) {
  const { go } = useNav();
  const [ex, setEx] = useState<ExchangeDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"request" | "response" | "summary" | "websocket">("response");
  const [capture, setCapture] = useState({ open: false, name: "", role: "user" });
  const action = useAction();
  const [note, setNote] = useState<string | null>(null);
  const [curl, setCurl] = useState<string | null>(null);
  // Big messages load cut to MAX_SHOWN until asked for in full.
  const [full, setFull] = useState(false);
  const cap = full ? "" : `max=${MAX_SHOWN}`;

  useEffect(() => {
    setCurl(null);
    setNote(null);
    api
      .get<ExchangeDetail>(`/exchanges/${id}${cap ? `?${cap}` : ""}`)
      .then((d) => {
        setEx(d);
        if (d.summary.status === 101 && !full) setTab("websocket");
      })
      .catch((e) => setError(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, full]);

  if (error) return <div className="detail"><ErrorBox error={error} /></div>;
  if (!ex) return <div className="detail muted">Loading…</div>;
  // The list may have newer annotations (set from the right-click menu).
  const s = live ? { ...ex.summary, highlight: live.highlight, comment: live.comment } : ex.summary;
  const resp = ex.view.response?.body;

  const doCapture = () =>
    action.run(async () => {
      await api.post("/identities/capture", { name: capture.name, role: capture.role, exchange_id: id });
      setCapture({ open: false, name: "", role: "user" });
      setNote(`Identity "${capture.name}" captured from #${id}.`);
    });

  const copyCurl = () =>
    action.run(async () => {
      const r = await api.get<{ command: string }>(`/exchanges/${id}/curl`);
      setCurl(r.command);
      await navigator.clipboard?.writeText(r.command).catch(() => {});
    });

  // Exact bytes for the hex view, fetched once when first asked for.
  const loadBytes = (k: "request_b64" | "response_b64") => () =>
    api.get<ExchangeDetail>(`/exchanges/${id}?bytes=1${cap ? `&${cap}` : ""}`).then((d) => d[k] ?? null);

  const saveAnnotation = (highlight: string | null | undefined, comment: string | null | undefined) =>
    action.run(async () => {
      const r = await api.put<ExchangeSummary>(`/exchanges/${id}/annotation`, {
        highlight: highlight || undefined,
        comment: comment || undefined,
      });
      setEx((e) => (e ? { ...e, summary: { ...e.summary, highlight: r.highlight, comment: r.comment } } : e));
      onAnnotated(r);
    });

  return (
    <div className="detail" data-testid="exchange-detail">
      <div className="row">
        <strong className="mono grow" style={{ wordBreak: "break-all" }}>
          {s.method} {ex.view.url}
        </strong>
        <StatusCode status={s.status} error={s.error} />
      </div>
      <div className="row small muted" style={{ marginTop: 4 }}>
        <span>#{s.id}</span>
        <span>{s.source}</span>
        <span>{s.actor_id}</span>
        {s.identity && <Chip value={`as ${s.identity}`} />}
        {s.duration_ms != null && <span>{s.duration_ms} ms</span>}
        {s.hypothesis_id && <span>hypothesis #{s.hypothesis_id}</span>}
      </div>
      <div className="row small" style={{ marginTop: 6 }}>
        <span className="muted">Highlight</span>
        {[null, ...HIGHLIGHTS].map((c) => (
          <button
            key={c ?? "none"}
            className={`swatch ${c ? `hl-${c}` : "none"} ${s.highlight === c || (!s.highlight && !c) ? "on" : ""}`}
            aria-label={`Highlight ${c ?? "none"}`}
            onClick={() => saveAnnotation(c, s.comment)}
          />
        ))}
        <CommentBox key={s.comment ?? ""} value={s.comment ?? ""} onSave={(c) => saveAnnotation(s.highlight, c)} />
      </div>
      <div className="row" style={{ marginTop: 10 }}>
        <button className="btn" onClick={() => go("replay", id)}>Send to Replay</button>
        <button className="btn" onClick={() => go("fuzzer", id)}>Send to Fuzzer</button>
        <button className="btn" onClick={() => go("issues", id)}>Active scan</button>
        <button className="btn" onClick={() => go("authz", id)}>Authorization check…</button>
        <button className="btn" onClick={() => setCapture((c) => ({ ...c, open: !c.open }))}>Capture identity…</button>
        <button className="btn" data-testid="copy-curl" onClick={copyCurl}>Copy as cURL</button>
      </div>
      {curl && <pre className="raw small" data-testid="curl-command" style={{ marginTop: 8 }}>{curl}</pre>}
      {capture.open && (
        <div className="row" style={{ marginTop: 8 }}>
          <input aria-label="Identity name" placeholder="name, e.g. alice" value={capture.name} onChange={(e) => setCapture((c) => ({ ...c, name: e.target.value }))} />
          <input aria-label="Role" placeholder="role" value={capture.role} onChange={(e) => setCapture((c) => ({ ...c, role: e.target.value }))} style={{ width: 90 }} />
          <button className="btn primary" disabled={!capture.name || action.busy} onClick={doCapture}>Capture</button>
        </div>
      )}
      <ErrorBox error={action.error} />
      {note && <div className="notice">{note}</div>}
      {ex.view.possible_prompt_injection?.length ? (
        <div className="error">Possible prompt injection in the response: {ex.view.possible_prompt_injection.join(" · ")}</div>
      ) : null}
      <div className="tabs" role="tablist">
        {([...(s.status === 101 ? ["websocket"] : []), "response", "request", "summary"] as const).map((t) => (
          <button key={t} role="tab" aria-selected={tab === t} className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t as typeof tab)}>
            {t === "websocket" ? "WebSocket" : t[0].toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>
      {tab === "websocket" && (
        <>
          <WsReplay id={id} />
          <WsMessages id={id} />
        </>
      )}
      {tab === "request" && (
        <MessageView text={ex.request} decodedBody={ex.view.request.body?.text} loadB64={loadBytes("request_b64")} truncated={ex.request_truncated} onShowAll={() => setFull(true)} testid="request-view" />
      )}
      {tab === "response" && (
        <MessageView
          text={ex.response ?? s.error}
          decodedBody={ex.response ? resp?.text : undefined}
          loadB64={ex.response ? loadBytes("response_b64") : undefined}
          truncated={ex.response_truncated}
          onShowAll={() => setFull(true)}
          empty="No response"
          testid="response-view"
        />
      )}
      {tab === "summary" && (
        <dl className="kv">
          <dt>Response type</dt>
          <dd>{resp?.content_type ?? resp?.kind ?? "–"}</dd>
          <dt>Body size</dt>
          <dd>{fmtBytes(resp?.size)}</dd>
          <dt>Outline</dt>
          <dd className="mono">{resp?.outline ?? "–"}</dd>
          <dt>Notes</dt>
          <dd>{resp?.notes?.join("; ") || "–"}</dd>
        </dl>
      )}
    </div>
  );
}

type WsReplayResult =
  | { status: "done"; exchange_id: number; closed_by: string; note?: string; messages: WsPage }
  | { status: "not_upgraded"; exchange_id: number; http_status?: number; error?: string }
  | { status: "pending_approval"; approval_id: string; summary: string; reasons: string[] }
  | { status: "denied"; reasons: string[] };

/** Opens a new WebSocket like this one and sends messages (one per line). */
function WsReplay({ id }: { id: number }) {
  const { go } = useNav();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [wait, setWait] = useState(1000);
  const [result, setResult] = useState<WsReplayResult | null>(null);
  const action = useAction();
  const send = () =>
    action.run(async () => {
      const messages = text
        .split("\n")
        .filter((l) => l.length > 0)
        .map((l) => ({ text: l }));
      setResult(await api.post<WsReplayResult>("/ws/replay", { exchange_id: id, messages, wait_ms: wait }));
    });
  if (!open) {
    return (
      <div className="row" style={{ margin: "8px 0" }}>
        <button className="btn" onClick={() => setOpen(true)}>Replay on a new connection…</button>
      </div>
    );
  }
  return (
    <div className="ws-replay" data-testid="ws-replay">
      <textarea
        aria-label="Messages to send"
        rows={3}
        placeholder="Messages to send, one per line (leave empty to just open and listen)"
        value={text}
        onChange={(e) => setText(e.target.value)}
        style={{ width: "100%" }}
      />
      <div className="row small" style={{ marginTop: 6 }}>
        <label>
          Listen after each message{" "}
          <input aria-label="Wait (ms)" type="number" min={0} max={10000} step={250} value={wait} onChange={(e) => setWait(Number(e.target.value))} style={{ width: 80 }} /> ms
        </label>
        <span className="grow muted">A fresh connection with the same headers; ProxyMind answers pings and closes at the end.</span>
        <button className="btn primary" data-testid="ws-replay-send" disabled={action.busy} onClick={send}>
          {action.busy ? "Running…" : "Open and send"}
        </button>
      </div>
      <ErrorBox error={action.error} />
      {result?.status === "done" && (
        <div className="notice" data-testid="ws-replay-result">
          {result.messages.total} message(s) recorded as exchange #{result.exchange_id}, closed by {result.closed_by}
          {result.note ? ` (${result.note})` : ""}.{" "}
          <a href="#" onClick={(e) => { e.preventDefault(); go("history", result.exchange_id); }}>Open it</a>
        </div>
      )}
      {result?.status === "not_upgraded" && (
        <div className="error">
          The server didn't open a WebSocket{result.http_status ? ` (HTTP ${result.http_status})` : ""}{result.error ? `: ${result.error}` : ""}. Recorded as #{result.exchange_id}.
        </div>
      )}
      {result?.status === "pending_approval" && <div className="notice">Waiting for approval: {result.summary}</div>}
      {result?.status === "denied" && <div className="error">Denied: {result.reasons.join("; ")}</div>}
    </div>
  );
}

/** WebSocket messages of an upgraded exchange; refreshes while open. */
function WsMessages({ id }: { id: number }) {
  const [page, setPage] = useState<WsPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    const load = () =>
      api
        .get<WsPage>(`/exchanges/${id}/ws?limit=500`)
        .then((p) => live && setPage(p))
        .catch((e) => live && setError(e.message));
    load();
    const t = setInterval(load, 3000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [id]);
  if (error) return <ErrorBox error={error} />;
  if (!page) return <div className="muted">Loading…</div>;
  if (page.total === 0) return <Empty>No WebSocket messages recorded yet.</Empty>;
  return (
    <div data-testid="ws-messages">
      <div className="small muted" style={{ margin: "6px 0" }}>
        {page.total} message(s){page.total > page.messages.length ? `, showing the first ${page.messages.length}` : ""}
      </div>
      {page.messages.map((m) => (
        <div key={m.id} className={`ws-msg ${m.from}`}>
          <div className="row small muted">
            <strong title={m.from === "client" ? "browser to server" : "server to browser"}>
              {m.from === "client" ? "→ to server" : "← from server"}
            </strong>
            <Chip value={m.kind} />
            <span>{fmtBytes(m.len)}</span>
            <span>{fmtTime(m.ts_ms)}</span>
            {m.truncated && <span>(cut short)</span>}
            {m.compressed && <span title="permessage-deflate data that could not be inflated">(compressed)</span>}
          </div>
          {m.possible_prompt_injection?.length ? (
            <div className="error">Possible prompt injection: {m.possible_prompt_injection.join(" · ")}</div>
          ) : null}
          <pre className="raw">{m.text ?? m.hex}</pre>
        </div>
      ))}
    </div>
  );
}

function CommentBox({ value, onSave }: { value: string; onSave: (c: string) => void }) {
  const [v, setV] = useState(value);
  return (
    <form className="row grow" onSubmit={(e) => { e.preventDefault(); onSave(v); }}>
      <input className="grow" aria-label="Comment" placeholder="comment…" value={v} onChange={(e) => setV(e.target.value)} />
      {v !== value && <button className="btn" data-testid="save-comment">Save</button>}
    </form>
  );
}
