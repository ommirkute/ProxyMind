import { useEffect, useMemo, useRef, useState } from "react";
import { api, fmtBytes, fmtTime, qs, type ExchangeDetail, type ExchangePage, type ExchangeSummary, type WsPage } from "../api";
import { Chip, Empty, ErrorBox, Raw, StatusCode, useAction, useNav } from "../components";

const ROW = 30;

interface Filters {
  host: string;
  path: string;
  method: string;
  status: string;
  source: string;
}

export default function History() {
  const { arg, counters, go } = useNav();
  const [filters, setFilters] = useState<Filters>({ host: "", path: "", method: "", status: "", source: "" });
  const [rows, setRows] = useState<ExchangeSummary[]>([]);
  const [olderFrom, setOlderFrom] = useState<number | undefined>();
  const [error, setError] = useState<string | null>(null);
  const selected = arg ? Number(arg) : undefined;

  const query = useMemo(
    () => ({
      host: filters.host,
      path: filters.path,
      method: filters.method,
      status: filters.status,
      source: filters.source,
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
          setError(null);
        })
        .catch((e) => setError(e.message));
    }, 200);
    return () => clearTimeout(t);
  }, [query]);

  // Live: fetch newer rows when the server says there are some.
  const newest = rows[0]?.id ?? 0;
  useEffect(() => {
    if (!counters || counters.last_exchange_id <= newest) return;
    api
      .get<ExchangePage>(`/exchanges${qs({ ...query, after_id: newest, limit: 500 })}`)
      .then((p) => p.exchanges.length && setRows((r) => [...p.exchanges, ...r]))
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [counters?.last_exchange_id]);

  const loadOlder = () =>
    api
      .get<ExchangePage>(`/exchanges${qs({ ...query, before_id: olderFrom, limit: 500 })}`)
      .then((p) => {
        setRows((r) => [...r, ...p.exchanges]);
        setOlderFrom(p.next_before_id);
      })
      .catch((e) => setError(e.message));

  const set = (k: keyof Filters) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setFilters((f) => ({ ...f, [k]: e.target.value }));

  return (
    <div className="content flush">
      <div className={`history ${selected ? "" : "single"}`}>
        <div className="history-list">
          <div className="filters" role="search">
            <input aria-label="Host" placeholder="host" value={filters.host} onChange={set("host")} />
            <input className="wide" aria-label="Path" placeholder="path contains…" value={filters.path} onChange={set("path")} />
            <select aria-label="Method" value={filters.method} onChange={set("method")}>
              <option value="">any method</option>
              {["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"].map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
            <input aria-label="Status" placeholder="status" value={filters.status} onChange={set("status")} style={{ width: 70 }} />
            <select aria-label="Source" value={filters.source} onChange={set("source")}>
              <option value="">any source</option>
              {["proxy", "replay", "authz", "proof", "login", "health"].map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
          </div>
          <ErrorBox error={error} />
          <VirtualRows rows={rows} selected={selected} onSelect={(id) => go("history", id)} />
          {olderFrom && (
            <div style={{ padding: 8, borderTop: "1px solid var(--border)" }}>
              <button className="btn" onClick={loadOlder}>Load older</button>
            </div>
          )}
        </div>
        {selected && <Detail key={selected} id={selected} />}
      </div>
    </div>
  );
}

function VirtualRows({ rows, selected, onSelect }: { rows: ExchangeSummary[]; selected?: number; onSelect: (id: number) => void }) {
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
  if (rows.length === 0) return <Empty>No traffic yet. Point your browser at the proxy, or use the Repeater.</Empty>;
  const first = Math.max(0, Math.floor(scroll / ROW) - 10);
  const last = Math.min(rows.length, Math.ceil((scroll + height) / ROW) + 10);
  return (
    <div className="vlist" ref={ref} onScroll={(e) => setScroll(e.currentTarget.scrollTop)} role="table" aria-label="History">
      <div className="vrow vhead" role="row">
        <span>#</span><span>Time</span><span>Method</span><span>Host</span><span>Path</span><span>Status</span><span>Size</span>
      </div>
      <div style={{ height: rows.length * ROW, position: "relative" }}>
        {rows.slice(first, last).map((r, i) => (
          <div
            key={r.id}
            role="row"
            data-testid={`row-${r.id}`}
            className={`vrow ${selected === r.id ? "selected" : ""}`}
            style={{ top: (first + i) * ROW }}
            onClick={() => onSelect(r.id)}
            title={`${r.source} · ${r.actor_id}${r.identity ? ` as ${r.identity}` : ""}`}
          >
            <span className="muted">{r.id}</span>
            <span className="muted">{fmtTime(r.ts_ms)}</span>
            <span>{r.method}</span>
            <span>{r.host}</span>
            <span>{r.path}</span>
            <span><StatusCode status={r.status} error={r.error} /></span>
            <span className="muted">{fmtBytes(r.resp_len)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Detail({ id }: { id: number }) {
  const { go } = useNav();
  const [ex, setEx] = useState<ExchangeDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"request" | "response" | "summary" | "websocket">("response");
  const [capture, setCapture] = useState({ open: false, name: "", role: "user" });
  const action = useAction();
  const [note, setNote] = useState<string | null>(null);

  useEffect(() => {
    setEx(null);
    setNote(null);
    api
      .get<ExchangeDetail>(`/exchanges/${id}`)
      .then((d) => {
        setEx(d);
        if (d.summary.status === 101) setTab("websocket");
      })
      .catch((e) => setError(e.message));
  }, [id]);

  if (error) return <div className="detail"><ErrorBox error={error} /></div>;
  if (!ex) return <div className="detail muted">Loading…</div>;
  const s = ex.summary;
  const resp = ex.view.response?.body;

  const doCapture = () =>
    action.run(async () => {
      await api.post("/identities/capture", { name: capture.name, role: capture.role, exchange_id: id });
      setCapture({ open: false, name: "", role: "user" });
      setNote(`Identity "${capture.name}" captured from #${id}.`);
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
      <div className="row" style={{ marginTop: 10 }}>
        <button className="btn" onClick={() => go("repeater", id)}>Send to Repeater</button>
        <button className="btn" onClick={() => go("intruder", id)}>Send to Intruder</button>
        <button className="btn" onClick={() => go("issues", id)}>Active scan</button>
        <button className="btn" onClick={() => go("authz", id)}>Authorization check…</button>
        <button className="btn" onClick={() => setCapture((c) => ({ ...c, open: !c.open }))}>Capture identity…</button>
      </div>
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
      {tab === "request" && <Raw text={ex.request} />}
      {tab === "response" && <Raw text={ex.response ?? s.error} label="No response" />}
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
