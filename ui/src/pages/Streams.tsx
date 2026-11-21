import { useCallback, useEffect, useMemo, useState } from "react";
import { api, fmtBytes, fmtDateTime, fmtTime, qs } from "../api";
import type { StreamChunkView, StreamDetail, StreamPage, StreamReplayResult, StreamRow } from "../api-types.gen";
import { Empty, ErrorBox, Highlighted, b64ToBytes, bytesToB64, hexDump, useAction } from "../components";
import { useLiveEvent, useLiveTick } from "../live";

/** Chunks fetched per request. */
const PAGE = 500;

/** A chunk with its bytes decoded once. */
interface Chunk extends StreamChunkView {
  bytes: Uint8Array;
  text_all: string;
  hex_all: string;
}

const decode = (c: StreamChunkView): Chunk => {
  const bytes = b64ToBytes(c.data_b64 ?? "");
  return { ...c, bytes, text_all: new TextDecoder().decode(bytes), hex_all: Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("") };
};

const target = (s: StreamRow) => `${s.host}:${s.port}`;

/** How a stream ended, in words. */
const endedText = (s: StreamRow) =>
  s.ended == null
    ? "open"
    : ({ client_closed: "client closed", server_closed: "server closed", error: "error", timeout: "timed out", limit: "size limit" } as Record<string, string>)[s.ended] ?? s.ended;

/**
 * Raw TCP and TLS streams the proxy relayed (protocols that are not HTTP): one row per connection, and for the
 * selected one its chunks in order with direction arrows, a text and a hex view, search, and a way to send it again.
 * New and finished streams arrive as `streams` events, so nothing here polls.
 */
export default function Streams() {
  const tick = useLiveTick(["streams"]);
  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [client, setClient] = useState("");
  const [list, setList] = useState<StreamRow[]>([]);
  const [older, setOlder] = useState<number | null | undefined>();
  const [error, setError] = useState<string | null>(null);
  const [sel, setSel] = useState<number | null>(null);
  const query = { host, port, client, limit: 200 };

  useEffect(() => {
    let live = true;
    api
      .get<StreamPage>(`/streams${qs(query)}`)
      .then((p) => {
        if (!live) return;
        setList(p.streams);
        setOlder(p.next_before_id);
        setError(null);
      })
      .catch((e) => live && setError(e.message));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [host, port, client, tick]);

  const loadOlder = () =>
    api
      .get<StreamPage>(`/streams${qs({ ...query, before_id: older })}`)
      .then((p) => {
        setList((x) => [...x, ...p.streams]);
        setOlder(p.next_before_id);
      })
      .catch((e) => setError(e.message));

  const row = list.find((s) => s.id === sel) ?? null;
  return (
    <div className="content flush">
      <div className={`history ${sel != null ? "" : "single"}`}>
        <div className="history-list">
          <div className="filters" role="search">
            <input aria-label="Stream host" placeholder="host" value={host} onChange={(e) => setHost(e.target.value)} />
            <input aria-label="Stream port" placeholder="port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))} />
            <input aria-label="Stream client" placeholder="client address or device" value={client} onChange={(e) => setClient(e.target.value)} />
          </div>
          <ErrorBox error={error} />
          {list.length === 0 ? (
            <Empty>
              No raw streams yet. Anything that is not HTTP, sent through a CONNECT tunnel, SOCKS5 or a transparent
              listener, is relayed unchanged and recorded here.
            </Empty>
          ) : (
            <div className="vlist">
              <table className="grid" data-testid="streams-list">
                <thead>
                  <tr><th>#</th><th>Started</th><th>Target</th><th>Client</th><th>→ server</th><th>← client</th><th>Chunks</th><th>Ended</th></tr>
                </thead>
                <tbody>
                  {list.map((s) => (
                    <tr key={s.id} className={`clickable ${sel === s.id ? "selected" : ""}`} data-testid={`stream-row-${s.id}`} onClick={() => setSel(s.id)}>
                      <td className="muted">{s.id}</td>
                      <td className="muted">{fmtTime(s.start_ms)}</td>
                      <td className="mono">
                        {target(s)} {s.tls && <span className="chip" title="the bytes are the decrypted ones of a TLS connection">TLS</span>}{" "}
                        {s.source === "stream_replay" && <span className="chip" title={`sent again from stream #${s.replay_of}`}>replay</span>}
                      </td>
                      <td className="mono">{s.client_addr ?? "–"}</td>
                      <td>{fmtBytes(s.bytes_to_server)}</td>
                      <td>{fmtBytes(s.bytes_to_client)}</td>
                      <td>{s.chunks}{s.truncated ? "+" : ""}</td>
                      <td>{endedText(s)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {older != null && (
            <div style={{ padding: 8, borderTop: "1px solid var(--border)" }}>
              <button className="btn" onClick={loadOlder}>Load older</button>
            </div>
          )}
        </div>
        {sel != null && <StreamView id={sel} summary={row} open={setSel} />}
      </div>
    </div>
  );
}

/** One stream: facts, then its chunks. Reloads when the server says this stream changed. */
function StreamView({ id, summary, open }: { id: number; summary: StreamRow | null; open: (id: number) => void }) {
  const [stream, setStream] = useState<StreamRow | null>(summary);
  const [chunks, setChunks] = useState<Chunk[]>([]);
  const [next, setNext] = useState<number | null | undefined>();
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<"text" | "hex">("text");
  const [search, setSearch] = useState("");
  const [replay, setReplay] = useState(false);

  const fetchPage = useCallback(
    async (after: number | undefined, replace: boolean) => {
      try {
        const d = await api.get<StreamDetail>(`/streams/${id}${qs({ after, limit: PAGE })}`);
        setStream(d.stream);
        const more = d.chunks.chunks.map(decode);
        setChunks((c) => (replace ? more : [...c, ...more.filter((m) => !c.some((x) => x.id === m.id))]));
        setNext(d.chunks.next_after_id);
        setError(null);
      } catch (e) {
        setError((e as Error).message);
      }
    },
    [id],
  );
  useEffect(() => {
    setChunks([]);
    setNext(undefined);
    setStream(summary);
    setReplay(false);
    fetchPage(undefined, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);
  // New chunks and the end of this stream arrive as events (a resync refetches whatever is open).
  useLiveEvent(["streams"], (e) => {
    if (e.topic === "resync" || e.data.id === id) {
      const last = chunks.length ? chunks[chunks.length - 1].id : undefined;
      fetchPage(last, last === undefined);
    }
  });

  const q = search.trim();
  const shown = useMemo(
    () => (q ? chunks.filter((c) => c.text_all.toLowerCase().includes(q.toLowerCase()) || c.hex_all.includes(q.replace(/\s/g, "").toLowerCase())) : chunks),
    [chunks, q],
  );
  if (!stream) return <div className="detail">{error ? <ErrorBox error={error} /> : <Empty>Loading…</Empty>}</div>;
  const s = stream;
  return (
    <div className="detail" data-testid="stream-detail">
      <div className="row small muted">
        <span>stream #{s.id}</span>
        <span className="mono">{target(s)}</span>
        {s.tls && <span>TLS{s.sni ? `, server name ${s.sni}` : ""}{s.alpn ? `, ALPN ${s.alpn}` : ""}</span>}
        <span>{s.client_addr ? `from ${s.client_addr}` : "sent by ProxyMind"}</span>
        <span>{fmtDateTime(s.start_ms)}</span>
        {s.replay_of != null && (
          <span>
            replay of <a href="#" onClick={(e) => { e.preventDefault(); open(s.replay_of!); }}>#{s.replay_of}</a>
          </span>
        )}
      </div>
      <dl className="kv" style={{ margin: "10px 0" }}>
        <dt>Sent to the server</dt>
        <dd>{fmtBytes(s.bytes_to_server)}</dd>
        <dt>Sent to the client</dt>
        <dd>{fmtBytes(s.bytes_to_client)}</dd>
        <dt>Ended</dt>
        <dd data-testid="stream-ended">{endedText(s)}{s.error ? `: ${s.error}` : ""}</dd>
      </dl>
      {s.truncated && (
        <div className="notice warn">
          This stream went past the recording limit: later bytes were relayed and counted, but only the first part is kept.
        </div>
      )}
      <div className="msgbar" style={{ margin: "8px 0" }}>
        <button className={`seg ${mode === "text" ? "on" : ""}`} aria-pressed={mode === "text"} onClick={() => setMode("text")}>Text</button>
        <button className={`seg ${mode === "hex" ? "on" : ""}`} aria-pressed={mode === "hex"} onClick={() => setMode("hex")}>Hex</button>
        <input aria-label="Search in stream" placeholder="search in this stream (text or hex)…" value={search} onChange={(e) => setSearch(e.target.value)} style={{ flex: 1 }} />
        <button className="btn" onClick={() => setReplay((r) => !r)} aria-expanded={replay}>Replay stream…</button>
      </div>
      <ErrorBox error={error} />
      {replay && <StreamReplay stream={s} chunks={chunks} open={(n) => { setReplay(false); open(n); }} />}
      {q && <div className="small muted" data-testid="stream-matches">{shown.length} of {chunks.length} chunk(s) match</div>}
      {chunks.length === 0 ? (
        <Empty>No chunks recorded{s.ended == null ? " yet" : ""}.</Empty>
      ) : (
        <div data-testid="stream-chunks">
          {shown.map((c) => (
            <div key={c.id} className={`stream-chunk ${c.from}`} data-testid="stream-chunk" data-from={c.from}>
              <div className="row small muted">
                <span className="stream-arrow" title={c.from === "client" ? "client → server" : "server → client"}>{c.from === "client" ? "→" : "←"}</span>
                <span>{c.from === "client" ? "client → server" : "server → client"}</span>
                <span>{fmtTime(c.ts_ms)}</span>
                <span>{c.len} bytes{c.kept < c.len ? ` (first ${c.kept} kept)` : ""}</span>
              </div>
              <pre className="mono stream-bytes">{mode === "hex" ? <Highlighted text={hexDump(c.bytes, 64 * 1024)} q={q} /> : <Highlighted text={c.text_all} q={q} />}</pre>
            </div>
          ))}
          {next != null && (
            <div style={{ padding: 8 }}>
              <button className="btn" onClick={() => fetchPage(next, false)}>Load more chunks</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** The bytes of a chunk as an editable text: UTF-8 when that round-trips, else hex. */
function editable(bytes: Uint8Array): { value: string; hex: boolean } {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const again = new TextEncoder().encode(text);
    if (again.length === bytes.length && again.every((b, i) => b === bytes[i])) return { value: text, hex: false };
  } catch {
    /* not text */
  }
  return { value: Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(" "), hex: true };
}

const fromHex = (s: string): Uint8Array => {
  const digits = s.replace(/\s+/g, "");
  if (!/^[0-9a-fA-F]*$/.test(digits) || digits.length % 2) throw new Error("hex chunks need pairs of 0-9 and a-f");
  return Uint8Array.from(digits.match(/../g) ?? [], (h) => parseInt(h, 16));
};

/** Send a stream's client chunks to its target again, edited if you like, and record what comes back. */
function StreamReplay({ stream, chunks, open }: { stream: StreamRow; chunks: Chunk[]; open: (id: number) => void }) {
  const sends = useMemo(() => chunks.filter((c) => c.from === "client"), [chunks]);
  const [texts, setTexts] = useState<{ value: string; hex: boolean }[]>(() => sends.map((c) => editable(c.bytes)));
  const [delay, setDelay] = useState(0);
  const [read, setRead] = useState(2000);
  const [result, setResult] = useState<StreamReplayResult | null>(null);
  const action = useAction();
  const cut = sends.some((c) => c.kept < c.len);
  const send = () =>
    action.run(async () => {
      const list = texts.map((t) => bytesToB64(t.hex ? fromHex(t.value) : new TextEncoder().encode(t.value)));
      setResult(await api.post<StreamReplayResult>(`/streams/${stream.id}/replay`, { chunks: list, delay_ms: delay, read_ms: read }));
    });
  return (
    <div className="ws-replay" data-testid="stream-replay">
      {sends.length === 0 && <div className="small muted">This stream has no client chunks: ProxyMind only connects and listens.</div>}
      {cut && <div className="notice warn">A chunk was cut at the recording limit; edit it before sending.</div>}
      {texts.map((t, i) => (
        <label key={sends[i].id} className="small" style={{ display: "block", marginBottom: 6 }}>
          Chunk {i + 1} to send{t.hex ? " (hex)" : ""}
          <textarea
            aria-label={`Chunk ${i + 1} to send`}
            rows={2}
            style={{ width: "100%" }}
            className="mono"
            value={t.value}
            onChange={(e) => setTexts((x) => x.map((y, j) => (j === i ? { ...y, value: e.target.value } : y)))}
          />
        </label>
      ))}
      <div className="row small" style={{ marginTop: 6 }}>
        <label>
          Wait between chunks <input aria-label="Delay between chunks (ms)" type="number" min={0} max={10000} step={100} value={delay} onChange={(e) => setDelay(Number(e.target.value))} style={{ width: 80 }} /> ms
        </label>
        <label>
          Listen at the end <input aria-label="Listen for (ms)" type="number" min={0} max={10000} step={250} value={read} onChange={(e) => setRead(Number(e.target.value))} style={{ width: 80 }} /> ms
        </label>
        <span className="grow muted">A new connection to {target(stream)}{stream.tls ? " (TLS, same server name)" : ""}; the target must be in scope.</span>
        <button className="btn primary" data-testid="stream-replay-send" disabled={action.busy} onClick={send}>
          {action.busy ? "Running…" : "Send stream"}
        </button>
      </div>
      <ErrorBox error={action.error} />
      {result?.status === "done" && (
        <div className="notice" data-testid="stream-replay-result">
          Sent {result.sent_bytes} bytes, received {result.received_bytes}; recorded as stream #{result.stream_id}
          {result.note ? ` (${result.note})` : ""}.{" "}
          <a href="#" onClick={(e) => { e.preventDefault(); open(result.stream_id); }}>Open it</a>
        </div>
      )}
      {result?.status === "failed" && (
        <div className="error">Could not reach the target: {result.error}. Recorded as stream #{result.stream_id}.</div>
      )}
      {result?.status === "pending_approval" && <div className="notice">Waiting for approval: {result.summary}</div>}
      {result?.status === "denied" && <div className="error" data-testid="stream-replay-denied">Denied: {result.reasons.join("; ")}</div>}
    </div>
  );
}
