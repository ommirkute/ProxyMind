import { useEffect, useState } from "react";
import { api, fmtTime, qs, type WsMessage } from "../api";
import { Empty, ErrorBox, ExchangeLink, MessageView, useNav } from "../components";

interface Item extends WsMessage {
  exchange_id: number;
  host: string;
  path: string;
}

interface Page {
  messages: Item[];
  next_before_id?: number;
}

/** WebSocket messages across every connection, newest first. */
export default function WsHistory() {
  const { counters, go } = useNav();
  const [host, setHost] = useState("");
  const [dir, setDir] = useState<"" | "client" | "server">("");
  const [text, setText] = useState("");
  const [items, setItems] = useState<Item[]>([]);
  const [older, setOlder] = useState<number | undefined>();
  const [sel, setSel] = useState<Item | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const t = setTimeout(() => {
      api
        .get<Page>(`/ws/history${qs({ host, limit: 500 })}`)
        .then((p) => {
          setItems(p.messages);
          setOlder(p.next_before_id);
          setError(null);
        })
        .catch((e) => setError(e.message));
    }, 200);
    return () => clearTimeout(t);
    // New messages don't change the exchange counters, so refresh on any counter change.
  }, [host, counters?.last_exchange_id, counters?.audit_records]);

  const loadOlder = () =>
    api
      .get<Page>(`/ws/history${qs({ host, before_id: older, limit: 500 })}`)
      .then((p) => {
        setItems((x) => [...x, ...p.messages]);
        setOlder(p.next_before_id);
      })
      .catch((e) => setError(e.message));

  const shown = items.filter(
    (m) => (!dir || m.from === dir) && (!text || (m.text ?? m.hex ?? "").toLowerCase().includes(text.toLowerCase())),
  );

  return (
    <div className="content flush">
      <div className={`history ${sel ? "" : "single"}`}>
        <div className="history-list">
          <div className="filters" role="search">
            <input aria-label="WebSocket host" placeholder="host" value={host} onChange={(e) => setHost(e.target.value)} />
            <select aria-label="Direction" value={dir} onChange={(e) => setDir(e.target.value as typeof dir)}>
              <option value="">both directions</option>
              <option value="client">to server</option>
              <option value="server">to client</option>
            </select>
            <input className="wide" aria-label="Message contains" placeholder="message contains…" value={text} onChange={(e) => setText(e.target.value)} />
          </div>
          <ErrorBox error={error} />
          {shown.length === 0 ? (
            <Empty>No WebSocket messages yet.</Empty>
          ) : (
            <div className="vlist">
              <table className="grid" data-testid="ws-history">
                <thead>
                  <tr><th>#</th><th>Time</th><th>Dir</th><th>URL</th><th>Kind</th><th>Length</th><th>Message</th></tr>
                </thead>
                <tbody>
                  {shown.map((m) => (
                    <tr key={m.id} className={`clickable ${sel?.id === m.id ? "selected" : ""}`} onClick={() => setSel(m)}>
                      <td className="muted">{m.id}</td>
                      <td className="muted">{fmtTime(m.ts_ms)}</td>
                      <td title={m.from === "client" ? "browser → server" : "server → browser"}>{m.from === "client" ? "→" : "←"}</td>
                      <td className="mono">{m.host}{m.path}</td>
                      <td>{m.kind}</td>
                      <td>{m.len}</td>
                      <td className="mono" style={{ maxWidth: 360, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {m.text ?? m.hex}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {older && (
            <div style={{ padding: 8, borderTop: "1px solid var(--border)" }}>
              <button className="btn" onClick={loadOlder}>Load older</button>
            </div>
          )}
        </div>
        {sel && (
          <div className="detail">
            <div className="row small muted">
              <span>message #{sel.id}</span>
              <span>{sel.from === "client" ? "browser → server" : "server → browser"}</span>
              <span>{sel.kind}, {sel.len} bytes{sel.truncated ? " (preview cut)" : ""}</span>
              <span>connection <ExchangeLink id={sel.exchange_id} /></span>
            </div>
            <div className="row" style={{ margin: "8px 0" }}>
              <button className="btn" onClick={() => go("history", sel.exchange_id)}>Open connection (replay, full messages)</button>
            </div>
            <MessageView text={sel.text ?? sel.hex ?? ""} testid="ws-message" />
          </div>
        )}
      </div>
    </div>
  );
}
