import { useState } from "react";
import { api, type ExchangeSummary, type Finding } from "../api";
import { Chip, Empty, ErrorBox, ExchangeLink, Panel, useAction, useNav, usePref } from "../components";

interface Snippet { text: string; start: number; end: number }
interface HttpHit { exchange: ExchangeSummary; part: string; matches: number; snippets: Snippet[] }
interface HttpResult { hits: HttpHit[]; scanned: number; next_before_id?: number }
interface WsHit { id: number; exchange_id: number; ts_ms: number; from_client: boolean; host: string; path: string; len: number; matches: number; snippets: Snippet[] }
interface WsResult { hits: WsHit[]; scanned: number; next_before_id?: number }
interface Issue { check: string; title: string; severity: string; origin: string; path: string; evidence: string; exchange_ids: number[] }

type Where = "http" | "ws" | "findings";

const PARTS = [
  ["both", "requests and responses"],
  ["request", "requests"],
  ["response", "responses"],
  ["headers", "headers (both)"],
  ["bodies", "bodies (both)"],
  ["request_headers", "request headers"],
  ["request_body", "request body"],
  ["response_headers", "response headers"],
  ["response_body", "response body"],
] as const;

function Snip({ s }: { s: Snippet }) {
  const c = [...s.text];
  return (
    <div className="mono small" style={{ wordBreak: "break-all" }}>
      {c.slice(0, s.start).join("")}
      <mark>{c.slice(s.start, s.end).join("")}</mark>
      {c.slice(s.end).join("")}
    </div>
  );
}

/** One search across recorded traffic, WebSocket messages, findings and scanner issues. */
export default function Search() {
  const [query, setQuery] = usePref("search.query", "");
  const [where, setWhere] = usePref<Where>("search.where", "http");
  const [regex, setRegex] = usePref("search.regex", false);
  const [cased, setCased] = usePref("search.case", false);
  const [invert, setInvert] = useState(false);
  const [inScope, setInScope] = usePref("search.scope", false);
  const [part, setPart] = usePref("search.part", "both");
  const [host, setHost] = useState("");
  const [method, setMethod] = useState("");
  const [statusClass, setStatusClass] = useState("");
  const [direction, setDirection] = useState("both");
  const [http, setHttp] = useState<HttpResult | null>(null);
  const [ws, setWs] = useState<WsResult | null>(null);
  const [found, setFound] = useState<{ findings: Finding[]; issues: Issue[] } | null>(null);
  const action = useAction();

  const run = (before?: number) =>
    action.run(async () => {
      if (where === "http") {
        const r = await api.post<HttpResult>("/search", {
          query, regex, case_sensitive: cased, invert, part, before_id: before, max_scan: 20000, limit: 200,
          host: host || undefined, method: method || undefined, status_class: statusClass || undefined,
          in_scope: inScope || undefined,
        });
        setHttp((old) => (before && old ? { ...r, hits: [...old.hits, ...r.hits], scanned: old.scanned + r.scanned } : r));
      } else if (where === "ws") {
        const r = await api.post<WsResult>("/search/ws", {
          query, regex, case_sensitive: cased, invert, direction, before_id: before, max_scan: 50000, limit: 200,
          host: host || undefined, in_scope: inScope || undefined,
        });
        setWs((old) => (before && old ? { ...r, hits: [...old.hits, ...r.hits], scanned: old.scanned + r.scanned } : r));
      } else {
        let re: RegExp;
        try {
          re = new RegExp(regex ? query : query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), cased ? "" : "i");
        } catch (e) {
          throw new Error(`regex: ${(e as Error).message}`);
        }
        const test = (...xs: (string | undefined)[]) => xs.some((x) => x && re.test(x)) !== invert;
        const [findings, issues] = await Promise.all([
          api.get<Finding[]>("/findings"),
          api.get<Issue[]>("/scan/issues?min_severity=info"),
        ]);
        setFound({
          findings: findings.filter((f) => test(f.title, f.description, f.url, f.vuln_class)),
          issues: issues.filter((i) => test(i.title, i.evidence, i.origin + i.path, i.check)),
        });
      }
    });

  return (
    <div className="content">
      <Panel title="Search">
        <form className="row" onSubmit={(e) => { e.preventDefault(); run(); }}>
          <input aria-label="Global search" autoFocus className="grow mono" placeholder="text or regex… (Ctrl+Shift+F from anywhere)" value={query} onChange={(e) => setQuery(e.target.value)} />
          <select aria-label="Search where" value={where} onChange={(e) => setWhere(e.target.value as Where)}>
            <option value="http">HTTP traffic</option>
            <option value="ws">WebSocket messages</option>
            <option value="findings">Findings and scanner issues</option>
          </select>
          <button className="btn primary" disabled={!query || action.busy} data-testid="global-search">{action.busy ? "Searching…" : "Search"}</button>
        </form>
        <div className="row small" style={{ flexWrap: "wrap" }}>
          <label><input type="checkbox" checked={regex} onChange={(e) => setRegex(e.target.checked)} /> regex</label>
          <label><input type="checkbox" checked={cased} onChange={(e) => setCased(e.target.checked)} /> match case</label>
          <label title="Show items that do NOT contain the text"><input type="checkbox" checked={invert} onChange={(e) => setInvert(e.target.checked)} /> not containing</label>
          {where !== "findings" && <label><input type="checkbox" checked={inScope} onChange={(e) => setInScope(e.target.checked)} /> in scope only</label>}
          {where === "http" && (
            <>
              <select aria-label="Search in" value={part} onChange={(e) => setPart(e.target.value)}>
                {PARTS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </select>
              <input aria-label="Search host" placeholder="host" value={host} onChange={(e) => setHost(e.target.value)} style={{ width: 140 }} />
              <input aria-label="Search method" placeholder="method" value={method} onChange={(e) => setMethod(e.target.value.toUpperCase())} style={{ width: 80 }} />
              <select aria-label="Search status" value={statusClass} onChange={(e) => setStatusClass(e.target.value)}>
                <option value="">any status</option>
                <option value="2">2xx</option>
                <option value="3">3xx</option>
                <option value="4">4xx</option>
                <option value="5">5xx</option>
                <option value="4,5">errors (4xx, 5xx)</option>
              </select>
            </>
          )}
          {where === "ws" && (
            <>
              <input aria-label="Search host" placeholder="host" value={host} onChange={(e) => setHost(e.target.value)} style={{ width: 140 }} />
              <select aria-label="Direction" value={direction} onChange={(e) => setDirection(e.target.value)}>
                <option value="both">both directions</option>
                <option value="client">client → server</option>
                <option value="server">server → client</option>
              </select>
            </>
          )}
        </div>
        <p className="small muted">Bodies are searched decoded (gzip, brotli, chunked). Nothing is sent.</p>
        <ErrorBox error={action.error} />
      </Panel>
      {where === "http" && http && <HttpHits r={http} invert={invert} more={() => run(http.next_before_id)} busy={action.busy} />}
      {where === "ws" && ws && <WsHits r={ws} more={() => run(ws.next_before_id)} busy={action.busy} />}
      {where === "findings" && found && <FoundList f={found} />}
    </div>
  );
}

function HttpHits({ r, invert, more, busy }: { r: HttpResult; invert: boolean; more: () => void; busy: boolean }) {
  return (
    <Panel title={`${r.hits.length} result(s) in ${r.scanned} exchange(s)`}>
      <span data-testid="search-summary" hidden>{r.hits.length}</span>
      {r.hits.length === 0 && <Empty>No {invert ? "exchanges without it" : "matches"}.</Empty>}
      {r.hits.map((h) => (
        <div key={`${h.exchange.id}-${h.part}`} data-testid="search-hit" className="search-hit">
          <div className="row small">
            <ExchangeLink id={h.exchange.id} />
            <span className="mono grow" style={{ wordBreak: "break-all" }}>{h.exchange.method} {h.exchange.host}{h.exchange.path}</span>
            {h.exchange.status != null && <span className="muted">{h.exchange.status}</span>}
            {h.part !== "none" && <Chip value={h.part} />}
            {h.part !== "none" && <span className="muted">{h.matches} match{h.matches === 1 ? "" : "es"}</span>}
          </div>
          {h.snippets.map((s, i) => <Snip key={i} s={s} />)}
        </div>
      ))}
      {r.next_before_id && <button className="btn" disabled={busy} onClick={more}>Search older</button>}
    </Panel>
  );
}

function WsHits({ r, more, busy }: { r: WsResult; more: () => void; busy: boolean }) {
  return (
    <Panel title={`${r.hits.length} message(s) of ${r.scanned} searched`}>
      {r.hits.length === 0 && <Empty>No matching messages.</Empty>}
      {r.hits.map((h) => (
        <div key={h.id} className="search-hit" data-testid="ws-hit">
          <div className="row small">
            <span>connection <ExchangeLink id={h.exchange_id} /></span>
            <span className="mono grow">{h.host}{h.path}</span>
            <Chip value={h.from_client ? "client → server" : "server → client"} />
            <span className="muted">{new Date(h.ts_ms).toLocaleTimeString()} · {h.len} B</span>
          </div>
          {h.snippets.map((s, i) => <Snip key={i} s={s} />)}
        </div>
      ))}
      {r.next_before_id && <button className="btn" disabled={busy} onClick={more}>Search older</button>}
    </Panel>
  );
}

function FoundList({ f }: { f: { findings: Finding[]; issues: Issue[] } }) {
  const { go } = useNav();
  return (
    <>
      <Panel title={`Findings (${f.findings.length})`}>
        {f.findings.length === 0 ? <Empty>No matching findings.</Empty> : (
          <ul className="small">
            {f.findings.map((x) => (
              <li key={x.id}>
                <a href="#" onClick={(e) => { e.preventDefault(); go("findings", x.id); }}>#{x.id} {x.title}</a>{" "}
                <Chip value={x.severity} /> <Chip value={x.status} /> <span className="muted mono">{x.url}</span>
              </li>
            ))}
          </ul>
        )}
      </Panel>
      <Panel title={`Scanner issues (${f.issues.length})`}>
        {f.issues.length === 0 ? <Empty>No matching issues.</Empty> : (
          <ul className="small">
            {f.issues.map((x, i) => (
              <li key={i}>
                <strong>{x.title}</strong> <Chip value={x.severity} /> <span className="mono">{x.origin}{x.path}</span>{" "}
                {x.exchange_ids.slice(0, 3).map((id) => <ExchangeLink key={id} id={id} />)}
                <div className="muted mono">{x.evidence}</div>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </>
  );
}
