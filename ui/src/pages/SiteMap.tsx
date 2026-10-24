import { useState } from "react";
import { api, type ExchangeSummary } from "../api";
import { Chip, Empty, ErrorBox, ExchangeLink, Panel, useAction, useLoad } from "../components";

interface SiteNode {
  name: string;
  path: string;
  requests: number;
  total: number;
  methods: string[];
  statuses: number[];
  queries: number;
  latest_id?: number;
  children: SiteNode[];
}

interface Site {
  origin: string;
  total: number;
  in_scope: boolean;
  root: SiteNode;
}

interface Snippet {
  text: string;
  start: number;
  end: number;
}

interface SearchResult {
  hits: { exchange: ExchangeSummary; part: string; matches: number; snippets: Snippet[] }[];
  scanned: number;
  next_before_id?: number;
}

/** Recorded traffic as a tree, and a search through request and response contents. */
export default function SiteMap() {
  const [host, setHost] = useState("");
  const sites = useLoad(() => api.get<Site[]>(`/sitemap${host ? `?host=${encodeURIComponent(host)}` : ""}`), [host]);
  return (
    <div className="content">
      <div className="split">
        <Panel title="Site map">
          <input aria-label="Site map host" placeholder="host contains…" value={host} onChange={(e) => setHost(e.target.value)} style={{ marginBottom: 8 }} />
          <ErrorBox error={sites.error} />
          {sites.data?.length === 0 && <Empty>No traffic recorded yet.</Empty>}
          <div className="tree mono small" data-testid="sitemap">
            {sites.data?.map((s) => (
              <details key={s.origin} open={sites.data!.length < 4}>
                <summary>
                  <strong>{s.origin}</strong> <span className="muted">{s.total}</span> {s.in_scope ? <Chip value="in scope" /> : <span className="muted small">out of scope</span>}
                </summary>
                <Tree node={s.root} />
              </details>
            ))}
          </div>
        </Panel>
        <Search />
      </div>
    </div>
  );
}

function Tree({ node }: { node: SiteNode }) {
  return (
    <ul style={{ listStyle: "none", paddingLeft: 14, margin: 0 }}>
      {node.requests > 0 && node.path === "/" && <Leaf node={node} />}
      {node.children.map((c) => (
        <li key={c.path}>
          {c.children.length ? (
            <details>
              <summary><Leaf node={c} /></summary>
              <Tree node={c} />
            </details>
          ) : (
            <Leaf node={c} />
          )}
        </li>
      ))}
    </ul>
  );
}

function Leaf({ node }: { node: SiteNode }) {
  return (
    <span data-testid="sitemap-node" data-path={node.path}>
      {node.name}
      {node.requests > 0 && (
        <span className="muted">
          {"  "}{node.methods.join(",")} {node.statuses.join(",")}
          {node.queries > 0 && ` ?×${node.queries}`} <ExchangeLink id={node.latest_id} />
        </span>
      )}
      {node.children.length > 0 && <span className="muted"> ({node.total})</span>}
    </span>
  );
}

function Search() {
  const [query, setQuery] = useState("");
  const [regex, setRegex] = useState(false);
  const [cased, setCased] = useState(false);
  const [part, setPart] = useState("both");
  const [result, setResult] = useState<SearchResult | null>(null);
  const action = useAction();

  const run = (before?: number) =>
    action.run(async () => {
      const r = await api.post<SearchResult>("/search", { query, regex, case_sensitive: cased, part, before_id: before, max_scan: 20000 });
      setResult((old) => (before && old ? { ...r, hits: [...old.hits, ...r.hits], scanned: old.scanned + r.scanned } : r));
    });

  return (
    <Panel title="Search contents">
      <form className="row" onSubmit={(e) => { e.preventDefault(); run(); }}>
        <input aria-label="Search text" className="grow mono" placeholder="text in requests or responses…" value={query} onChange={(e) => setQuery(e.target.value)} />
        <select aria-label="Search in" value={part} onChange={(e) => setPart(e.target.value)}>
          <option value="both">requests and responses</option>
          <option value="request">requests</option>
          <option value="response">responses</option>
        </select>
        <label className="small"><input type="checkbox" checked={regex} onChange={(e) => setRegex(e.target.checked)} /> regex</label>
        <label className="small"><input type="checkbox" checked={cased} onChange={(e) => setCased(e.target.checked)} /> match case</label>
        <button className="btn primary" disabled={!query || action.busy} data-testid="search">Search</button>
      </form>
      <ErrorBox error={action.error} />
      {result && (
        <>
          <p className="small muted" data-testid="search-summary">
            {result.hits.length} hit(s) in {result.scanned} exchange(s). Bodies are searched decoded (gzip, chunked).
          </p>
          {result.hits.map((h) => (
            <div key={`${h.exchange.id}-${h.part}`} data-testid="search-hit" style={{ marginBottom: 6, padding: 6, border: "1px solid var(--border)", borderRadius: 6 }}>
              <div className="row small">
                <ExchangeLink id={h.exchange.id} />
                <span className="mono grow" style={{ wordBreak: "break-all" }}>{h.exchange.method} {h.exchange.host}{h.exchange.path}</span>
                <Chip value={h.part} />
                <span className="muted">{h.matches} match{h.matches === 1 ? "" : "es"}</span>
              </div>
              {h.snippets.map((s, i) => {
                const c = [...s.text];
                return (
                  <div key={i} className="mono small" style={{ wordBreak: "break-all" }}>
                    {c.slice(0, s.start).join("")}<mark>{c.slice(s.start, s.end).join("")}</mark>{c.slice(s.end).join("")}
                  </div>
                );
              })}
            </div>
          ))}
          {result.next_before_id && (
            <button className="btn" disabled={action.busy} onClick={() => run(result.next_before_id)}>Search older</button>
          )}
        </>
      )}
    </Panel>
  );
}
