import { useState } from "react";
import { api, type Coverage, type ModelObject, type Operation } from "../api";
import { Chip, Empty, ErrorBox, ExchangeLink, Panel, StatusCode, useAction, useLoad, useNav } from "../components";

interface ModelResponse {
  operations: Operation[];
  object_counts: Record<string, number>;
  objects?: ModelObject[];
}

export default function Model() {
  const { counters } = useNav();
  const [filter, setFilter] = useState("");
  const [showObjects, setShowObjects] = useState(false);
  const model = useLoad(
    () => api.get<ModelResponse>(`/model?include_objects=${showObjects}`),
    [showObjects, counters?.exchanges],
  );
  const [allCells, setAllCells] = useState(false);
  const coverage = useLoad(() => api.get<Coverage>(`/coverage?all=${allCells}`), [allCells, counters?.audit_records]);

  const ops = model.data?.operations.filter((o) => o.key.toLowerCase().includes(filter.toLowerCase())) ?? [];

  return (
    <div className="content">
      <CrawlPanel />
      <OpenApiPanel />
      <Panel
        title="Operations"
        actions={
          <>
            <input aria-label="Filter operations" placeholder="filter…" value={filter} onChange={(e) => setFilter(e.target.value)} />
            <label className="row small"><input type="checkbox" checked={showObjects} onChange={(e) => setShowObjects(e.target.checked)} /> objects</label>
          </>
        }
      >
        <ErrorBox error={model.error} />
        {model.data && ops.length === 0 && <Empty>No operations yet: record some traffic first.</Empty>}
        {ops.length > 0 && (
          <table className="grid" data-testid="operations">
            <thead>
              <tr><th>Method</th><th>Operation</th><th>Kind</th><th>Seen</th><th>Statuses</th><th>Identities</th><th>Params</th><th>Example</th></tr>
            </thead>
            <tbody>
              {ops.map((o) => (
                <tr key={o.key}>
                  <td>{o.method}</td>
                  <td className="mono small">{o.origin}<strong>{o.template}</strong></td>
                  <td><Chip value={o.kind} /></td>
                  <td>{o.count}</td>
                  <td className="small">{Object.entries(o.statuses).map(([k, v]) => `${k}×${v}`).join(" ")}</td>
                  <td className="small">{o.identities.join(", ") || <span className="muted">–</span>}</td>
                  <td className="small mono">{[...o.query_params, ...o.body_params].join(", ")}</td>
                  <td><ExchangeLink id={o.examples[o.examples.length - 1]} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {showObjects && model.data?.objects && (
          <>
            <h3>Objects ({Object.entries(model.data.object_counts).map(([k, v]) => `${v} ${k}`).join(", ")})</h3>
            <table className="grid">
              <thead><tr><th>Type</th><th>Id</th><th>Owner</th><th>Known from</th><th>Read by</th></tr></thead>
              <tbody>
                {model.data.objects.map((o) => (
                  <tr key={`${o.object_type}-${o.id}`}>
                    <td>{o.object_type}</td>
                    <td className="mono">{o.id}</td>
                    <td>{o.owner ?? <span className="muted">unknown</span>}</td>
                    <td className="small muted">{o.owner_source ?? "–"}</td>
                    <td className="small">{o.accessed_by.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </Panel>

      <Panel
        title="Coverage"
        actions={<label className="row small"><input type="checkbox" checked={allCells} onChange={(e) => setAllCells(e.target.checked)} /> include finished</label>}
      >
        <ErrorBox error={coverage.error} />
        {coverage.data && (
          <>
            <div className="row small" style={{ marginBottom: 6 }}>
              <strong>{coverage.data.percent_tested}% tested</strong>
              {Object.entries(coverage.data.totals).map(([k, v]) => (
                <span key={k}><Chip value={k} /> {v}</span>
              ))}
            </div>
            <div className="bar" style={{ marginBottom: 12 }}><div style={{ width: `${coverage.data.percent_tested}%` }} /></div>
            {coverage.data.cells.length === 0 ? (
              <Empty>Nothing left to test (or no operations yet).</Empty>
            ) : (
              <table className="grid" data-testid="coverage">
                <thead><tr><th>Status</th><th>Class</th><th>Operation</th><th>Parameter</th><th>Hypotheses</th></tr></thead>
                <tbody>
                  {coverage.data.cells.map((c) => (
                    <tr key={`${c.operation}|${c.vuln_class}|${c.param}`}>
                      <td><Chip value={c.status} /></td>
                      <td>{c.vuln_class}</td>
                      <td className="mono small">{c.operation}</td>
                      <td className="mono small">{c.param || "–"}</td>
                      <td className="small">{c.hypotheses?.map((h) => `#${h}`).join(" ") || "–"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </Panel>
    </div>
  );
}

type CrawlResult =
  | {
      status: "done";
      pages: { url: string; depth: number; exchange_id: number; status?: number; content_type?: string; links_found: number }[];
      forms: { page: string; method: string; action: string; inputs: string[] }[];
      skipped: { url: string; reason: string }[];
      skipped_total: number;
      not_visited: number;
    }
  | { status: "pending_approval"; approval_id: string; summary: string; reasons: string[] }
  | { status: "denied"; reasons: string[] };

/** Discover pages: GET only, in scope only, never links that log out or delete. */
function CrawlPanel() {
  const [url, setUrl] = useState("");
  const [maxPages, setMaxPages] = useState(50);
  const [result, setResult] = useState<CrawlResult | null>(null);
  const [open, setOpen] = useState(false);
  const action = useAction();
  const run = () =>
    action.run(async () => {
      setResult(await api.post<CrawlResult>("/crawl", { url, max_pages: maxPages }));
    });
  return (
    <Panel
      title="Crawl"
      actions={<button className="btn" onClick={() => setOpen((o) => !o)}>{open ? "Hide" : "Discover pages…"}</button>}
    >
      {open && (
        <>
          <div className="row">
            <input aria-label="Crawl start URL" className="grow mono" placeholder="https://app.example.com/" value={url} onChange={(e) => setUrl(e.target.value)} />
            <input aria-label="Max pages" type="number" min={1} max={500} value={maxPages} onChange={(e) => setMaxPages(Number(e.target.value))} style={{ width: 80 }} />
            <button className="btn primary" disabled={!url || action.busy} onClick={run} data-testid="crawl-run">{action.busy ? "Crawling…" : "Crawl"}</button>
          </div>
          <p className="small muted">GET requests only, in scope only; links that look like log out or delete are skipped, forms are listed but never submitted.</p>
          <ErrorBox error={action.error} />
          {result?.status === "pending_approval" && <div className="notice">Needs approval: {result.summary}</div>}
          {result?.status === "denied" && <div className="error">Denied: {result.reasons.join("; ")}</div>}
          {result?.status === "done" && (
            <>
              <div className="small" data-testid="crawl-summary">
                {result.pages.length} pages · {result.forms.length} forms · {result.skipped_total} skipped · {result.not_visited} not visited
              </div>
              <table className="grid small">
                <thead><tr><th>Status</th><th>URL</th><th>Type</th><th>Links</th><th></th></tr></thead>
                <tbody>
                  {result.pages.map((p) => (
                    <tr key={p.exchange_id}>
                      <td><StatusCode status={p.status ?? null} /></td>
                      <td className="mono">{p.url}</td>
                      <td className="muted">{p.content_type?.split(";")[0]}</td>
                      <td>{p.links_found}</td>
                      <td><ExchangeLink id={p.exchange_id} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {result.forms.length > 0 && (
                <ul className="small">{result.forms.map((f) => <li key={f.method + f.action}><Chip value={f.method} /> <span className="mono">{f.action}</span> ({f.inputs.join(", ") || "no fields"})</li>)}</ul>
              )}
              {result.skipped.length > 0 && (
                <details className="small"><summary>Skipped links</summary>
                  <ul>{result.skipped.map((s) => <li key={s.url}><span className="mono">{s.url}</span>: {s.reason}</li>)}</ul>
                </details>
              )}
            </>
          )}
        </>
      )}
    </Panel>
  );
}

interface ApiOperation { method: string; path: string; summary?: string; auth: boolean; example_request: string }
type ImportResult =
  | { status: "imported"; title: string; version: string; base_url?: string; operations: ApiOperation[]; sent: { method: string; path: string; exchange_id: number; status?: number }[]; skipped: string[] }
  | { status: "pending_approval"; summary: string }
  | { status: "denied"; reasons: string[] };

/** Import an OpenAPI / Swagger description from a recorded response or pasted text. */
function OpenApiPanel() {
  const [open, setOpen] = useState(false);
  const [exchange, setExchange] = useState("");
  const [spec, setSpec] = useState("");
  const [send, setSend] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);
  const action = useAction();
  const run = () =>
    action.run(async () => {
      const body = exchange ? { exchange_id: Number(exchange), send_examples: send } : { spec, send_examples: send };
      setResult(await api.post<ImportResult>("/openapi/import", body));
    });
  return (
    <Panel title="API description" actions={<button className="btn" onClick={() => setOpen((o) => !o)}>{open ? "Hide" : "Import OpenAPI…"}</button>}>
      {open && (
        <>
          <div className="row">
            <span className="small">From recorded exchange</span>
            <input aria-label="Spec exchange" value={exchange} onChange={(e) => setExchange(e.target.value)} placeholder="id" style={{ width: 70 }} />
            <span className="small muted">or paste the spec below</span>
            <label className="small"><input type="checkbox" checked={send} onChange={(e) => setSend(e.target.checked)} /> send GET examples (in scope only)</label>
            <button className="btn primary" disabled={(!exchange && !spec) || action.busy} onClick={run} data-testid="openapi-import">{action.busy ? "Importing…" : "Import"}</button>
          </div>
          {!exchange && <textarea aria-label="OpenAPI spec" className="mono" rows={4} value={spec} onChange={(e) => setSpec(e.target.value)} placeholder="JSON or YAML" style={{ width: "100%", marginTop: 6 }} />}
          <ErrorBox error={action.error} />
          {result?.status === "pending_approval" && <div className="notice">Needs approval: {result.summary}</div>}
          {result?.status === "denied" && <div className="error">Denied: {result.reasons.join("; ")}</div>}
          {result?.status === "imported" && (
            <>
              <div className="small" data-testid="openapi-summary">
                {result.title} {result.version}: {result.operations.length} operations{result.sent.length ? `, ${result.sent.length} examples sent` : ""}
              </div>
              <table className="grid small">
                <thead><tr><th>Method</th><th>Path</th><th>Auth</th><th>Summary</th><th>Sent</th></tr></thead>
                <tbody>
                  {result.operations.map((o) => {
                    const sent = result.sent.find((x) => x.method === o.method && x.path === o.path);
                    return (
                      <tr key={o.method + o.path} title={o.example_request}>
                        <td><Chip value={o.method} /></td>
                        <td className="mono">{o.path}</td>
                        <td>{o.auth ? "yes" : "no"}</td>
                        <td className="muted">{o.summary}</td>
                        <td>{sent ? <><StatusCode status={sent.status ?? null} /> <ExchangeLink id={sent.exchange_id} /></> : "–"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </>
          )}
        </>
      )}
    </Panel>
  );
}
