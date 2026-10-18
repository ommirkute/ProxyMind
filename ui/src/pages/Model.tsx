import { useState } from "react";
import { api, type Coverage, type ModelObject, type Operation } from "../api";
import { Chip, Empty, ErrorBox, ExchangeLink, Panel, useLoad, useNav } from "../components";

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
