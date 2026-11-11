import { useEffect, useState } from "react";
import { api, toast } from "./api";
import { Chip, Empty, ErrorBox, Panel } from "./components";

interface Step { text: string; finding_id?: number; exchange_id?: number }
interface Path { id: number; scan_id: number | null; title: string; impact: string; severity: string; steps: Step[]; actor: string; created_ms: number }
interface Node { id: string; label: string; finding_id?: number; severity?: string; depth: number; impact: boolean }
interface Edge { from: string; to: string; paths: number[] }
interface Graph { nodes: Node[]; edges: Edge[]; paths: Path[] }

const W = 190, H = 54, GX = 70, GY = 22, PAD = 12;
const color = (sev?: string) =>
  sev === "critical" ? "var(--crit)" : sev === "high" ? "var(--bad)" : sev === "medium" ? "var(--warn)" : sev === "low" ? "var(--info)" : "var(--border-strong)";

/** A step's node id (the same rule as the server's graph). */
const keyOf = (s: Step) => (s.finding_id ? `finding:${s.finding_id}` : `step:${s.text.trim().split(/\s+/).join(" ").toLowerCase()}`);

/** Splits a label into at most two lines that fit a node. */
function lines(label: string): string[] {
  const max = 27;
  if (label.length <= max) return [label];
  const cut = label.lastIndexOf(" ", max);
  const first = label.slice(0, cut > 10 ? cut : max);
  const rest = label.slice(first.length).trim();
  return [first, rest.length > max ? `${rest.slice(0, max - 1)}…` : rest];
}

/** Attack paths as a graph (entry points on the left, impact on the right), with the paths listed below. */
export function AttackGraph({ scan, refresh, title = "Attack paths" }: { scan?: number; refresh?: unknown; title?: string }) {
  const [g, setG] = useState<Graph | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hover, setHover] = useState<number | null>(null);
  const load = () =>
    api.get<Graph>(`/attack-graph${scan !== undefined ? `?scan=${scan}` : ""}`).then((r) => { setG(r); setError(null); }).catch((e: Error) => setError(e.message));
  useEffect(() => { void load(); }, [scan, refresh]); // eslint-disable-line react-hooks/exhaustive-deps
  if (error) return <ErrorBox error={error} />;
  if (!g || g.paths.length === 0) return scan === undefined ? null : (
    <Panel title={title}><Empty>No attack paths yet: the agent records them in the chaining phase.</Empty></Panel>
  );

  const columns: Node[][] = [];
  for (const n of g.nodes) (columns[n.depth] ??= []).push(n);
  const pos = new Map<string, { x: number; y: number }>();
  columns.forEach((col, d) => col.forEach((n, i) => pos.set(n.id, { x: PAD + d * (W + GX), y: PAD + i * (H + GY) })));
  const width = PAD * 2 + columns.length * W + (columns.length - 1) * GX;
  const height = PAD * 2 + Math.max(...columns.map((c) => c.length)) * (H + GY) - GY;
  const remove = async (id: number) => {
    if (!confirm(`Delete attack path #${id}?`)) return;
    await api.del(`/attack-paths/${id}`);
    toast("Attack path deleted");
    void load();
  };

  return (
    <Panel title={title}>
      <div style={{ overflowX: "auto" }}>
        <svg width={width} height={height} role="img" aria-label="Attack graph" data-testid="attack-graph" style={{ display: "block" }}>
          <defs>
            <marker id="ag-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" fill="var(--muted)" />
            </marker>
          </defs>
          {g.edges.map((e, i) => {
            const a = pos.get(e.from), b = pos.get(e.to);
            if (!a || !b) return null;
            const x1 = a.x + W, y1 = a.y + H / 2, x2 = b.x, y2 = b.y + H / 2;
            const back = x2 <= x1;
            const d = back
              ? `M${x1},${y1} C${x1 + 40},${y1 - 60} ${x2 - 40},${y2 - 60} ${x2},${y2}`
              : `M${x1},${y1} C${(x1 + x2) / 2},${y1} ${(x1 + x2) / 2},${y2} ${x2},${y2}`;
            const lit = hover !== null && e.paths.includes(hover);
            return (
              <path key={i} d={d} fill="none" markerEnd="url(#ag-arrow)"
                stroke={lit ? "var(--accent)" : "var(--muted)"} strokeWidth={lit ? 2.5 : 1.2 + Math.min(e.paths.length - 1, 3) * 0.6} />
            );
          })}
          {g.nodes.map((n) => {
            const p = pos.get(n.id)!;
            const lit = hover !== null && !!g.paths.find((x) => x.id === hover)?.steps.some((s) => keyOf(s) === n.id);
            return (
              <g key={n.id} transform={`translate(${p.x},${p.y})`} style={{ cursor: n.finding_id ? "pointer" : "default" }}
                onClick={() => { if (n.finding_id) location.hash = `#/findings/${n.finding_id}`; }}>
                <title>{n.label}{n.finding_id ? ` (finding #${n.finding_id})` : ""}</title>
                <rect width={W} height={H} rx={8} fill={n.impact ? "var(--bad-soft)" : "var(--panel-2)"}
                  stroke={lit ? "var(--accent)" : color(n.severity)} strokeWidth={n.finding_id || lit ? 2 : 1} />
                {lines(n.label).map((t, i, all) => (
                  <text key={i} x={10} y={H / 2 + (i - (all.length - 1) / 2) * 15 + 4} fontSize={12} fill="var(--text)">{t}</text>
                ))}
                {n.finding_id && <text x={W - 8} y={13} fontSize={10} textAnchor="end" fill="var(--muted)">#{n.finding_id}</text>}
              </g>
            );
          })}
        </svg>
      </div>
      <p className="small muted">Entry points on the left; red boxes end a path (the impact). Coloured borders are findings (by severity): click one to open it. Hover a path below to highlight it.</p>
      <table className="grid" data-testid="attack-path-list">
        <thead><tr><th>#</th><th>Severity</th><th>Path</th><th>Impact</th><th>By</th><th></th></tr></thead>
        <tbody>
          {g.paths.map((p) => (
            <tr key={p.id} onMouseEnter={() => setHover(p.id)} onMouseLeave={() => setHover(null)}>
              <td>{p.id}</td>
              <td><Chip value={p.severity} /></td>
              <td className="small"><b>{p.title}</b><div className="muted">{p.steps.map((s) => s.text).join(" → ")}</div></td>
              <td className="small">{p.impact}</td>
              <td className="small mono">{p.actor}</td>
              <td><button className="btn sm" onClick={() => void remove(p.id)}>Delete</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  );
}
