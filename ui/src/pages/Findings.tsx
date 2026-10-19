import { useState } from "react";
import { api, fmtDateTime, type Finding, type IdentityInfo, type ProofResult } from "../api";
import { Chip, Empty, ErrorBox, ExchangeLink, Panel, useAction, useLoad, useNav } from "../components";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export default function Findings() {
  const { arg, go, counters } = useNav();
  const list = useLoad(() => api.get<Finding[]>("/findings"), [counters?.findings, counters?.audit_records]);
  const selected = arg ? Number(arg) : undefined;
  const [creating, setCreating] = useState(false);
  const sorted = [...(list.data ?? [])].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.id - a.id,
  );

  return (
    <div className="content">
      <div className="split">
        <Panel
          title="Findings"
          actions={
            <>
              <a className="btn" href="/api/v1/report" download="proxymind-report.md" style={{ textDecoration: "none", padding: "6px 12px", border: "1px solid var(--border)", borderRadius: 6 }}>
                Download report
              </a>
              <button className="btn primary" onClick={() => setCreating((c) => !c)}>New finding</button>
            </>
          }
        >
          <ErrorBox error={list.error} />
          {creating && <NewFinding onDone={(id) => { setCreating(false); list.reload(); go("findings", id); }} />}
          {sorted.length === 0 && !creating && <Empty>No findings yet.</Empty>}
          {sorted.length > 0 && (
            <table className="grid" data-testid="findings">
              <thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Status</th></tr></thead>
              <tbody>
                {sorted.map((f) => (
                  <tr key={f.id} className="clickable" onClick={() => go("findings", f.id)} style={selected === f.id ? { background: "var(--accent-soft)" } : undefined}>
                    <td className="muted">{f.id}</td>
                    <td><Chip value={f.severity} /></td>
                    <td>{f.title}<div className="small muted mono">{f.url}</div></td>
                    <td><Chip value={f.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
        {selected ? <FindingDetail key={selected} id={selected} onChange={list.reload} /> : <Panel><Empty>Select a finding.</Empty></Panel>}
      </div>
    </div>
  );
}

function NewFinding({ onDone }: { onDone: (id: number) => void }) {
  const [f, setF] = useState({ title: "", vuln_class: "idor", severity: "medium", description: "", evidence: "" });
  const action = useAction();
  const save = () =>
    action.run(async () => {
      const evidence = f.evidence.split(/[ ,]+/).filter(Boolean).map(Number);
      const created = await api.post<Finding>("/findings", { ...f, evidence });
      onDone(created.id);
    });
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) =>
    setF((x) => ({ ...x, [k]: e.target.value }));
  return (
    <div className="panel" style={{ background: "var(--panel-2)" }}>
      <div className="row">
        <input aria-label="Title" className="grow" placeholder="Title" value={f.title} onChange={set("title")} />
        <select aria-label="Class" value={f.vuln_class} onChange={set("vuln_class")}>
          {["idor", "bfla", "authn", "sqli", "xss", "ssrf", "mass_assignment", "business_logic", "other"].map((c) => <option key={c}>{c}</option>)}
        </select>
        <select aria-label="Severity" value={f.severity} onChange={set("severity")}>
          {SEVERITY_ORDER.map((c) => <option key={c}>{c}</option>)}
        </select>
      </div>
      <textarea aria-label="Description" rows={3} placeholder="What is wrong, impact, how to reproduce" value={f.description} onChange={set("description")} style={{ marginTop: 6 }} />
      <div className="row" style={{ marginTop: 6 }}>
        <input aria-label="Evidence" className="grow" placeholder="Evidence exchange ids, e.g. 12, 15" value={f.evidence} onChange={set("evidence")} />
        <button className="btn primary" disabled={!f.title || !f.evidence || action.busy} onClick={save}>Save</button>
      </div>
      <ErrorBox error={action.error} />
    </div>
  );
}

function FindingDetail({ id, onChange }: { id: number; onChange: () => void }) {
  const f = useLoad(() => api.get<Finding>(`/findings/${id}`), [id]);
  const ids = useLoad(() => api.get<IdentityInfo[]>("/identities"), []);
  const [attacker, setAttacker] = useState("");
  const [exchange, setExchange] = useState("");
  const [result, setResult] = useState<ProofResult | null>(null);
  const [xss, setXss] = useState<{ url: string; raw: string } | null>(null);
  const action = useAction();

  if (f.error) return <Panel><ErrorBox error={f.error} /></Panel>;
  if (!f.data) return <Panel><span className="muted">Loading…</span></Panel>;
  const d = f.data;
  const ex = exchange || String(d.evidence[0] ?? "");

  const setStatus = (status: string) =>
    action.run(async () => {
      await api.patch(`/findings/${id}`, { id, status });
      f.reload();
      onChange();
    });
  const prove = () =>
    action.run(async () => {
      const r = await api.post<ProofResult>("/proofs", { oracle: "differential_authz", exchange_id: Number(ex), attacker, finding_id: id });
      setResult(r);
      f.reload();
      onChange();
    });
  const xssForm = xss ?? xssTemplate(d.url);
  const proveXss = () =>
    action.run(async () => {
      const r = await api.post<ProofResult>("/proofs", { oracle: "reflection", url: xssForm.url, raw: xssForm.raw, finding_id: id });
      setResult(r);
      f.reload();
      onChange();
    });
  const rerun = (proofId: number) =>
    action.run(async () => {
      setResult(await api.post<ProofResult>(`/proofs/${proofId}/rerun`));
      f.reload();
    });

  return (
    <Panel title={<>#{d.id} {d.title}</>}>
      <div className="row small" style={{ marginBottom: 8 }}>
        <Chip value={d.severity} />
        <Chip value={d.status} />
        <span className="muted">{d.vuln_class}</span>
        <span className="muted">by {d.actor} · {fmtDateTime(d.created_ms)}</span>
      </div>
      <div className="mono small" style={{ wordBreak: "break-all" }}>{d.url}</div>
      <p style={{ whiteSpace: "pre-wrap" }}>{d.description || <span className="muted">No description.</span>}</p>
      <div className="small">Evidence: {d.evidence.length ? d.evidence.map((e) => <span key={e}><ExchangeLink id={e} /> </span>) : "–"}</div>

      <h3>Proofs</h3>
      {d.proofs?.length ? (
        d.proofs.map((p) => (
          <div key={p.proof_id} className="panel" style={{ background: "var(--panel-2)" }} data-testid={`proof-${p.proof_id}`}>
            <div className="row">
              <Chip value={p.proven ? "proven" : "not proven"} />
              <strong className="grow">{p.oracle}</strong>
              <span className="small muted">{p.confidence} confidence · #{p.proof_id}</span>
              <button className="btn" disabled={action.busy} onClick={() => rerun(p.proof_id)}>Re-run</button>
            </div>
            <ul className="small">{p.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
            <div className="small muted">Requests: {p.exchange_ids.map((e) => <span key={e}><ExchangeLink id={e} /> </span>)}</div>
          </div>
        ))
      ) : (
        <p className="muted small">Not proven yet. A finding becomes proven only when ProxyMind verifies it.</p>
      )}

      <div className="row" style={{ marginTop: 8 }}>
        <span className="small">Prove access control: replay</span>
        <input aria-label="Owner exchange" value={ex} onChange={(e) => setExchange(e.target.value)} style={{ width: 70 }} />
        <span className="small">as</span>
        <select aria-label="Attacker" value={attacker} onChange={(e) => setAttacker(e.target.value)}>
          <option value="">choose identity…</option>
          {ids.data?.map((i) => <option key={i.name} value={i.name}>{i.name}</option>)}
        </select>
        <button className="btn primary" disabled={!attacker || !ex || action.busy} onClick={prove} data-testid="prove">
          {action.busy ? "Proving…" : "Prove"}
        </button>
      </div>
      <details style={{ marginTop: 8 }} open={d.vuln_class.toLowerCase().includes("xss")}>
        <summary className="small">Prove XSS in a headless browser</summary>
        <p className="small muted">
          Put <code>{"{{xss_url}}"}</code> (percent-encoded payload), <code>{"{{xss}}"}</code> (as is) or <code>{"{{token}}"}</code> (in
          your own payload calling <code>pmProof()</code> or <code>alert()</code>) where the payload goes. The recorded response is
          rendered offline with every other request blocked; it is proven only if the script runs.
        </p>
        <div className="row">
          <input aria-label="XSS target" className="grow mono" placeholder="http://host:port" value={xssForm.url}
            onChange={(e) => setXss({ ...xssForm, url: e.target.value })} />
          <button className="btn primary" disabled={!xssForm.url || !xssForm.raw || action.busy} onClick={proveXss} data-testid="prove-xss">
            {action.busy ? "Proving…" : "Prove XSS"}
          </button>
        </div>
        <textarea aria-label="XSS request" className="mono" rows={4} value={xssForm.raw} style={{ marginTop: 6, width: "100%" }}
          onChange={(e) => setXss({ ...xssForm, raw: e.target.value })} />
      </details>
      {result?.status === "completed" && (
        <div className={result.proven ? "notice" : "error"} data-testid="proof-result">
          {result.proven ? "Proven" : "Not proven"} ({result.confidence}): {result.reasons.join(" · ")}
        </div>
      )}
      {result && result.status !== "completed" && <div className="error">{result.status}: {result.reasons.join("; ")}</div>}
      <ErrorBox error={action.error} />

      <h3>Decision</h3>
      <div className="row">
        <button className="btn" onClick={() => setStatus("confirmed")} disabled={action.busy}>Confirm</button>
        <button className="btn" onClick={() => setStatus("false_positive")} disabled={action.busy}>False positive</button>
        <button className="btn" onClick={() => setStatus("reported")} disabled={action.busy}>Reported</button>
        <button className="btn" onClick={() => setStatus("suspected")} disabled={action.busy}>Back to suspected</button>
      </div>
    </Panel>
  );
}

/** A starting point for an XSS proof: the finding's URL with its first query value (or a new q) as the payload. */
function xssTemplate(findingUrl: string): { url: string; raw: string } {
  try {
    const u = new URL(findingUrl);
    const pairs = u.search.slice(1).split("&").filter(Boolean);
    const query = pairs.length
      ? [`${pairs[0].split("=")[0]}={{xss_url}}`, ...pairs.slice(1)].join("&")
      : "q={{xss_url}}";
    return { url: u.origin, raw: `GET ${u.pathname}?${query} HTTP/1.1\nHost: ${u.host}\n\n` };
  } catch {
    return { url: "", raw: "GET /?q={{xss_url}} HTTP/1.1\nHost: x\n\n" };
  }
}
