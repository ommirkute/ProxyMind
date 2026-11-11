import { useEffect, useState } from "react";
import { api, toast } from "../api";
import { Chip, Empty, ErrorBox, Panel, copyText, useAction } from "../components";

interface Check { name: string; ok: boolean; detail: string }
interface Verification {
  ok: boolean; fingerprint?: string | null; engagement: { name?: string | null; client?: string | null } | null;
  checks: Check[]; findings: number; exchanges: number;
}
interface Cell { operation: string; vuln_class: string; param?: string; status: string; by?: string[]; how?: string[]; findings?: number[] }
interface CoverageProof { operations: number; cells: Cell[]; totals: Record<string, number>; percent_tested: number }

/** Verifiable evidence: a signed pack for the client, its verifier, and the coverage proof. */
export default function Evidence() {
  return (
    <div className="content">
      <Export />
      <Verify />
      <Coverage />
    </div>
  );
}

function Export() {
  const [fp, setFp] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [all, setAll] = useState(false);
  useEffect(() => {
    api.get<{ fingerprint: string }>("/evidence/fingerprint").then((r) => setFp(r.fingerprint)).catch((e: Error) => setError(e.message));
  }, []);
  return (
    <Panel
      title="Evidence pack"
      actions={<>
        <label className="small"><input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> include all in-scope traffic</label>
        <a className="btn primary" href={`/api/v1/evidence/pack${all ? "?all=true" : ""}`} download="proxymind-evidence.zip" data-testid="evidence-download">Download pack</a>
      </>}
    >
      <p className="small muted">
        One ZIP for the client: the report, the exact request and response bytes behind every finding, the proofs, the
        hash-chained audit log, the rules of engagement and the coverage proof, with a manifest signed by this
        installation's key. The client checks it with <code>proxymind verify pack.zip</code> (or the box below): nothing
        changed since you signed it, the audit chain is intact, every request ProxyMind's tools sent was in scope, and each
        finding's evidence is there.
      </p>
      <ErrorBox error={error} />
      {fp && (
        <p className="small" data-testid="evidence-fingerprint">
          Your signing key: <code>{fp}</code>{" "}
          <button className="btn sm" onClick={() => { copyText(fp); toast("Fingerprint copied"); }}>Copy</button>
          <span className="muted"> · Send it to the client separately (email, chat) so they can tell your packs from anyone else's.</span>
        </p>
      )}
    </Panel>
  );
}

function Verify() {
  const [v, setV] = useState<Verification | null>(null);
  const action = useAction();
  const verify = (file: File) =>
    action.run(async () => {
      const res = await fetch("/api/v1/evidence/verify", { method: "POST", body: await file.arrayBuffer(), headers: { "content-type": "application/zip", "X-ProxyMind": "1" }, credentials: "same-origin" });
      if (!res.ok) throw new Error(`verify failed: ${res.status} ${await res.text()}`);
      setV(await res.json());
    });
  return (
    <Panel title="Verify a pack">
      <p className="small muted">Check an evidence pack someone sent you. Nothing in it is opened or run; the checks read its files.</p>
      <input type="file" accept=".zip" aria-label="Evidence pack file" onChange={(e) => { const f = e.target.files?.[0]; if (f) void verify(f); }} />
      <ErrorBox error={action.error} />
      {v && (
        <div data-testid="evidence-verdict">
          <p>
            <Chip value={v.ok ? "verified" : "failed"} />{" "}
            {v.engagement?.name && <b>{v.engagement.name}</b>} {v.findings} finding(s), {v.exchanges} recorded exchange(s)
          </p>
          {v.fingerprint && <p className="small">Signed by key <code>{v.fingerprint}</code>: compare it with the fingerprint the tester gave you.</p>}
          <table className="grid">
            <tbody>
              {v.checks.map((c) => (
                <tr key={c.name}>
                  <td>{c.ok ? "✓" : "✗"}</td>
                  <td><b>{c.name}</b></td>
                  <td className="small">{c.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function Coverage() {
  const [c, setC] = useState<CoverageProof | null>(null);
  const [only, setOnly] = useState("");
  const action = useAction();
  const load = () => action.run(async () => setC(await api.get<CoverageProof>("/coverage/proof")));
  useEffect(() => { void load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const shown = (c?.cells ?? []).filter((x) => !only || x.status === only);
  return (
    <Panel
      title="Coverage proof"
      actions={<>
        <select aria-label="Coverage status" value={only} onChange={(e) => setOnly(e.target.value)}>
          <option value="">all</option>
          {["untested", "open", "tested", "vulnerable"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <button className="btn" onClick={() => void load()} disabled={action.busy}>Refresh</button>
      </>}
    >
      <p className="small muted">
        Every operation in the app model against the vulnerability classes that apply to it: who tested each one and how
        (scanner checks, authorization checks, proofs, hypotheses), and what was found. What nobody tested is listed
        first, so the report can say so. It goes into the evidence pack as <code>coverage.json</code>.
      </p>
      <ErrorBox error={action.error} />
      {c && (
        <p data-testid="coverage-summary">
          <b>{c.percent_tested}%</b> tested across {c.operations} operation(s) ·{" "}
          {["vulnerable", "tested", "open", "untested"].map((k) => <span key={k} style={{ marginRight: 8 }}><Chip value={k} /> {c.totals[k] ?? 0}</span>)}
        </p>
      )}
      {c && (shown.length === 0 ? <Empty>No operations yet: browse or crawl the app first.</Empty> : (
        <table className="grid" data-testid="coverage-cells">
          <thead><tr><th>Status</th><th>Class</th><th>Operation</th><th>By</th><th>How</th></tr></thead>
          <tbody>
            {shown.slice(0, 500).map((x, i) => (
              <tr key={i}>
                <td><Chip value={x.status} /></td>
                <td className="small">{x.vuln_class}{x.param ? <span className="muted"> [{x.param}]</span> : null}</td>
                <td className="mono small" style={{ wordBreak: "break-all" }}>{x.operation}</td>
                <td className="small mono">{(x.by ?? []).join(", ")}</td>
                <td className="small">
                  {(x.how ?? []).join("; ")}
                  {(x.findings ?? []).map((f) => <a key={f} href={`#/findings/${f}`} style={{ marginLeft: 6 }}>#{f}</a>)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </Panel>
  );
}
