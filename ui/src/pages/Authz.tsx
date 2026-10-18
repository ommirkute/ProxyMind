import { useEffect, useState } from "react";
import { api, type AuthzCandidate, type AuthzRow, type IdentityInfo } from "../api";
import { Chip, Empty, ErrorBox, ExchangeLink, Panel, useAction, useLoad, useNav } from "../components";

interface Report {
  method: string;
  url: string;
  baseline_status: number | null;
  results: AuthzRow[];
  how_to_read: string;
}

export function AuthzTable({ rows }: { rows: AuthzRow[] }) {
  if (rows.length === 0) return <Empty>No results yet.</Empty>;
  return (
    <table className="grid" data-testid="authz-results">
      <thead>
        <tr>
          <th>Request</th>
          <th>As</th>
          <th>Verdict</th>
          <th>Status</th>
          <th>Similar</th>
          <th>Evidence</th>
          <th>Why</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.id}>
            <td className="mono small" style={{ whiteSpace: "nowrap" }}>
              <ExchangeLink id={r.exchange_id} /> {r.method} {new URL(r.url).pathname}
            </td>
            <td>{r.identity}</td>
            <td><Chip value={r.verdict} /></td>
            <td>{r.status ?? "–"}</td>
            <td>{r.similarity == null ? "–" : `${Math.round(r.similarity * 100)}%`}</td>
            <td><ExchangeLink id={r.evidence_id} /></td>
            <td className="small muted" style={{ minWidth: 260 }}>{r.summary}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Authz() {
  const { arg } = useNav();
  const ids = useLoad(() => api.get<IdentityInfo[]>("/identities"), []);
  const cands = useLoad(() => api.get<AuthzCandidate[]>("/authz/candidates"), []);
  const results = useLoad(() => api.get<AuthzRow[]>("/authz/results"), []);
  const [exchange, setExchange] = useState(arg ? String(arg) : "");
  const [chosen, setChosen] = useState<string[]>([]);
  const [anon, setAnon] = useState(true);
  const [report, setReport] = useState<Report | null>(null);
  const action = useAction();
  const checkAction = useAction();
  const [checks, setChecks] = useState<Record<string, string>>({});

  useEffect(() => {
    if (arg) setExchange(String(arg));
  }, [arg]);

  const run = (exchange_id: number, identities: string[]) =>
    action.run(async () => {
      const r = await api.post<Report>("/authz/check", { exchange_id, identities, include_anonymous: anon });
      setReport(r);
      results.reload();
    });

  const checkIdentity = (name: string) =>
    checkAction.run(async () => {
      const c = await api.post<{ status: string; notes: string[] }>(`/identities/${encodeURIComponent(name)}/check`);
      setChecks((m) => ({ ...m, [name]: [c.status, ...c.notes].join(" · ") }));
      ids.reload();
    });

  return (
    <div className="content">
      <div className="split">
        <Panel title="Identities">
          <ErrorBox error={ids.error ?? checkAction.error} />
          {ids.data?.length === 0 && (
            <Empty>No identities yet. In History, open a request made while logged in and use "Capture identity…".</Empty>
          )}
          {!!ids.data?.length && (
            <table className="grid">
              <thead>
                <tr><th>Name</th><th>Role</th><th>Session</th><th>Credentials</th><th></th></tr>
              </thead>
              <tbody>
                {ids.data.map((i) => (
                  <tr key={i.name}>
                    <td><strong>{i.name}</strong></td>
                    <td>{i.role}</td>
                    <td>
                      <Chip value={i.status} />
                      {checks[i.name] && <div className="small muted">{checks[i.name]}</div>}
                    </td>
                    <td className="small muted">
                      {[...i.cookies.map((c) => `cookie ${c}`), ...i.headers].join(", ")}
                      {i.has_login && " · auto re-login"}
                    </td>
                    <td>
                      <button className="btn" disabled={checkAction.busy || !i.has_health_check} title={i.has_health_check ? "" : "No health check set (proxymind identity health)"} onClick={() => checkIdentity(i.name)}>
                        Check
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Run an authorization check">
          <p className="small muted" style={{ marginTop: 0 }}>
            Re-sends a recorded GET made by the data's owner as other identities (and anonymously), and compares each
            response with the owner's, ignoring timestamps and tokens.
          </p>
          <div className="row">
            <label>Exchange #</label>
            <input aria-label="Exchange id" value={exchange} onChange={(e) => setExchange(e.target.value)} style={{ width: 90 }} />
            {ids.data?.map((i) => (
              <label key={i.name} className="row small" style={{ gap: 4 }}>
                <input
                  type="checkbox"
                  checked={chosen.includes(i.name)}
                  onChange={(e) => setChosen((c) => (e.target.checked ? [...c, i.name] : c.filter((x) => x !== i.name)))}
                />
                {i.name}
              </label>
            ))}
            <label className="row small" style={{ gap: 4 }}>
              <input type="checkbox" checked={anon} onChange={(e) => setAnon(e.target.checked)} /> anonymous
            </label>
            <button className="btn primary" disabled={action.busy || !exchange} onClick={() => run(Number(exchange), chosen)} data-testid="run-authz">
              {action.busy ? "Checking…" : "Check"}
            </button>
          </div>
          <ErrorBox error={action.error} />
          {report && (
            <div style={{ marginTop: 10 }}>
              <div className="small muted">
                {report.method} {report.url} · owner's request re-sent: {report.baseline_status ?? "no response"}
              </div>
              <AuthzTable rows={report.results} />
              <p className="small muted">{report.how_to_read}</p>
            </div>
          )}
        </Panel>
      </div>

      <Panel title="Suggested checks" actions={<button className="btn" onClick={cands.reload}>Refresh</button>}>
        <p className="small muted" style={{ marginTop: 0 }}>From the app model: objects owned by one identity, to try as the others.</p>
        <ErrorBox error={cands.error} />
        {cands.data?.length === 0 && <Empty>No suggestions yet. Capture at least two identities and browse as each.</Empty>}
        {!!cands.data?.length && (
          <table className="grid">
            <thead><tr><th>Operation</th><th>Object</th><th>Owner</th><th>Try as</th><th></th></tr></thead>
            <tbody>
              {cands.data.map((c) => (
                <tr key={`${c.operation}-${c.object}`}>
                  <td className="mono small">{c.operation}</td>
                  <td>{c.object}</td>
                  <td>{c.owner}</td>
                  <td>{c.try_as.join(", ")}</td>
                  <td>
                    <button className="btn" disabled={action.busy} onClick={() => { setExchange(String(c.exchange_id)); run(c.exchange_id, c.try_as); }}>
                      Check
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="All results" actions={<button className="btn" onClick={results.reload}>Refresh</button>}>
        <ErrorBox error={results.error} />
        {results.data && <AuthzTable rows={results.data} />}
      </Panel>
    </div>
  );
}
