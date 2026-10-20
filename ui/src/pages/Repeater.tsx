import { useEffect, useState } from "react";
import { api, originOf, type ExchangeDetail, type IdentityInfo, type ReplayResult } from "../api";
import { Chip, ErrorBox, ExchangeLink, Panel, Raw, StatusCode, useAction, useLoad, useNav } from "../components";

interface RaceGroup {
  status?: number;
  body_length: number;
  count: number;
  exchange_ids: number[];
  error?: string;
}

type RaceResult =
  | { status: "done"; mode: "single_packet" | "last_byte"; count: number; groups: RaceGroup[]; successes: number; fastest_ms: number; slowest_ms: number; exchange_ids: number[] }
  | { status: "pending_approval"; approval_id: string; summary: string; reasons: string[] }
  | { status: "denied"; reasons: string[] };

interface Sent {
  result: ReplayResult;
  response?: string | null;
  status?: number | null;
}

export default function Repeater() {
  const { arg, go } = useNav();
  const [url, setUrl] = useState("");
  const [raw, setRaw] = useState("GET / HTTP/1.1\nHost: example.com\n\n");
  const [identity, setIdentity] = useState("");
  const [fixCl, setFixCl] = useState(true);
  const [sent, setSent] = useState<Sent | null>(null);
  const [approval, setApproval] = useState<string | null>(null);
  const [raceCount, setRaceCount] = useState(10);
  const [raceMode, setRaceMode] = useState<"auto" | "single_packet" | "last_byte">("auto");
  const [race, setRace] = useState<RaceResult | null>(null);
  const [raceApproval, setRaceApproval] = useState<string | null>(null);
  const [curlOpen, setCurlOpen] = useState(false);
  const [curlText, setCurlText] = useState("");
  const [curlWarnings, setCurlWarnings] = useState<string[]>([]);
  const ids = useLoad(() => api.get<IdentityInfo[]>("/identities"), []);
  const action = useAction();

  // A request handed over by another page (e.g. a GraphQL example).
  useEffect(() => {
    if (arg) return;
    try {
      const draft = sessionStorage.getItem("pm_repeater_draft");
      if (!draft) return;
      sessionStorage.removeItem("pm_repeater_draft");
      const d = JSON.parse(draft) as { url: string; raw: string };
      setUrl(d.url);
      setRaw(d.raw.replace(/\r\n/g, "\n"));
    } catch {
      /* storage blocked or bad draft */
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Load the exchange we were sent here with.
  useEffect(() => {
    if (!arg) return;
    api
      .get<ExchangeDetail>(`/exchanges/${arg}`)
      .then((ex) => {
        setUrl(originOf(ex.summary));
        setRaw(ex.request.replace(/\r\n/g, "\n"));
        setSent(null);
      })
      .catch((e) => action.setError(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [arg]);

  const pasteCurl = () =>
    action.run(async () => {
      const r = await api.post<{ url: string; raw: string; warnings: string[] }>("/tools/curl", { command: curlText });
      setUrl(r.url);
      setRaw(r.raw.replace(/\r\n/g, "\n"));
      setCurlWarnings(r.warnings);
      setCurlOpen(false);
      setSent(null);
    });

  const send = () =>
    action.run(async () => {
      const result = await api.post<ReplayResult>("/replay", {
        url,
        raw,
        identity: identity || undefined,
        fix_content_length: fixCl,
        approval_id: approval || undefined,
      });
      let response: string | null | undefined;
      let status: number | null | undefined;
      if (result.status === "sent" || result.status === "failed") {
        const ex = await api.get<ExchangeDetail>(`/exchanges/${result.exchange_id}`);
        response = ex.response;
        status = ex.summary.status;
      }
      setApproval(result.status === "pending_approval" ? result.approval_id : null);
      setSent({ result, response, status });
      setRace(null);
    });

  const runRace = () =>
    action.run(async () => {
      const r = await api.post<RaceResult>("/race", {
        url,
        raw,
        count: raceCount,
        mode: raceMode,
        identity: identity || undefined,
        fix_content_length: fixCl,
        approval_id: raceApproval || undefined,
      });
      setRaceApproval(r.status === "pending_approval" ? r.approval_id : null);
      setRace(r);
      setSent(null);
    });

  return (
    <div className="content">
      <div className="split">
        <Panel
          title="Request"
          actions={
            <button className="btn primary" onClick={send} disabled={action.busy || !url} data-testid="send">
              {action.busy ? "Sending…" : approval ? "Send approved" : "Send"}
            </button>
          }
        >
          <div className="row" style={{ marginBottom: 8 }}>
            <button className="btn" onClick={() => setCurlOpen((o) => !o)} data-testid="paste-curl">Paste cURL…</button>
          </div>
          {curlOpen && (
            <div style={{ marginBottom: 8 }}>
              <textarea aria-label="cURL command" className="mono" rows={5} style={{ width: "100%" }} placeholder="curl 'https://…' -H '…'" value={curlText} onChange={(e) => setCurlText(e.target.value)} />
              <button className="btn primary" disabled={!curlText.trim() || action.busy} onClick={pasteCurl} data-testid="parse-curl">Load into Repeater</button>
              <span className="small muted"> Nothing is sent until you press Send.</span>
            </div>
          )}
          {curlWarnings.length > 0 && <div className="notice small">Ignored: {curlWarnings.join("; ")}</div>}
          <div className="row" style={{ marginBottom: 8 }}>
            <input aria-label="Target" className="grow mono" placeholder="https://host:port" value={url} onChange={(e) => setUrl(e.target.value)} />
            <select aria-label="Send as" value={identity} onChange={(e) => setIdentity(e.target.value)}>
              <option value="">as written</option>
              <option value="anonymous">anonymous</option>
              {ids.data?.map((i) => (
                <option key={i.name} value={i.name}>as {i.name}</option>
              ))}
            </select>
            <label className="small row" style={{ gap: 4 }}>
              <input type="checkbox" checked={fixCl} onChange={(e) => setFixCl(e.target.checked)} /> fix Content-Length
            </label>
          </div>
          <textarea
            aria-label="Raw request"
            rows={22}
            value={raw}
            onChange={(e) => {
              setRaw(e.target.value);
              setApproval(null);
              setRaceApproval(null);
            }}
            spellCheck={false}
          />
          <p className="small muted">
            Sent exactly as written (bare line breaks in the head become CRLF). Choosing an identity swaps in its
            cookies and auth headers. Everything goes through the rules of engagement.
          </p>
          <div className="row small race-bar">
            <strong>Race</strong>
            <label>
              send <input aria-label="Race count" type="number" min={2} max={50} value={raceCount} onChange={(e) => { setRaceCount(Number(e.target.value)); setRaceApproval(null); }} style={{ width: 60 }} /> copies at once
            </label>
            <select aria-label="Race mode" value={raceMode} onChange={(e) => { setRaceMode(e.target.value as typeof raceMode); setRaceApproval(null); }}>
              <option value="auto">auto (HTTP/2 single packet if possible)</option>
              <option value="single_packet">HTTP/2 single packet</option>
              <option value="last_byte">last-byte sync</option>
            </select>
            <button className="btn" data-testid="race" onClick={runRace} disabled={action.busy || !url}>
              {raceApproval ? "Race approved" : "Race"}
            </button>
          </div>
        </Panel>
        <Panel title="Response">
          <ErrorBox error={action.error} />
          {!sent && !race && <p className="muted">Nothing sent yet.</p>}
          {race && !sent && <RaceView race={race} goApprovals={() => go("approvals")} />}
          {sent?.result.status === "sent" && (
            <>
              <div className="row small" style={{ marginBottom: 8 }} data-testid="replay-result">
                <StatusCode status={sent.status ?? null} />
                <span className="muted">{sent.result.elapsed_ms} ms</span>
                <span className="muted">recorded as <ExchangeLink id={sent.result.exchange_id} /></span>
                {sent.result.notes?.map((n) => <Chip key={n} value={n} />)}
              </div>
              <Raw text={sent.response} />
            </>
          )}
          {sent?.result.status === "failed" && <div className="error">Failed: {sent.result.error}</div>}
          {sent?.result.status === "denied" && <div className="error">Denied by the rules of engagement: {sent.result.reasons.join("; ")}</div>}
          {sent?.result.status === "pending_approval" && (
            <div className="notice">
              Needs approval ({sent.result.reasons.join("; ")}). Approve <strong>{sent.result.approval_id}</strong> on the{" "}
              <a href="#" onClick={(e) => { e.preventDefault(); go("approvals"); }}>Approvals</a> page, then press Send again.
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}

function RaceView({ race, goApprovals }: { race: RaceResult; goApprovals: () => void }) {
  if (race.status === "denied") return <div className="error">Denied by the rules of engagement: {race.reasons.join("; ")}</div>;
  if (race.status === "pending_approval") {
    return (
      <div className="notice">
        {race.summary} needs approval ({race.reasons.join("; ")}). Approve <strong>{race.approval_id}</strong> on the{" "}
        <a href="#" onClick={(e) => { e.preventDefault(); goApprovals(); }}>Approvals</a> page, then press Race again.
      </div>
    );
  }
  return (
    <div data-testid="race-result">
      <div className="row small" style={{ marginBottom: 8 }}>
        <strong>{race.count} requests</strong>
        <Chip value={race.mode === "single_packet" ? "HTTP/2 single packet" : "last-byte sync"} />
        <span className="muted">responses in {race.fastest_ms}–{race.slowest_ms} ms</span>
        <span className={race.successes > 1 ? "bad" : "muted"}>{race.successes} succeeded (2xx)</span>
      </div>
      {race.successes > 1 && (
        <div className="notice">More than one request succeeded. If this action should only work once, that's a race condition: open the exchanges to compare.</div>
      )}
      <table className="grid">
        <thead>
          <tr><th>Status</th><th>Body</th><th>Count</th><th>Exchanges</th></tr>
        </thead>
        <tbody>
          {race.groups.map((g, i) => (
            <tr key={i}>
              <td>{g.error ? <span className="bad">error</span> : <StatusCode status={g.status ?? null} />}</td>
              <td className="small">{g.error ?? `${g.body_length} bytes`}</td>
              <td>{g.count}</td>
              <td className="small">{g.exchange_ids.slice(0, 8).map((id) => <span key={id} style={{ marginRight: 6 }}><ExchangeLink id={id} /></span>)}{g.exchange_ids.length > 8 ? "…" : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
