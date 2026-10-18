import { useEffect, useState } from "react";
import { api, originOf, type ExchangeDetail, type IdentityInfo, type ReplayResult } from "../api";
import { Chip, ErrorBox, ExchangeLink, Panel, Raw, StatusCode, useAction, useLoad, useNav } from "../components";

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
  const ids = useLoad(() => api.get<IdentityInfo[]>("/identities"), []);
  const action = useAction();

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
            }}
            spellCheck={false}
          />
          <p className="small muted">
            Sent exactly as written (bare line breaks in the head become CRLF). Choosing an identity swaps in its
            cookies and auth headers. Everything goes through the rules of engagement.
          </p>
        </Panel>
        <Panel title="Response">
          <ErrorBox error={action.error} />
          {!sent && <p className="muted">Nothing sent yet.</p>}
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
