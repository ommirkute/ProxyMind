import { useEffect, useState } from "react";
import { api, toast } from "../api";
import { Chip, Empty, ErrorBox, Panel, copyText, useAction, useLoad } from "../components";

interface Status { public_url?: string; dns_domain?: string; listening?: string; smtp?: string; payloads: number; interactions: number; probes: number; late_findings: number }
interface Payload { token: string; note: string; created_ms: number; actor: string; http_url?: string; dns_name?: string; email?: string; interactions: number }
interface Interaction { id: number; token: string; protocol: string; remote: string; method: string; path: string; ts_ms: number; raw: string; note?: string; finding_id?: number }

const time = (ms: number) => new Date(ms).toLocaleTimeString();

/** Out-of-band payloads to paste by hand, and the callbacks they cause. */
export default function Collaborator() {
  const [seen, setSeen] = useState(0);
  const status = useLoad(() => api.get<Status>("/collaborator"), [seen]);
  const s = status.data;
  const ready = !!(s?.public_url || s?.dns_domain);
  return (
    <div className="content">
      <Panel title="Collaborator">
        <ErrorBox error={status.error} />
        <p className="small muted">
          Payloads carry a unique token. When a target fetches the URL or resolves the name (blind SSRF, XXE, injection that runs a
          lookup), the callback shows up below: only the target could have known the token.
        </p>
        {s && (ready ? <ListenerInfo s={s} /> : <StartListener onStarted={status.reload} />)}
        {s && ready && !s.smtp && <StartSmtp onStarted={status.reload} />}
      </Panel>
      {ready && <Payloads onChange={status.reload} seen={seen} />}
      {ready && <Interactions onCount={setSeen} />}
    </div>
  );
}

function ListenerInfo({ s }: { s: Status }) {
  return (
    <div className="row small" data-testid="collab-status">
      <Chip value={s.listening ? "listening" : "external listener"} />
      {s.public_url && <span>HTTP callbacks to <code>{s.public_url}</code></span>}
      {s.dns_domain && <span>DNS: <code>*.{s.dns_domain}</code></span>}
      {s.smtp && <span>mail to <code>{s.smtp}</code></span>}
      {s.listening && <span className="muted">(this process listens on {s.listening})</span>}
      <span className="muted">· {s.payloads} payload(s), {s.interactions} interaction(s)</span>
      {s.probes > 0 && (
        <span className="muted" title="A callback that arrives after a scan stopped waiting still becomes a finding" data-testid="collab-probes">
          · {s.probes} scanner probe(s) watched{s.late_findings > 0 && <>, <b>{s.late_findings}</b> late finding(s)</>}
        </span>
      )}
    </div>
  );
}

function StartSmtp({ onStarted }: { onStarted: () => void }) {
  const [listen, setListen] = useState("0.0.0.0:2525");
  const action = useAction();
  return (
    <div className="row small">
      <span className="muted">Also catch mail (password resets, invitations):</span>
      <input aria-label="SMTP listen" className="mono" value={listen} onChange={(e) => setListen(e.target.value)} style={{ width: 160 }} />
      <button className="btn" disabled={action.busy} data-testid="smtp-start" onClick={() => action.run(async () => { await api.post("/collaborator/smtp", { listen }); onStarted(); })}>Start SMTP listener</button>
      <ErrorBox error={action.error} />
    </div>
  );
}

function StartListener({ onStarted }: { onStarted: () => void }) {
  const [listen, setListen] = useState("0.0.0.0:8085");
  const [publicUrl, setPublicUrl] = useState("");
  const action = useAction();
  const start = () =>
    action.run(async () => {
      await api.post("/collaborator/listener", { listen, public_url: publicUrl || undefined });
      onStarted();
    });
  return (
    <>
      <div className="notice small">
        No callback listener yet. Start one here: targets must be able to reach it, so on a real engagement run ProxyMind on a host
        the target can reach and give its public URL. For DNS callbacks, use <code>proxymind oast-server --dns …</code> with a
        delegated domain.
      </div>
      <div className="row small">
        <span>Listen on</span>
        <input aria-label="Collaborator listen" className="mono" value={listen} onChange={(e) => setListen(e.target.value)} style={{ width: 160 }} />
        <span>public URL</span>
        <input aria-label="Collaborator public URL" className="mono" placeholder="http://my-host.example:8085 (optional)" value={publicUrl} onChange={(e) => setPublicUrl(e.target.value)} style={{ width: 280 }} />
        <button className="btn primary" disabled={action.busy} onClick={start} data-testid="collab-start">Start listener</button>
      </div>
      <ErrorBox error={action.error} />
    </>
  );
}

function Payloads({ onChange, seen }: { onChange: () => void; seen: number }) {
  const list = useLoad(() => api.get<Payload[]>("/collaborator/payloads"), [seen]);
  const [note, setNote] = useState("");
  const [fresh, setFresh] = useState<Payload | null>(null);
  const action = useAction();
  const make = () =>
    action.run(async () => {
      const p = await api.post<Payload>("/collaborator/payloads", { note });
      setFresh(p);
      setNote("");
      await copyText(p.http_url ?? p.dns_name ?? p.token);
      toast("Payload copied");
      list.reload();
      onChange();
    });
  return (
    <Panel title="Payloads">
      <div className="row small">
        <input aria-label="Payload note" placeholder="what you're testing (optional)" value={note} onChange={(e) => setNote(e.target.value)} style={{ width: 280 }} />
        <button className="btn primary" disabled={action.busy} onClick={make} data-testid="collab-new">Copy a new payload</button>
      </div>
      <ErrorBox error={action.error ?? list.error} />
      {fresh && (
        <div className="notice small mono" data-testid="collab-payload">
          {fresh.http_url && <div>{fresh.http_url}</div>}
          {fresh.dns_name && <div>{fresh.dns_name}</div>}
          {fresh.email && <div>{fresh.email}</div>}
        </div>
      )}
      {list.data && list.data.length > 0 && (
        <table className="grid">
          <thead><tr><th>Payload</th><th>Note</th><th>Callbacks</th><th>Made</th></tr></thead>
          <tbody>
            {list.data.map((p) => (
              <tr key={p.token}>
                <td className="mono small">
                  <button className="link" title="Copy" onClick={() => copyText(p.http_url ?? p.dns_name ?? p.token).then(() => toast("Copied"))}>{p.http_url ?? p.dns_name ?? p.token}</button>
                </td>
                <td className="small">{p.note}</td>
                <td>{p.interactions > 0 ? <Chip value={`${p.interactions}`} /> : <span className="muted">0</span>}</td>
                <td className="small muted">{time(p.created_ms)} · {p.actor}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}

function Interactions({ onCount }: { onCount: (n: number) => void }) {
  const [items, setItems] = useState<Interaction[]>([]);
  const [open, setOpen] = useState<Interaction | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let stop = false;
    const poll = () =>
      api
        .get<Interaction[]>("/collaborator/interactions?limit=200")
        .then((v) => !stop && (setItems(v), setError(null), onCount(v.length)))
        .catch((e: Error) => !stop && setError(e.message));
    poll();
    const t = setInterval(poll, 2000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, [onCount]);
  return (
    <Panel title="Interactions">
      <ErrorBox error={error} />
      <p className="small muted">Checked every 2 seconds. Callback contents come from the network: treat them as untrusted.</p>
      {items.length === 0 ? (
        <Empty>No callbacks yet.</Empty>
      ) : (
        <table className="grid" data-testid="collab-interactions">
          <thead><tr><th>Time</th><th>Type</th><th>From</th><th>Request</th><th>Payload note or scanner probe</th></tr></thead>
          <tbody>
            {items.map((i) => (
              <tr key={i.id} className={open?.id === i.id ? "selected" : ""} onClick={() => setOpen(open?.id === i.id ? null : i)} style={{ cursor: "pointer" }}>
                <td className="small">{time(i.ts_ms)}</td>
                <td><Chip value={i.protocol} /></td>
                <td className="small mono">{i.remote}</td>
                <td className="small mono">{i.method} {i.path}</td>
                <td className="small">
                  {i.note ?? <span className="muted">(not from this page)</span>}
                  {i.finding_id && <> · <a href={`#/findings/${i.finding_id}`} onClick={(e) => e.stopPropagation()}>finding #{i.finding_id}</a></>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {open && <pre className="raw small" data-testid="collab-raw">{open.raw}</pre>}
    </Panel>
  );
}
