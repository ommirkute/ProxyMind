import { useCallback, useEffect, useRef, useState } from "react";
import TransformMenu from "../TransformMenu";
import { api, originOf, toast, type ExchangeDetail, type IdentityInfo, type ReplayResult } from "../api";
import { altSvcH3, altTarget } from "../altsvc";
import { Chip, ErrorBox, ExchangeLink, MessageView, StatusCode, b64ToBytes, bytesToB64, copyText, useAction, useLoad, useNav } from "../components";
import {
  cookies,
  decodeComponent,
  formParams,
  jsonParams,
  parseRequest,
  queryParams,
  redirectOf,
  setCookie,
  setFormParam,
  setHeader,
  setJsonParam,
  setQueryParam,
  setAuthority,
  setRequestLine,
  isMultiplexed,
  toProtocol,
} from "../http";

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

/**
 * A gRPC or Protobuf body being edited as text. The raw editor holds only the head: the body's bytes are not text.
 * `body` is the original body (base64; null for none), `orig` the text it decoded to. Unedited (`text === orig`),
 * the original bytes are sent; edited, the text is encoded through the API when sending.
 */
interface ProtoBody {
  body: string | null;
  text: string;
  orig: string;
  /** Decoding then encoding gives the original bytes. */
  exact: boolean;
  /** Notes from the decoder (what will not round-trip). */
  notes?: string[];
}

const PROTO_KINDS: Record<string, string> = {
  "application/grpc": "grpc",
  "application/grpc+proto": "grpc",
  "application/grpc-web": "grpc-web",
  "application/grpc-web+proto": "grpc-web",
  "application/grpc-web-text": "grpc-web-text",
  "application/grpc-web-text+proto": "grpc-web-text",
  "application/x-protobuf": "protobuf",
  "application/protobuf": "protobuf",
  "application/vnd.google.protobuf": "protobuf",
};

const headOf = (raw: string) => {
  const m = raw.search(/\r?\n\r?\n/);
  return m < 0 ? raw : raw.slice(0, m);
};

/** `grpc`, `grpc-web`, `grpc-web-text` or `protobuf` when the request's Content-Type says so, else null. */
function protoKind(raw: string): string | null {
  const ct = headOf(raw).match(/^content-type:[ \t]*([^;\r\n]*)/im)?.[1]?.trim().toLowerCase();
  return (ct && PROTO_KINDS[ct]) || null;
}

/** Chunked or content-encoded bodies are not the message itself: they stay in the raw editor. */
const plainBody = (raw: string) => !/^(transfer-encoding|content-encoding):/im.test(headOf(raw));

/** The body to send for a tab with a Protobuf message: the original bytes, or the edited text encoded. */
async function protoBodyOf(raw: string, pb: ProtoBody | undefined): Promise<string | undefined> {
  const kind = protoKind(raw);
  if (!pb || !kind || !plainBody(raw)) return undefined;
  if (pb.text === pb.orig) return pb.body ?? undefined;
  return (await api.post<{ body_b64: string }>("/tools/protobuf/encode", { text: pb.text, kind })).body_b64;
}

/** HTTP/2 requests carry no Content-Length of their own: do not add one when sending a Protobuf body. */
const fixClFor = (raw: string, fixCl: boolean, hasBody: boolean) =>
  fixCl && !(hasBody && /^[^\n]*\sHTTP\/2(\.0)?\s*$/.test(raw.split("\n", 1)[0].trimEnd()) && !/^content-length:/im.test(headOf(raw)));

/** Splits recorded request bytes into the head text and the body bytes. */
function splitHead(b: Uint8Array): { head: string; body: Uint8Array } {
  let end = b.length;
  for (let i = 0; i < b.length; i++) {
    if (b[i] === 10 && b[i + 1] === 10) { end = i + 2; break; }
    if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) { end = i + 4; break; }
  }
  return { head: new TextDecoder().decode(b.subarray(0, end)), body: b.subarray(end) };
}

/** A recorded request as a Replay tab: for gRPC/Protobuf, the head as text and the body as an editable message. */
async function tabFromExchange(arg: string, ex: ExchangeDetail): Promise<Partial<RTab>> {
  const base = { name: `#${arg}`, url: originOf(ex.summary) };
  const plain = { ...base, raw: ex.request.replace(/\r\n/g, "\n") };
  if (ex.request_protobuf == null || !plainBody(ex.request)) return plain;
  const full = await api.get<ExchangeDetail>(`/exchanges/${arg}?bytes=1`);
  if (!full.request_b64 || full.request_truncated) return plain;
  const { head, body } = splitHead(b64ToBytes(full.request_b64));
  const kind = protoKind(head);
  if (!kind) return plain;
  const bodyB64 = bytesToB64(body);
  try {
    const d = await api.post<{ text: string; exact: boolean; notes: string[] }>("/tools/protobuf/decode", { body_b64: bodyB64, kind, annotate: false });
    return { ...base, raw: head.replace(/\r\n/g, "\n"), pb: { body: bodyB64, text: d.text, orig: d.text, exact: d.exact, notes: d.notes } };
  } catch {
    return plain;
  }
}

/** One send in a tab's history. */
interface Step {
  url: string;
  raw: string;
  /** The Protobuf message sent with it (left out when it is large). */
  pb?: ProtoBody;
  exchange_id?: number;
  status?: number | null;
  elapsed_ms?: number;
  error?: string;
  notes?: string[];
}

/** A Replay tab, saved in the project (`/api/v1/ui/replay`). */
interface RTab {
  id: string;
  name: string;
  url: string;
  raw: string;
  /** A gRPC / Protobuf body edited as text; `raw` then holds only the head. */
  pb?: ProtoBody;
  identity: string;
  fixCl: boolean;
  autoFollow: boolean;
  history: Step[];
  /** Which step the editor shows; -1 or past the end means "editing". */
  pos: number;
}

interface Saved {
  tabs: RTab[];
  active: string;
}

/** What only lives while the page is open: approvals, outcomes, race results. */
interface Transient {
  approval?: string;
  outcome?: ReplayResult;
  race?: RaceResult;
  raceApproval?: string;
}

const newId = () => Math.random().toString(36).slice(2, 10);
const blank = (n: number): RTab => ({
  id: newId(),
  name: String(n),
  url: "",
  raw: "GET / HTTP/1.1\nHost: example.com\n\n",
  identity: "",
  fixCl: true,
  autoFollow: false,
  history: [],
  pos: -1,
});

export default function Replay() {
  const { arg, go } = useNav();
  const [state, setState] = useState<Saved | null>(null);
  const [tmp, setTmp] = useState<Record<string, Transient>>({});
  const [details, setDetails] = useState<Record<number, ExchangeDetail>>({});
  const [inspector, setInspector] = useState(true);
  const [curlOpen, setCurlOpen] = useState(false);
  const [curlText, setCurlText] = useState("");
  const [curlWarnings, setCurlWarnings] = useState<string[]>([]);
  const [raceCount, setRaceCount] = useState(10);
  const [raceMode, setRaceMode] = useState<"auto" | "single_packet" | "last_byte">("auto");
  const [groupOpen, setGroupOpen] = useState(false);
  const caret = useRef<[number, number] | null>(null);
  const rawEditor = useRef<HTMLTextAreaElement>(null);
  const ids = useLoad(() => api.get<IdentityInfo[]>("/identities"), []);
  const action = useAction();
  const loaded = useRef(false);

  // Load saved tabs once.
  useEffect(() => {
    api
      .get<Saved | null>("/ui/replay")
      // Tabs saved before the rename live under the old key.
      .then((s) => (s?.tabs?.length ? s : api.get<Saved | null>("/ui/repeater").catch(() => null)))
      .then((s) => {
        const tabs = s?.tabs?.length ? s.tabs : [blank(1)];
        setState({ tabs, active: tabs.some((t) => t.id === s?.active) ? s!.active : tabs[0].id });
        loaded.current = true;
      })
      .catch(() => {
        const t = blank(1);
        setState({ tabs: [t], active: t.id });
        loaded.current = true;
      });
  }, []);

  // Save (debounced) whenever tabs change.
  useEffect(() => {
    if (!state || !loaded.current) return;
    const t = setTimeout(() => api.put("/ui/replay", state).catch(() => {}), 600);
    return () => clearTimeout(t);
  }, [state]);

  const addTab = useCallback((t: Partial<RTab>) => {
    setState((s) => {
      if (!s) return s;
      const n = s.tabs.reduce((m, x) => Math.max(m, Number(x.name) || 0), 0) + 1;
      const tab = { ...blank(n), ...t, id: newId() };
      return { tabs: [...s.tabs, tab], active: tab.id };
    });
  }, []);

  // A request sent here from History (#/replay/<id>) or another page opens in a new tab.
  useEffect(() => {
    if (!state) return;
    if (arg) {
      window.history.replaceState(null, "", "#/replay");
      // "h3:<id>": the recorded request written for HTTP/3, at the alternative its response advertised (Alt-Svc).
      const asH3 = String(arg).startsWith("h3:");
      const id = asH3 ? String(arg).slice(3) : String(arg);
      api
        .get<ExchangeDetail>(`/exchanges/${id}`)
        .then((ex) => tabFromExchange(id, ex).then((t) => (asH3 ? withHttp3(t, ex.response) : t)))
        .then((t) => addTab(t))
        .catch((e) => action.setError(e.message));
      return;
    }
    try {
      const draft = sessionStorage.getItem("pm_replay_draft");
      if (draft) {
        sessionStorage.removeItem("pm_replay_draft");
        const d = JSON.parse(draft) as { url: string; raw: string; name?: string };
        addTab({ name: d.name ?? "draft", url: d.url, raw: d.raw.replace(/\r\n/g, "\n") });
      }
    } catch {
      /* storage blocked or bad draft */
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [arg, state === null]);

  const tab = state?.tabs.find((t) => t.id === state.active);
  const t = (tab && tmp[tab.id]) || {};
  const step = tab && tab.pos >= 0 && tab.pos < tab.history.length ? tab.history[tab.pos] : undefined;

  // Load the response shown for the current step.
  useEffect(() => {
    const id = step?.exchange_id;
    if (id == null || details[id]) return;
    api.get<ExchangeDetail>(`/exchanges/${id}`).then((d) => setDetails((m) => ({ ...m, [id]: d }))).catch(() => {});
  }, [step?.exchange_id, details]);

  if (!state || !tab) return <div className="content muted">Loading…</div>;

  const update = (patch: Partial<RTab>) =>
    setState((s) => (s ? { ...s, tabs: s.tabs.map((x) => (x.id === tab.id ? { ...x, ...patch } : x)) } : s));
  const setT = (patch: Partial<Transient>) => setTmp((m) => ({ ...m, [tab.id]: { ...m[tab.id], ...patch } }));
  const editRaw = (raw: string) => {
    update({ raw, pos: -1 });
    setT({ approval: undefined, raceApproval: undefined });
  };

  const sendOnce = async (url: string, raw: string, approval?: string, pb?: ProtoBody): Promise<{ r: ReplayResult; d?: ExchangeDetail }> => {
    const body_b64 = await protoBodyOf(raw, pb);
    const r = await api.post<ReplayResult>("/replay", {
      url,
      raw,
      body_b64,
      identity: tab.identity || undefined,
      fix_content_length: fixClFor(raw, tab.fixCl, body_b64 != null),
      approval_id: approval,
    });
    if (r.status === "sent" || r.status === "failed") {
      const d = await api.get<ExchangeDetail>(`/exchanges/${r.exchange_id}`);
      setDetails((m) => ({ ...m, [r.exchange_id]: d }));
      return { r, d };
    }
    return { r };
  };

  const record = (url: string, raw: string, r: ReplayResult, d?: ExchangeDetail, pb?: ProtoBody): Step | undefined => {
    // A big body is not kept in every step: the project's saved state has a size limit.
    const kept = pb && protoKind(raw) && (pb.body?.length ?? 0) + pb.text.length + pb.orig.length < 64_000 ? { pb } : {};
    return r.status === "sent"
      ? { url, raw, ...kept, exchange_id: r.exchange_id, status: d?.summary.status, elapsed_ms: r.elapsed_ms, notes: r.notes }
      : r.status === "failed"
        ? { url, raw, ...kept, exchange_id: r.exchange_id, error: r.error }
        : undefined;
  };

  const send = (url = tab.url, raw = tab.raw) =>
    action.run(async () => {
      let { r, d } = await sendOnce(url, raw, t.approval, tab.pb);
      setT({ outcome: r, approval: r.status === "pending_approval" ? r.approval_id : undefined, race: undefined });
      const steps: Step[] = [];
      const first = record(url, raw, r, d, tab.pb);
      if (first) steps.push(first);
      // Same-origin redirects, when asked, up to 5 hops.
      for (let hop = 0; tab.autoFollow && d && hop < 5; hop++) {
        const next = followTarget(url, raw, d.response);
        if (!next || new URL(next.url).origin !== new URL(url).origin) break;
        ({ r, d } = await sendOnce(next.url, next.raw));
        const s = record(next.url, next.raw, r, d);
        if (!s) break;
        steps.push(s);
        url = next.url;
        raw = next.raw;
      }
      if (steps.length) {
        const kept = tab.pos >= 0 ? tab.history.slice(0, tab.pos + 1) : tab.history;
        const history = [...kept, ...steps].slice(-100);
        const last = steps[steps.length - 1];
        update({ history, pos: history.length - 1, url: last.url, raw: last.raw });
      }
    });

  /** Switches this tab to HTTP/3 at the host and port the response's Alt-Svc offered, and sends it. */
  const sendHttp3 = (response: string | null | undefined) => {
    const t3 = withHttp3({ url: tab.url, raw: tab.raw }, response);
    update({ url: t3.url, raw: t3.raw });
    send(t3.url, t3.raw);
  };

  const follow = () => {
    const d = step?.exchange_id != null ? details[step.exchange_id] : undefined;
    const next = step && d ? followTarget(step.url, step.raw, d.response) : null;
    if (next) send(next.url, next.raw);
  };

  const runRace = () =>
    action.run(async () => {
      const body_b64 = await protoBodyOf(tab.raw, tab.pb);
      const r = await api.post<RaceResult>("/race", {
        url: tab.url,
        raw: tab.raw,
        body_b64,
        count: raceCount,
        mode: raceMode,
        identity: tab.identity || undefined,
        fix_content_length: fixClFor(tab.raw, tab.fixCl, body_b64 != null),
        approval_id: t.raceApproval || undefined,
      });
      setT({ race: r, raceApproval: r.status === "pending_approval" ? r.approval_id : undefined, outcome: undefined });
    });

  const pasteCurl = () =>
    action.run(async () => {
      const r = await api.post<{ url: string; raw: string; warnings: string[] }>("/tools/curl", { command: curlText });
      update({ url: r.url, raw: r.raw.replace(/\r\n/g, "\n"), pos: -1 });
      setCurlWarnings(r.warnings);
      setCurlOpen(false);
    });

  const move = (by: number) => {
    const pos = Math.max(0, Math.min(tab.history.length - 1, (tab.pos < 0 ? tab.history.length : tab.pos) + by));
    const s = tab.history[pos];
    if (s) update({ pos, url: s.url, raw: s.raw, pb: s.pb });
  };

  const closeTab = (id: string) =>
    setState((s) => {
      if (!s) return s;
      const tabs = s.tabs.filter((x) => x.id !== id);
      if (!tabs.length) tabs.push(blank(1));
      return { tabs, active: s.active === id ? tabs[Math.max(0, s.tabs.findIndex((x) => x.id === id) - 1)].id : s.active };
    });

  const pbKind = protoKind(tab.raw);
  const pbBlocked = !plainBody(tab.raw);
  const pbEdited = !!tab.pb && tab.pb.text !== tab.pb.orig;
  const detail = step?.exchange_id != null ? details[step.exchange_id] : undefined;
  const redirect = redirectOf(detail?.response);
  const offersH3 = altSvcH3(detail?.response).length > 0;
  const onKey = (e: React.KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === "Enter" || e.key === " ")) {
      e.preventDefault();
      if (!action.busy && tab.url) send();
    }
  };

  return (
    <div className="content replay">
      <div className="rtabs" role="tablist" aria-label="Replay tabs">
        {state.tabs.map((x) => (
          <div key={x.id} role="tab" aria-selected={x.id === tab.id} className={`rtab ${x.id === tab.id ? "active" : ""}`}
            onClick={() => setState({ ...state, active: x.id })}
            onDoubleClick={() => {
              const name = window.prompt("Tab name", x.name);
              if (name) setState({ ...state, tabs: state.tabs.map((y) => (y.id === x.id ? { ...y, name } : y)) });
            }}
            title="Double-click to rename"
          >
            <span>{x.name}</span>
            <button className="rtab-x" aria-label={`Close tab ${x.name}`} onClick={(e) => { e.stopPropagation(); closeTab(x.id); }}>×</button>
          </div>
        ))}
        <button className="rtab add" aria-label="New tab" onClick={() => addTab({})}>+</button>
        <button className="rtab add" title="Duplicate this tab" onClick={() => addTab({ name: `${tab.name} copy`, url: tab.url, raw: tab.raw, pb: tab.pb, identity: tab.identity })}>⧉</button>
      </div>

      <div className="row replay-bar">
        <button className="btn primary" onClick={() => send()} disabled={action.busy || !tab.url} data-testid="send" title="Ctrl+Enter">
          {action.busy ? "Sending…" : t.approval ? "Send approved" : "Send"}
        </button>
        <button className="btn" onClick={() => move(-1)} disabled={!tab.history.length || tab.pos === 0} aria-label="Previous request" title="Previous in this tab">‹</button>
        <button className="btn" onClick={() => move(1)} disabled={tab.pos < 0 || tab.pos >= tab.history.length - 1} aria-label="Next request" title="Next in this tab">›</button>
        <span className="small muted">{tab.history.length ? `${tab.pos < 0 ? "edited" : tab.pos + 1} / ${tab.history.length}` : ""}</span>
        <input aria-label="Target" className="grow mono" placeholder="https://host:port" value={tab.url} onChange={(e) => update({ url: e.target.value })} />
        <select aria-label="Send as" value={tab.identity} onChange={(e) => update({ identity: e.target.value })}>
          <option value="">as written</option>
          <option value="anonymous">anonymous</option>
          {ids.data?.map((i) => (
            <option key={i.name} value={i.name}>as {i.name}</option>
          ))}
        </select>
        <label className="small row" style={{ gap: 4 }}>
          <input type="checkbox" checked={tab.fixCl} onChange={(e) => update({ fixCl: e.target.checked })} /> fix Content-Length
        </label>
        <label className="small row" style={{ gap: 4 }} title="Follow same-origin redirects automatically (up to 5)">
          <input type="checkbox" checked={tab.autoFollow} onChange={(e) => update({ autoFollow: e.target.checked })} /> follow redirects
        </label>
        <select
          aria-label="Change request"
          data-testid="request-transform"
          value=""
          onChange={(e) => {
            const v = e.target.value;
            if (!v) return;
            if (v.startsWith("oast:")) {
              action.run(async () => {
                const p = await api.post<{ http_url?: string; dns_name?: string; email?: string; token: string }>("/collaborator/payloads", { note: `Replay tab ${tab.name}` });
                const value = (v === "oast:dns" ? p.dns_name : v === "oast:email" ? p.email : p.http_url) ?? p.http_url ?? p.dns_name ?? p.email ?? p.token;
                const [a, b] = caret.current ?? [tab.raw.length, tab.raw.length];
                editRaw(tab.raw.slice(0, a) + value + tab.raw.slice(b));
                toast("Collaborator payload inserted");
              });
              return;
            }
            if (v.startsWith("code:")) {
              action.run(async () => {
                const r = await api.post<{ code: string }>("/tools/code", { url: tab.url, raw: tab.raw, lang: v.slice(5) });
                await copyText(r.code);
                toast("Code copied");
              });
              return;
            }
            const body = v === "method" ? { op: "change_method", raw: tab.raw } : { op: "convert_body", raw: tab.raw, to: v };
            action.run(async () => editRaw((await api.post<{ raw: string }>("/tools/request-transform", body)).raw));
          }}
        >
          <option value="">Request…</option>
          <option value="method">Change method (GET ⇄ POST)</option>
          <option value="url_encoded">Body as URL-encoded form</option>
          <option value="multipart">Body as multipart form</option>
          <option value="json">Body as JSON</option>
          <option value="oast:http">Insert Collaborator URL</option>
          <option value="oast:dns">Insert Collaborator DNS name</option>
          <option value="oast:email">Insert Collaborator email</option>
          <option value="code:python" disabled={!tab.url}>Copy as Python requests</option>
          <option value="code:javascript" disabled={!tab.url}>Copy as JavaScript fetch</option>
          <option value="code:powershell" disabled={!tab.url}>Copy as PowerShell</option>
        </select>
        <button className="btn" onClick={() => setCurlOpen((o) => !o)} data-testid="paste-curl">Paste cURL…</button>
        <button className="btn" onClick={() => setGroupOpen((o) => !o)} aria-pressed={groupOpen} data-testid="group-open">Send group…</button>
        <button className="btn" onClick={() => setInspector((i) => !i)} aria-pressed={inspector}>Inspector</button>
      </div>
      {curlOpen && (
        <div style={{ marginBottom: 8 }}>
          <textarea aria-label="cURL command" className="mono" rows={4} style={{ width: "100%" }} placeholder="curl 'https://…' -H '…'" value={curlText} onChange={(e) => setCurlText(e.target.value)} />
          <button className="btn primary" disabled={!curlText.trim() || action.busy} onClick={pasteCurl} data-testid="parse-curl">Load into this tab</button>
          <span className="small muted"> Nothing is sent until you press Send.</span>
        </div>
      )}
      {curlWarnings.length > 0 && <div className="notice small">Ignored: {curlWarnings.join("; ")}</div>}
      {groupOpen && <GroupPanel tabs={state.tabs} current={tab} goApprovals={() => go("approvals")} />}
      <ErrorBox error={action.error} />

      <div className={`replay-grid ${inspector ? "" : "no-inspector"}`}>
        <section className="pane">
          <h3 className="pane-title">Request</h3>
          <TransformMenu target={rawEditor} resetKey={tab.id} />
          <textarea ref={rawEditor} aria-label="Raw request" className={`editor ${pbKind ? "editor-head" : ""}`} value={tab.raw} onChange={(e) => editRaw(e.target.value)} onKeyDown={onKey} onSelect={(e) => { caret.current = [e.currentTarget.selectionStart, e.currentTarget.selectionEnd]; }} spellCheck={false} />
          {pbKind && (
            <div className="pbedit" data-testid="protobuf-panel">
              <div className="row small">
                <strong>Protobuf message</strong>
                <span className="muted">{pbKind}</span>
                {pbEdited ? <span className="notice small">edited: re-encoded when sent</span> : <span className="muted">unedited: sent byte for byte</span>}
                <button className="btn" disabled={!pbEdited} onClick={() => update({ pb: tab.pb && { ...tab.pb, text: tab.pb.orig }, pos: -1 })}>Revert</button>
              </div>
              {pbBlocked && <div className="notice small">Chunked or content-encoded bodies are not edited as Protobuf here; edit the raw request, or remove that header.</div>}
              {tab.pb?.notes?.map((n) => <div key={n} className="notice small">{n}</div>)}
              <textarea
                aria-label="Protobuf message"
                data-testid="protobuf-editor"
                className="editor editor-pb"
                disabled={pbBlocked}
                placeholder={'one field per line: 1: 150, 2: "text", 3 {  }, 4: 0x0a0b, 5: 1.5f32\ngRPC: start each message with @message'}
                value={tab.pb?.text ?? ""}
                onChange={(e) => update({ pb: { body: tab.pb?.body ?? null, orig: tab.pb?.orig ?? "", exact: tab.pb?.exact ?? true, notes: tab.pb?.notes, text: e.target.value }, pos: -1 })}
                spellCheck={false}
              />
            </div>
          )}
          <div className="row small race-bar">
            <strong>Race</strong>
            <label>
              send <input aria-label="Race count" type="number" min={2} max={50} value={raceCount} onChange={(e) => { setRaceCount(Number(e.target.value)); setT({ raceApproval: undefined }); }} style={{ width: 60 }} /> copies at once
            </label>
            <select aria-label="Race mode" value={raceMode} onChange={(e) => { setRaceMode(e.target.value as typeof raceMode); setT({ raceApproval: undefined }); }}>
              <option value="auto">auto (HTTP/2 single packet if possible)</option>
              <option value="single_packet">HTTP/2 single packet</option>
              <option value="last_byte">last-byte sync</option>
            </select>
            <button className="btn" data-testid="race" onClick={runRace} disabled={action.busy || !tab.url}>
              {t.raceApproval ? "Race approved" : "Race"}
            </button>
          </div>
        </section>

        <section className="pane">
          <h3 className="pane-title">Response</h3>
          {t.race && <RaceView race={t.race} goApprovals={() => go("approvals")} />}
          {!t.race && t.outcome?.status === "denied" && <div className="error">Denied by the rules of engagement: {t.outcome.reasons.join("; ")}</div>}
          {!t.race && t.outcome?.status === "pending_approval" && (
            <div className="notice">
              Needs approval ({t.outcome.reasons.join("; ")}). Approve <strong>{t.outcome.approval_id}</strong> on the{" "}
              <a href="#" onClick={(e) => { e.preventDefault(); go("approvals"); }}>Approvals</a> page, then press Send again.
            </div>
          )}
          {!t.race && step && (
            <>
              <div className="row small" style={{ marginBottom: 6 }} data-testid="replay-result">
                {step.error ? <span className="bad">Failed: {step.error}</span> : <StatusCode status={step.status ?? null} />}
                {step.elapsed_ms != null && <span className="muted">{step.elapsed_ms} ms</span>}
                {detail?.summary.resp_len != null && <span className="muted">{detail.summary.resp_len} bytes</span>}
                {step.exchange_id != null && <span className="muted">recorded as <ExchangeLink id={step.exchange_id} /></span>}
                {step.notes?.map((n) => <Chip key={n} value={n} />)}
                {offersH3 && <Chip value="offers HTTP/3" />}
                {offersH3 && !isMultiplexed(parseRequest(step.raw).version) && (
                  <button className="btn" onClick={() => sendHttp3(detail?.response)} disabled={action.busy} data-testid="send-http3" title="The response advertised HTTP/3 (Alt-Svc). Sends this request again over QUIC.">
                    Send with HTTP/3
                  </button>
                )}
                {redirect && <button className="btn" onClick={follow} disabled={action.busy} data-testid="follow-redirect">Follow redirect → {redirect}</button>}
              </div>
              <MessageView
                text={detail?.response ?? (step.error ? null : undefined) ?? null}
                decodedBody={detail?.response_body}
                protobuf={detail?.response_protobuf}
                loadB64={step.exchange_id != null ? () => api.get<ExchangeDetail>(`/exchanges/${step.exchange_id}?bytes=1`).then((d) => d.response_b64) : undefined}
                empty={step.error ? "No response" : "Loading…"}
                testid="replay-response"
              />
            </>
          )}
          {!t.race && !step && !t.outcome && <p className="muted">Nothing sent from this tab yet. Ctrl+Enter sends.</p>}
        </section>

        {inspector && <Inspector raw={tab.raw} onChange={editRaw} url={tab.url} />}
      </div>
    </div>
  );
}

/** A request tab written for HTTP/3, at the target the response's Alt-Svc offered when there is one. */
function withHttp3<T extends { url?: string; raw?: string }>(t: T, response: string | null | undefined): T {
  const alt = altSvcH3(response)[0];
  return {
    ...t,
    ...(t.raw != null ? { raw: toProtocol(t.raw, "HTTP/3") } : {}),
    ...(alt && t.url ? { url: altTarget(t.url, alt) } : {}),
  };
}

/** The request to send next when a response redirects, or null. */
function followTarget(url: string, raw: string, response: string | null | undefined): { url: string; raw: string } | null {
  const loc = redirectOf(response);
  if (!loc) return null;
  const p = parseRequest(raw);
  let next: URL;
  try {
    const base = new URL(p.target.startsWith("http") ? p.target : url.replace(/\/$/, "") + p.target);
    next = new URL(loc, base);
  } catch {
    return null;
  }
  // Like a browser: GET, same headers minus the body ones.
  const keep = p.headers.filter((h) => !["content-length", "content-type", "transfer-encoding", "host"].includes(h.name.toLowerCase()));
  const lines = [`GET ${next.pathname}${next.search} ${p.version}`, `Host: ${next.host}`, ...keep.map((h) => `${h.name}: ${h.value}`)];
  return { url: next.origin, raw: lines.join("\n") + "\n\n" };
}

/**
 * One editable value. Defined at module level: a component declared inside another is a new type on every render,
 * so React would replace the input (and lose what was typed) whenever the page re-renders, e.g. on a live update.
 */
function Field({ value, label, set }: { value: string; label: string; set: (v: string) => void }) {
  return (
    <input aria-label={label} className="mono" defaultValue={value} key={value} onBlur={(e) => e.target.value !== value && set(e.target.value)}
      onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()} />
  );
}

/** Parameters, cookies and headers of the request, editable in place. */
function Inspector({ raw, onChange, url }: { raw: string; onChange: (raw: string) => void; url: string }) {
  const p = parseRequest(raw);
  const h2 = isMultiplexed(p.version); // HTTP/2 and HTTP/3 are edited the same way (pseudo-headers)
  const h3 = /^HTTP\/3/i.test(p.version);
  const proto = h3 ? "HTTP/3" : h2 ? "HTTP/2" : "HTTP/1.1";
  const host = p.headers.find((h) => h.name.toLowerCase() === "host")?.value ?? "";
  const q = queryParams(p);
  const form = formParams(p);
  const json = jsonParams(p);
  const cs = cookies(p);
  const section = (title: string, rows: { name: string; value: string; set: (v: string) => void; decoded?: string }[]) =>
    rows.length > 0 && (
      <details open key={title}>
        <summary>{title} ({rows.length})</summary>
        <table className="grid inspector-table">
          <tbody>
            {rows.map((r, i) => (
              <tr key={`${r.name}-${i}`}>
                <td className="mono" title={r.name}>{r.name}</td>
                <td>
                  <Field value={r.value} label={`${title} ${r.name}`} set={r.set} />
                  {r.decoded && r.decoded !== r.value && <div className="small muted mono" title="decoded">{r.decoded}</div>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    );
  return (
    <section className="pane inspector" aria-label="Inspector">
      <h3 className="pane-title">Inspector</h3>
      <div className="row small" style={{ marginBottom: 6 }}>
        <select aria-label="Protocol" value={proto} onChange={(e) => onChange(toProtocol(raw, e.target.value as "HTTP/3" | "HTTP/2" | "HTTP/1.1"))}>
          <option value="HTTP/1.1">HTTP/1.1</option>
          <option value="HTTP/2">HTTP/2</option>
          <option value="HTTP/3">HTTP/3 (QUIC)</option>
        </select>
        <span className="mono">{p.method} {p.target.split("?")[0]}</span>
      </div>
      {section(h2 ? `${proto} pseudo-headers` : "Request line", [
        { name: h2 ? ":method" : "method", value: p.method, set: (v: string) => onChange(setRequestLine(raw, { method: v })) },
        { name: h2 ? ":path" : "path", value: p.target, set: (v: string) => onChange(setRequestLine(raw, { target: v })) },
        ...(h2 ? [{ name: ":authority", value: host, set: (v: string) => onChange(setAuthority(raw, v)) }] : []),
      ])}
      {h2 && <div className="small muted">:scheme is {url.startsWith("http://") ? "http" : "https"} (from the target); :authority is the host header.</div>}
      {section("Query parameters", q.map((x, i) => ({ ...x, decoded: decodeComponent(x.value), set: (v: string) => onChange(setQueryParam(raw, i, v)) })))}
      {section("Body parameters", form.map((x, i) => ({ ...x, decoded: decodeComponent(x.value), set: (v: string) => onChange(setFormParam(raw, i, v)) })))}
      {section("JSON fields", json.map((x) => ({ ...x, set: (v: string) => onChange(setJsonParam(raw, x.name, v)) })))}
      {section("Cookies", cs.map((x) => ({ ...x, set: (v: string) => onChange(setCookie(raw, x.name, v)) })))}
      {section("Headers", p.headers.map((x, i) => ({ ...x, set: (v: string) => onChange(setHeader(raw, i, v)) })))}
    </section>
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

type GroupResult =
  | { status: "done"; mode: "sequence" | "parallel"; parallel?: "single_packet" | "last_byte"; results: { index: number; name?: string; exchange_id: number | null; status: number | null; elapsed_ms: number; error?: string }[] }
  | { status: "pending_approval"; approval_id: string; summary: string; reasons: string[] }
  | { status: "denied"; reasons: string[] };

/** Several tabs sent together: one after another, or at the same moment (one server). */
function GroupPanel({ tabs, current, goApprovals }: { tabs: RTab[]; current: RTab; goApprovals: () => void }) {
  const sameServer = (t: RTab) => t.url.replace(/\/+$/, "") === current.url.replace(/\/+$/, "");
  const [picked, setPicked] = useState<string[]>(() => tabs.filter(sameServer).map((t) => t.id));
  const [mode, setMode] = useState<"sequence" | "parallel">("sequence");
  const [stop, setStop] = useState(false);
  const [approval, setApproval] = useState<string | undefined>();
  const [result, setResult] = useState<GroupResult | null>(null);
  const action = useAction();
  const chosen = tabs.filter((t) => picked.includes(t.id));
  const toggle = (id: string) => {
    setApproval(undefined);
    setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]));
  };
  const send = () =>
    action.run(async () => {
      const requests = await Promise.all(chosen.map(async (t) => ({ url: t.url, raw: t.raw, body_b64: await protoBodyOf(t.raw, t.pb), name: t.name })));
      const r = await api.post<GroupResult>("/replay/group", {
        requests,
        mode,
        stop_on_error: stop,
        identity: current.identity || undefined,
        fix_content_length: current.fixCl,
        approval_id: approval,
      });
      setResult(r);
      setApproval(r.status === "pending_approval" ? r.approval_id : undefined);
    });
  return (
    <div className="notice" data-testid="group-panel" style={{ marginBottom: 8 }}>
      <div className="row small" style={{ flexWrap: "wrap" }}>
        <strong>Send group</strong>
        {tabs.map((t) => (
          <label key={t.id} title={t.url} style={{ opacity: sameServer(t) ? 1 : 0.5 }}>
            <input type="checkbox" aria-label={`Group tab ${t.name}`} checked={picked.includes(t.id)} onChange={() => toggle(t.id)} /> {t.name}
          </label>
        ))}
      </div>
      <div className="row small">
        <select aria-label="Group mode" value={mode} onChange={(e) => { setMode(e.target.value as typeof mode); setApproval(undefined); }}>
          <option value="sequence">one after another</option>
          <option value="parallel">all at the same moment</option>
        </select>
        {mode === "sequence" && <label><input type="checkbox" checked={stop} onChange={(e) => setStop(e.target.checked)} /> stop at the first failure</label>}
        <button className="btn primary" data-testid="group-send" disabled={chosen.length < 2 || action.busy} onClick={send}>
          {approval ? "Send approved group" : `Send ${chosen.length} tabs`}
        </button>
        <span className="muted">All tabs in a group go to one server{current.url ? ` (${current.url})` : ""}, as this tab's identity.</span>
      </div>
      <ErrorBox error={action.error} />
      {result?.status === "denied" && <div className="error">Denied by the rules of engagement: {result.reasons.join("; ")}</div>}
      {result?.status === "pending_approval" && (
        <div className="small">
          {result.summary} needs approval ({result.reasons.join("; ")}). Approve <strong>{result.approval_id}</strong> on the{" "}
          <a href="#" onClick={(e) => { e.preventDefault(); goApprovals(); }}>Approvals</a> page, then send again.
        </div>
      )}
      {result?.status === "done" && (
        <table className="grid" data-testid="group-result">
          <thead><tr><th>Tab</th><th>Status</th><th>Time</th><th>Exchange</th></tr></thead>
          <tbody>
            {result.results.map((x) => (
              <tr key={x.index}>
                <td>{x.name ?? x.index + 1}</td>
                <td>{x.error ? <span className="bad">{x.error}</span> : <StatusCode status={x.status} />}</td>
                <td className="small muted">{x.elapsed_ms} ms</td>
                <td><ExchangeLink id={x.exchange_id} /></td>
              </tr>
            ))}
          </tbody>
          {result.parallel && <caption className="small muted">sent {result.parallel === "single_packet" ? "in one HTTP/2 packet" : "with last-byte sync"}</caption>}
        </table>
      )}
    </div>
  );
}
