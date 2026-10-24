import { useState } from "react";
import { api } from "../api";
import { Chip, ErrorBox, ExchangeLink, Panel, useAction } from "../components";

interface Step { op: string; output: string }
interface DiffLine { op: "same" | "added" | "removed"; text: string }
interface LineDiff { lines: DiffLine[]; added: number; removed: number; truncated: boolean }
interface Analysis {
  samples: number; unique: number; min_len: number; max_len: number; alphabet: string;
  estimated_bits: number; sample_limit_bits: number; constant_positions: number[]; sequential_step?: number;
  rating: string; notes: string[];
}
type SeqResult =
  | { status: "done"; requests: number; found: number; analysis: Analysis; exchange_ids: number[] }
  | { status: "pending_approval"; summary: string }
  | { status: "denied"; reasons: string[] };

const OPS = ["base64_decode", "base64_encode", "base64url_decode", "url_decode", "url_encode", "html_decode", "html_encode", "hex_decode", "hex_encode", "unicode_unescape", "gzip_decode", "jwt_decode", "sha256", "sha1"];

export default function Tools() {
  return (
    <div className="content">
      <Decoder />
      <Comparer />
      <Sequencer />
    </div>
  );
}

function Decoder() {
  const [input, setInput] = useState("");
  const [ops, setOps] = useState<string[]>([]);
  const [steps, setSteps] = useState<Step[] | null>(null);
  const action = useAction();
  const run = () => action.run(async () => setSteps((await api.post<{ steps: Step[] }>("/tools/decode", { input, ops })).steps));
  return (
    <Panel title="Decoder">
      <textarea aria-label="Decoder input" className="mono" rows={3} value={input} onChange={(e) => setInput(e.target.value)} style={{ width: "100%" }} placeholder="text, base64, a JWT, %-encoded…" />
      <div className="row small" style={{ marginTop: 6 }}>
        <select aria-label="Add operation" value="" onChange={(e) => e.target.value && setOps([...ops, e.target.value])}>
          <option value="">add a step…</option>
          {OPS.map((o) => <option key={o}>{o}</option>)}
        </select>
        {ops.map((o, i) => <span key={i} className="chip" onClick={() => setOps(ops.filter((_, j) => j !== i))} title="remove">{o} ✕</span>)}
        <button className="btn primary" disabled={!input || action.busy} onClick={run} data-testid="decode">{ops.length ? "Run steps" : "Smart decode"}</button>
        <span className="muted">Runs locally; nothing is sent.</span>
      </div>
      <ErrorBox error={action.error} />
      {steps && steps.length === 0 && <p className="small muted">Nothing to decode.</p>}
      {steps?.map((s, i) => (
        <div key={i} style={{ marginTop: 6 }}>
          <div className="small muted">{i + 1}. {s.op}</div>
          <pre className="mono small" data-testid="decode-step" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0 }}>{s.output}</pre>
        </div>
      ))}
    </Panel>
  );
}

function DiffView({ d }: { d: LineDiff }) {
  return (
    <pre className="mono small" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 300, overflow: "auto" }}>
      {d.lines.map((l, i) => (
        <div key={i} style={{ background: l.op === "added" ? "rgba(34,160,90,.15)" : l.op === "removed" ? "rgba(210,60,60,.15)" : undefined }}>
          {l.op === "added" ? "+ " : l.op === "removed" ? "- " : "  "}{l.text}
        </div>
      ))}
    </pre>
  );
}

function Comparer() {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [r, setR] = useState<{ response_semantic?: { similarity: number; summary: string }; request_lines: LineDiff; response_lines: LineDiff } | null>(null);
  const action = useAction();
  const run = () => action.run(async () => setR(await api.post("/tools/compare", { a: Number(a), b: Number(b) })));
  return (
    <Panel title="Comparer">
      <div className="row small">
        <span>Exchange</span><input aria-label="Compare A" value={a} onChange={(e) => setA(e.target.value)} style={{ width: 70 }} />
        <span>with</span><input aria-label="Compare B" value={b} onChange={(e) => setB(e.target.value)} style={{ width: 70 }} />
        <button className="btn primary" disabled={!a || !b || action.busy} onClick={run} data-testid="compare">Compare</button>
      </div>
      <ErrorBox error={action.error} />
      {r && (
        <>
          {r.response_semantic && <p className="small" data-testid="compare-summary">Responses {Math.round(r.response_semantic.similarity * 100)}% similar: {r.response_semantic.summary}</p>}
          <div className="split">
            <div><h3>Requests (+{r.request_lines.added} −{r.request_lines.removed})</h3><DiffView d={r.request_lines} /></div>
            <div><h3>Responses (+{r.response_lines.added} −{r.response_lines.removed})</h3><DiffView d={r.response_lines} /></div>
          </div>
        </>
      )}
    </Panel>
  );
}

function Sequencer() {
  const [ex, setEx] = useState("");
  const [locator, setLocator] = useState("cookie:session");
  const [samples, setSamples] = useState(100);
  const [r, setR] = useState<SeqResult | null>(null);
  const action = useAction();
  const run = () => action.run(async () => setR(await api.post<SeqResult>("/tools/sequencer", { exchange_id: Number(ex), locator, samples })));
  return (
    <Panel title="Sequencer">
      <div className="row small">
        <span>Re-send exchange</span><input aria-label="Token exchange" value={ex} onChange={(e) => setEx(e.target.value)} style={{ width: 70 }} />
        <input aria-label="Samples" type="number" min={10} max={500} value={samples} onChange={(e) => setSamples(Number(e.target.value))} style={{ width: 70 }} />
        <span>times; token at</span>
        <input aria-label="Token locator" className="mono" value={locator} onChange={(e) => setLocator(e.target.value)} style={{ width: 220 }} title="cookie:<name>, header:<name>, json:/pointer or between:<a>|<b>" />
        <button className="btn primary" disabled={!ex || action.busy} onClick={run} data-testid="sequencer">{action.busy ? "Collecting…" : "Analyse"}</button>
      </div>
      <p className="small muted">Shows statistics only; the tokens are live secrets. It can show a token is weak, never that it is strong.</p>
      <ErrorBox error={action.error} />
      {r?.status === "pending_approval" && <div className="notice">Needs approval: {r.summary}</div>}
      {r?.status === "denied" && <div className="error">Denied: {r.reasons.join("; ")}</div>}
      {r?.status === "done" && (
        <div data-testid="sequencer-result">
          <div className="row"><Chip value={r.analysis.rating} /><strong>~{r.analysis.estimated_bits} bits</strong><span className="small muted">({r.found} of {r.requests} responses had a token; a sample this size can show at most {r.analysis.sample_limit_bits} bits)</span></div>
          <ul className="small">
            <li>{r.analysis.unique} unique, length {r.analysis.min_len}–{r.analysis.max_len}, alphabet <code>{r.analysis.alphabet}</code></li>
            {r.analysis.notes.map((n) => <li key={n}>{n}</li>)}
          </ul>
          <div className="small muted">Requests: {r.exchange_ids.slice(0, 5).map((e) => <span key={e}><ExchangeLink id={e} /> </span>)}…</div>
        </div>
      )}
    </Panel>
  );
}
