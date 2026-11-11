import { useEffect, useState } from "react";
import { api, toast } from "../api";
import { AttackGraph } from "../AttackGraph";
import { Chip, Empty, ErrorBox, Panel, copyText, useAction, useLoad } from "../components";

interface Log { ts_ms: number; kind: string; text: string }
interface Scan {
  id: number; target: string; focus: string; status: string; phase: string; model: string;
  steps: number; max_steps: number; deadline_ms: number; actor: string; started_by: string;
  created_ms: number; updated_ms: number; error: string; report: string; findings: number; log: Log[];
  tokens_in: number; tokens_out: number; cost: number; max_cost: number;
}
interface AssistantState { config: { model: string; base_url: string }; local: boolean; cloud_models_allowed: boolean; problem?: string | null }

const PHASES = ["recon", "scanning", "exploitation", "chaining", "report"];
const active = (s: Scan) => s.status === "running" || s.status === "stopping";
const time = (ms: number) => new Date(ms).toLocaleTimeString();
const fmtTokens = (n: number) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : String(n));
const usd = (n: number) => "$" + n.toFixed(2);
function costText(s: Scan): string {
  const tokens = `${fmtTokens((s.tokens_in ?? 0) + (s.tokens_out ?? 0))} tokens`;
  if (!s.cost && !s.max_cost) return tokens;
  return `${tokens} · ${usd(s.cost ?? 0)}${s.max_cost ? ` of ${usd(s.max_cost)}` : ""}`;
}

function download(name: string, text: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/** AI scan: the configured model assesses the target on its own, from recon to chained proofs. */
export default function AiScan() {
  const state = useLoad(() => api.get<AssistantState>("/assistant"), []);
  const scans = useLoad(() => api.get<Scan[]>("/ai-scan"), []);
  const [selected, setSelected] = useState<number | null>(null);
  const list = scans.data ?? [];
  useEffect(() => {
    if (selected === null && list.length > 0) setSelected(list[0].id);
  }, [list, selected]);
  return (
    <div className="content">
      <Start state={state.data} stateError={state.error} onStarted={(id) => { setSelected(id); scans.reload(); }} />
      {list.length > 0 && (
        <Panel title="Runs">
          <table className="grid" data-testid="ai-scan-runs">
            <thead><tr><th>#</th><th>Status</th><th>Phase</th><th>Steps</th><th>Findings</th><th>Target</th><th>Started</th></tr></thead>
            <tbody>
              {list.map((s) => (
                <tr key={s.id} className={selected === s.id ? "selected" : ""} onClick={() => setSelected(s.id)} style={{ cursor: "pointer" }}>
                  <td>{s.id}</td>
                  <td><Chip value={s.status} /></td>
                  <td>{s.phase}</td>
                  <td className="mono small">{s.steps}/{s.max_steps}</td>
                  <td>{s.findings}</td>
                  <td className="mono small">{s.target}</td>
                  <td className="small">{new Date(s.created_ms).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
      {selected !== null && <Run id={selected} onChange={scans.reload} />}
    </div>
  );
}

function Start({ state, stateError, onStarted }: { state: AssistantState | null; stateError: string | null; onStarted: (id: number) => void }) {
  const [target, setTarget] = useState("");
  const [focus, setFocus] = useState("");
  const [steps, setSteps] = useState(150);
  const [minutes, setMinutes] = useState(60);
  const [maxCost, setMaxCost] = useState(0);
  const [prompt, setPrompt] = useState<string | null>(null);
  const action = useAction();
  useEffect(() => {
    api.get<{ target: string; prompt: string }>("/ai-scan/prompt").then((p) => { setTarget((t) => t || p.target); setPrompt(p.prompt); }).catch(() => {});
  }, []);
  const start = () =>
    action.run(async () => {
      const s = await api.post<Scan>("/ai-scan", { target: target || undefined, focus: focus || undefined, max_steps: steps, max_minutes: minutes, max_cost: maxCost > 0 ? maxCost : undefined });
      toast(`AI scan #${s.id} started`);
      onStarted(s.id);
    });
  return (
    <Panel title="AI scan">
      <p className="small muted">
        An AI agent assesses the target on its own: recon, scanning, exploitation to proof of concept, chaining findings
        into attack paths, and a report. It acts as its own agent through the rules of engagement: out-of-scope requests
        are refused, risky steps wait in <a href="#/approvals">Approvals</a>, and everything is in the audit log. It uses
        the model set on the <a href="#/assistant">Assistant</a> page.
      </p>
      <ErrorBox error={stateError} />
      {state && (
        <p className="small" data-testid="ai-scan-model">
          Model: <b>{state.config.model || "not set"}</b> at <code>{state.config.base_url}</code> ({state.local ? "local" : "cloud"})
          {state.problem && <span style={{ color: "var(--bad)" }}> · {state.problem}</span>}
        </p>
      )}
      <div className="row">
        <input aria-label="AI scan target" placeholder="target URL (default: the scope)" value={target} onChange={(e) => setTarget(e.target.value)} style={{ width: 320 }} />
        <input aria-label="AI scan focus" placeholder="focus (optional), e.g. the API and login" value={focus} onChange={(e) => setFocus(e.target.value)} style={{ width: 260 }} />
        <label className="small">steps <input type="number" aria-label="AI scan steps" min={1} max={1000} value={steps} onChange={(e) => setSteps(Number(e.target.value))} style={{ width: 80 }} /></label>
        <label className="small">minutes <input type="number" aria-label="AI scan minutes" min={1} max={1440} value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} style={{ width: 80 }} /></label>
        <label className="small">max USD <input type="number" aria-label="AI scan max cost" min={0} step="0.5" value={maxCost} onChange={(e) => setMaxCost(Number(e.target.value))} style={{ width: 80 }} title="0: no cost limit. Needs prices in the assistant settings." /></label>
        <button className="btn primary" onClick={start} disabled={action.busy || !!state?.problem} data-testid="ai-scan-start">Start AI scan</button>
      </div>
      <ErrorBox error={action.error} />
      {prompt && (
        <details className="small">
          <summary>System prompt</summary>
          <p className="muted">Replace it by saving your own as <code>~/.proxymind/ai-scan-prompt.md</code> (keep <code>{"{{target}}"}</code>, <code>{"{{scope}}"}</code> and <code>{"{{focus}}"}</code>).</p>
          <pre className="raw small" style={{ maxHeight: 320, overflow: "auto" }}>{prompt}</pre>
        </details>
      )}
    </Panel>
  );
}

function Run({ id, onChange }: { id: number; onChange: () => void }) {
  const [s, setS] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const load = () =>
      api.get<Scan>(`/ai-scan/${id}`).then((r) => {
        if (stop) return;
        setS(r);
        setError(null);
        if (active(r)) timer = setTimeout(load, 2000);
        else onChange();
      }).catch((e: Error) => !stop && setError(e.message));
    load();
    return () => { stop = true; clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);
  const stopScan = async () => {
    setS(await api.post<Scan>(`/ai-scan/${id}/stop`, {}));
    toast("Stopping after the current step");
  };
  if (error) return <ErrorBox error={error} />;
  if (!s) return null;
  const at = PHASES.indexOf(s.phase);
  return (
    <>
    <Panel
      title={`AI scan #${s.id}`}
      actions={active(s) && s.status === "running" ? <button className="btn" onClick={() => void stopScan()} data-testid="ai-scan-stop">Stop</button> : undefined}
    >
      <div className="row small" data-testid="ai-scan-status">
        <Chip value={s.status} />
        <span className="mono">{s.target}</span>
        <span>{s.steps}/{s.max_steps} model calls</span>
        <span data-testid="ai-scan-cost">{costText(s)}</span>
        <span><a href="#/findings">{s.findings} finding(s)</a></span>
        <span className="muted">model {s.model} · acts as {s.actor}</span>
        {s.error && <span style={{ color: "var(--bad)" }}>{s.error}</span>}
      </div>
      <div className="row" aria-label="Phases" data-testid="ai-scan-phases">
        {PHASES.map((p, i) => (
          <span key={p} className={`chip ${i < at ? "ok" : i === at ? "accent" : ""}`}>{i + 1}. {p}</span>
        ))}
      </div>
      {s.status === "running" && <Say id={s.id} onSent={setS} />}
      {s.report && (
        <details open className="small" data-testid="ai-scan-report">
          <summary>
            Report{" "}
            <button className="btn sm" onClick={(e) => { e.preventDefault(); download(`ai-scan-${s.id}-report.md`, s.report); }}>Download .md</button>{" "}
            <button className="btn sm" onClick={(e) => { e.preventDefault(); copyText(s.report); toast("Report copied"); }}>Copy</button>
          </summary>
          <pre className="raw small" style={{ whiteSpace: "pre-wrap", maxHeight: 480, overflow: "auto" }}>{s.report}</pre>
        </details>
      )}
      <h3 className="small muted">Activity</h3>
      {s.log.length === 0 ? <Empty>Nothing yet.</Empty> : (
        <table className="grid" data-testid="ai-scan-log">
          <tbody>
            {[...s.log].reverse().slice(0, 300).map((l, i) => (
              <tr key={i}>
                <td className="small muted" style={{ whiteSpace: "nowrap" }}>{time(l.ts_ms)}</td>
                <td><Chip value={l.kind} /></td>
                <td className="small mono" style={{ wordBreak: "break-word" }}>{l.text}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
    <AttackGraph scan={s.id} refresh={`${s.updated_ms}:${s.status}`} title={`Attack paths of AI scan #${s.id}`} />
    </>
  );
}

/** Sends the running agent a message: it reads it with its next step. */
function Say({ id, onSent }: { id: number; onSent: (s: Scan) => void }) {
  const [text, setText] = useState("");
  const action = useAction();
  const send = () =>
    action.run(async () => {
      onSent(await api.post<Scan>(`/ai-scan/${id}/message`, { text }));
      setText("");
      toast("Sent: the agent reads it with its next step");
    });
  return (
    <div className="row">
      <input aria-label="Message the agent" placeholder="Message the agent: “focus on checkout”, “skip /admin”, “why did you try that?”" value={text}
        onChange={(e) => setText(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && text.trim()) void send(); }} style={{ flex: 1, minWidth: 240 }} />
      <button className="btn" onClick={() => void send()} disabled={action.busy || !text.trim()} data-testid="ai-scan-say">Send</button>
      <ErrorBox error={action.error} />
    </div>
  );
}
