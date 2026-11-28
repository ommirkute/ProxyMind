import { useEffect, useState } from "react";
import { api } from "../api";
import type { Edit, ExtractType, RunStatus, Side, Step, StepStatus, Workflow, WorkflowRun } from "../api-types.gen";
import { Empty, ErrorBox, ExchangeLink, Panel, useAction, useLoad, useNav } from "../components";
import { useLiveTick } from "../live";
import { TRANSFORMS } from "../transforms";

type StepType = Step["type"];
type Of<T extends StepType> = Extract<Step, { type: T }>;

/** What the editor holds: a workflow without the fields the server manages. */
interface Draft {
  id?: number;
  name: string;
  description: string;
  steps: Step[];
}

const KINDS: { type: StepType; label: string; help: string }[] = [
  { type: "match", label: "match", help: "Stop here unless the exchange fits." },
  { type: "extract", label: "extract", help: "Read a value into a variable." },
  { type: "transform", label: "transform", help: "Encode, decode or hash a value, or build one from a template." },
  { type: "send", label: "send", help: "Send a request through the rules of engagement." },
  { type: "assert", label: "assert", help: "Check the answer; a failed check fails the run, which goes on." },
];

const NEW_STEP: { [K in StepType]: () => Of<K> } = {
  match: () => ({ type: "match", status: "2xx" }),
  extract: () => ({ type: "extract", name: "token", kind: "json", expr: "/token" }),
  transform: () => ({ type: "transform", name: "auth", value: "Bearer {{token}}", ops: [] }),
  send: () => ({ type: "send", raw: "GET / HTTP/1.1\nHost: \n\n", edits: [] }),
  assert: () => ({ type: "assert", status: "200" }),
};

const EXPR_HINT: Record<ExtractType, string> = {
  regex: 'token=([a-z0-9]+)',
  json: "/data/token",
  header: "X-CSRF-Token",
  cookie: "session",
  html_input: "csrf",
};

const STATUS_CLASS: Record<string, string> = {
  ok: "ok",
  failed: "bad",
  stopped: "info",
  denied: "bad",
  pending_approval: "warn",
  running: "info",
};

function StatusChip({ status }: { status: RunStatus | StepStatus }) {
  return <span className={`chip ${STATUS_CLASS[status] ?? ""}`} data-testid="run-status">{status.replace(/_/g, " ")}</span>;
}

const opt = (v: string | null | undefined) => v ?? "";
const nul = (v: string) => (v === "" ? null : v);

/** Workflows: saved chains of steps that run on an exchange, on new traffic, or on each Fuzzer result. */
export default function Workflows() {
  const { arg } = useNav();
  const tick = useLiveTick(["workflows"]);
  const list = useLoad(() => api.get<Workflow[]>("/workflows"), [tick]);
  const runs = useLoad(() => api.get<WorkflowRun[]>("/workflows/runs?limit=50"), [tick]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [exchange, setExchange] = useState(arg ? String(arg) : "");
  const [result, setResult] = useState<WorkflowRun | null>(null);
  const [shown, setShown] = useState<number | null>(null);
  const action = useAction();
  useEffect(() => {
    if (arg) setExchange(String(arg));
  }, [arg]);

  const workflows = list.data ?? [];
  const edit = (w: Workflow) => setDraft({ id: w.id, name: w.name, description: w.description, steps: structuredClone(w.steps) });
  const save = () =>
    action.run(async () => {
      if (!draft) return;
      const body = { name: draft.name, description: draft.description, steps: draft.steps };
      const w = draft.id ? await api.put<Workflow>(`/workflows/${draft.id}`, body) : await api.post<Workflow>("/workflows", body);
      setDraft(null);
      list.reload();
      setResult(null);
      return w;
    });
  const remove = (w: Workflow) =>
    action.run(async () => {
      if (!window.confirm(`Delete workflow ${w.name} and its runs?`)) return;
      await api.del(`/workflows/${w.id}`);
      list.reload();
      runs.reload();
    });
  const run = (w: Workflow, approval?: string, onExchange?: number | null) =>
    action.run(async () => {
      const ex = onExchange ?? (exchange.trim() ? Number(exchange) : undefined);
      const r = await api.post<WorkflowRun>(`/workflows/${w.id}/run`, { exchange_id: ex, approval_id: approval });
      setResult(r);
      setShown(null);
      runs.reload();
    });
  const trigger = (w: Workflow, enabled: boolean, max?: number) =>
    action.run(async () => {
      await api.put(`/workflows/${w.id}/trigger`, { enabled, max_per_minute: max });
      list.reload();
    });

  const detail = shown != null ? runs.data?.find((r) => r.id === shown) ?? null : result;
  const byId = new Map(workflows.map((w) => [w.id, w]));

  return (
    <div className="content" data-testid="workflows-page">
      <p className="muted small" style={{ marginTop: 0 }}>
        A workflow is a saved chain of steps working on the <em>current exchange</em>: <code>match</code> it, <code>extract</code> values
        into variables, <code>transform</code> them, <code>send</code> a request (its answer becomes the current exchange) and{" "}
        <code>assert</code> on it. Every send goes through the rules of engagement like Replay does, and shows in HTTP history as{" "}
        <code>workflow</code>. Steps run once, in order: there are no loops. At most 50 steps, 20 sends and 2 minutes per run.
        Use <code>{"{{name}}"}</code> to put a variable into a request; <code>{"{{current_status}}"}</code>, <code>current_host</code>,{" "}
        <code>current_path</code>… describe the current exchange.
      </p>
      <ErrorBox error={list.error ?? action.error} />
      <Panel
        title="Workflows"
        actions={
          <button className="btn primary" data-testid="wf-new" onClick={() => setDraft({ name: "", description: "", steps: [NEW_STEP.send()] })}>
            New workflow
          </button>
        }
      >
        <div className="row small" style={{ marginBottom: 8 }}>
          <label htmlFor="wf-exchange">Run on exchange #</label>
          <input id="wf-exchange" aria-label="Run on exchange" type="number" min={1} value={exchange} onChange={(e) => setExchange(e.target.value)} style={{ width: 90 }} />
          <span className="muted">(leave empty for a workflow whose first step sends a request of its own)</span>
        </div>
        {workflows.length === 0 && !list.loading && <Empty>No workflows yet. Create one, or right-click an exchange in HTTP history.</Empty>}
        {workflows.length > 0 && (
          <table className="grid" data-testid="wf-list">
            <thead>
              <tr>
                <th>Name</th>
                <th>Steps</th>
                <th>On new traffic</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {workflows.map((w) => (
                <tr key={w.id} data-testid="wf-row">
                  <td>
                    <strong>{w.name}</strong>
                    {w.description && <div className="small muted">{w.description}</div>}
                  </td>
                  <td className="small mono">{w.steps.map((s) => s.type).join(" → ")}</td>
                  <td className="small">
                    <label className="row" style={{ gap: 4 }} title="Runs by itself on each new proxied exchange that fits the first match step, as you, at most this many per minute. Editing the steps turns it off.">
                      <input
                        type="checkbox"
                        aria-label={`Run ${w.name} on new traffic`}
                        checked={w.trigger.enabled}
                        disabled={action.busy || w.steps[0]?.type !== "match"}
                        onChange={(e) => trigger(w, e.target.checked)}
                      />
                      {w.trigger.enabled ? "on" : "off"}
                    </label>
                    {w.trigger.enabled && (
                      <span className="muted">
                        {" "}
                        max{" "}
                        <input
                          aria-label={`${w.name} runs per minute`}
                          type="number"
                          min={1}
                          max={60}
                          defaultValue={w.trigger.max_per_minute}
                          style={{ width: 54 }}
                          onBlur={(e) => Number(e.target.value) !== w.trigger.max_per_minute && trigger(w, true, Number(e.target.value))}
                        />{" "}
                        per minute{w.trigger.skipped > 0 ? `, ${w.trigger.skipped} skipped` : ""}
                      </span>
                    )}
                    {w.steps[0]?.type !== "match" && <span className="muted"> needs a first match step</span>}
                  </td>
                  <td>
                    <div className="row" style={{ justifyContent: "flex-end" }}>
                      <button className="btn" data-testid="wf-run" disabled={action.busy} onClick={() => run(w)}>
                        {exchange.trim() ? `Run on exchange #${exchange.trim()}` : "Run"}
                      </button>
                      <button className="btn" data-testid="wf-edit" onClick={() => edit(w)}>Edit</button>
                      <button className="btn" aria-label={`Delete ${w.name}`} onClick={() => remove(w)}>✕</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {draft && <Editor draft={draft} onChange={setDraft} onSave={save} onCancel={() => setDraft(null)} busy={action.busy} />}

      {detail && (
        <Panel title={`Run #${detail.id} of ${detail.workflow_name}`} actions={<button className="btn" onClick={() => { setResult(null); setShown(null); }}>Close</button>}>
          <RunDetail run={detail} onContinue={(approval) => { const w = byId.get(detail.workflow_id); if (w) run(w, approval, detail.start_exchange ?? null); }} busy={action.busy} />
        </Panel>
      )}

      <Panel title="Run history" actions={<button className="btn" onClick={() => runs.reload()}>Refresh</button>}>
        <ErrorBox error={runs.error} />
        {(runs.data?.length ?? 0) === 0 && <Empty>No runs yet.</Empty>}
        {(runs.data?.length ?? 0) > 0 && (
          <table className="grid" data-testid="wf-runs">
            <thead>
              <tr>
                <th>Run</th>
                <th>Workflow</th>
                <th>Started by</th>
                <th>Status</th>
                <th>Steps</th>
                <th>Sent</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {runs.data!.map((r) => (
                <tr key={r.id} className={`clickable ${shown === r.id ? "selected" : ""}`} data-testid="wf-run-row" onClick={() => { setShown(r.id); setResult(null); }}>
                  <td>#{r.id}</td>
                  <td>{r.workflow_name}</td>
                  <td className="small">{r.actor} <span className="muted">({r.trigger}{r.start_exchange ? ` on #${r.start_exchange}` : ""})</span></td>
                  <td><StatusChip status={r.status} /></td>
                  <td>{r.steps.length}</td>
                  <td>{r.exchanges.map((id) => <span key={id} style={{ marginRight: 6 }}><ExchangeLink id={id} /></span>)}</td>
                  <td className="small">{r.duration_ms} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

/** One run: status, each step with the exchange it sent, assertions, variables, and where it waits for approval. */
function RunDetail({ run, onContinue, busy }: { run: WorkflowRun; onContinue: (approval: string) => void; busy: boolean }) {
  const vars = Object.entries(run.variables);
  return (
    <div data-testid="run-detail">
      <div className="row">
        <StatusChip status={run.status} />
        <span className="small muted">
          {run.actor} · {run.trigger}
          {run.start_exchange ? <> on <ExchangeLink id={run.start_exchange} /></> : null} · {run.duration_ms} ms · {run.sends} send(s)
        </span>
      </div>
      {run.reason && <p className="small" data-testid="run-reason">{run.reason}</p>}
      {run.pending && (
        <div className="notice warn" role="status" data-testid="run-pending">
          Step {run.pending.step} waits for approval <code>{run.pending.approval_id}</code>: {run.pending.summary}. Approve it on the Approvals page, then continue: the earlier steps are not sent again.
          <div className="row" style={{ marginTop: 6 }}>
            <button className="btn" data-testid="run-continue" disabled={busy} onClick={() => onContinue(run.pending!.approval_id)}>Continue</button>
          </div>
        </div>
      )}
      <table className="grid" data-testid="run-steps" style={{ marginTop: 8 }}>
        <thead>
          <tr>
            <th>#</th>
            <th>Step</th>
            <th>Result</th>
            <th>What happened</th>
            <th>Exchange</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {run.steps.map((s) => (
            <tr key={s.step} data-testid="run-step">
              <td>{s.step}</td>
              <td className="mono">{s.kind}</td>
              <td><StatusChip status={s.status} /></td>
              <td className="small">{s.message}</td>
              <td><ExchangeLink id={s.exchange_id} /></td>
              <td className="small">{s.elapsed_ms} ms</td>
            </tr>
          ))}
        </tbody>
      </table>
      {vars.length > 0 && (
        <p className="small" data-testid="run-variables">
          Variables:{" "}
          {vars.map(([k, v]) => (
            <span key={k} className="chip mono" title={v} style={{ marginRight: 4 }}>{k} = {v.length > 32 ? v.slice(0, 32) + "…" : v}</span>
          ))}
        </p>
      )}
    </div>
  );
}

function Editor({ draft, onChange, onSave, onCancel, busy }: { draft: Draft; onChange: (d: Draft) => void; onSave: () => void; onCancel: () => void; busy: boolean }) {
  const setStep = (i: number, patch: Partial<Step>) => onChange({ ...draft, steps: draft.steps.map((s, j) => (j === i ? ({ ...s, ...patch } as Step) : s)) });
  const move = (i: number, d: number) => {
    const to = i + d;
    if (to < 0 || to >= draft.steps.length) return;
    const steps = [...draft.steps];
    [steps[i], steps[to]] = [steps[to], steps[i]];
    onChange({ ...draft, steps });
  };
  return (
    <Panel title={draft.id ? `Edit ${draft.name || "workflow"}` : "New workflow"}>
      <div className="form-grid">
        <label htmlFor="wf-name">Name</label>
        <input id="wf-name" aria-label="Workflow name" value={draft.name} onChange={(e) => onChange({ ...draft, name: e.target.value })} />
        <label htmlFor="wf-desc">What it is for</label>
        <input id="wf-desc" aria-label="Workflow description" value={draft.description} onChange={(e) => onChange({ ...draft, description: e.target.value })} />
      </div>
      {draft.steps.map((s, i) => (
        <div key={i} className="session-card" data-testid="wf-step">
          <div className="row">
            <strong>{i + 1}.</strong>
            <select aria-label={`Step ${i + 1} type`} value={s.type} onChange={(e) => onChange({ ...draft, steps: draft.steps.map((x, j) => (j === i ? NEW_STEP[e.target.value as StepType]() : x)) })}>
              {KINDS.map((k) => <option key={k.type} value={k.type}>{k.label}</option>)}
            </select>
            <span className="small muted grow">{KINDS.find((k) => k.type === s.type)?.help}</span>
            <button className="btn" aria-label={`Move step ${i + 1} up`} disabled={i === 0} onClick={() => move(i, -1)}>↑</button>
            <button className="btn" aria-label={`Move step ${i + 1} down`} disabled={i === draft.steps.length - 1} onClick={() => move(i, 1)}>↓</button>
            <button className="btn" aria-label={`Remove step ${i + 1}`} disabled={draft.steps.length < 2} onClick={() => onChange({ ...draft, steps: draft.steps.filter((_, j) => j !== i) })}>✕</button>
          </div>
          {(s.type === "match" || s.type === "assert") && <ConditionForm n={i + 1} step={s} set={(p) => setStep(i, p)} />}
          {s.type === "extract" && <ExtractForm n={i + 1} step={s} set={(p) => setStep(i, p)} />}
          {s.type === "transform" && <TransformForm n={i + 1} step={s} set={(p) => setStep(i, p)} />}
          {s.type === "send" && <SendForm n={i + 1} step={s} set={(p) => setStep(i, p)} />}
        </div>
      ))}
      <div className="row small" style={{ margin: "8px 0" }}>
        <span className="muted">Add a step:</span>
        {KINDS.map((k) => (
          <button key={k.type} className="btn small" data-testid={`add-${k.type}`} aria-label={`Add ${k.label} step`} title={k.help} onClick={() => onChange({ ...draft, steps: [...draft.steps, NEW_STEP[k.type]()] })}>
            + {k.label}
          </button>
        ))}
      </div>
      <div className="row">
        <button className="btn primary" data-testid="wf-save" disabled={busy || !draft.name.trim()} onClick={onSave}>Save workflow</button>
        <button className="btn" onClick={onCancel}>Cancel</button>
      </div>
    </Panel>
  );
}

type SetFn<T> = (patch: Partial<T>) => void;

function ConditionForm({ n, step, set }: { n: number; step: Of<"match"> | Of<"assert">; set: SetFn<Of<"match"> | Of<"assert">> }) {
  const text = (label: string, key: keyof Of<"match">, placeholder: string, width?: number) => (
    <>
      <label>{label}</label>
      <input
        aria-label={`Step ${n} ${label}`}
        className="mono"
        placeholder={placeholder}
        value={opt(step[key] as string | null | undefined)}
        onChange={(e) => set({ [key]: nul(e.target.value) } as Partial<Of<"match">>)}
        style={width ? { width } : undefined}
      />
    </>
  );
  return (
    <div className="form-grid" style={{ marginTop: 8 }}>
      {text("status", "status", "200, 2xx, 200..299 or 200,302")}
      {text("method", "method", "POST or GET,HEAD")}
      {text("path contains", "path_contains", "/api/orders")}
      {text("header", "header", "name, e.g. Location")}
      {step.header && text("header contains", "header_contains", "text it contains")}
      {text("body contains", "body_contains", "text (may use {{variable}})")}
      {text("body regex", "body_regex", 'e.g. "token":"\\w+"')}
      {text("HQL", "hql", 'e.g. status:200 resp:"welcome"')}
      {text("variable", "var", "a variable that must be set")}
      {step.var && text("equals", "var_equals", "exact value")}
      <label>Look at</label>
      <select aria-label={`Step ${n} side`} value={step.side ?? "response"} onChange={(e) => set({ side: e.target.value as Side })}>
        <option value="response">the response</option>
        <option value="request">the request</option>
      </select>
      <label>Reversed</label>
      <label className="small"><input type="checkbox" aria-label={`Step ${n} negate`} checked={!!step.negate} onChange={(e) => set({ negate: e.target.checked })} /> pass when the tests do NOT all hold</label>
      {text("message", "message", step.type === "assert" ? "what a failed check says" : "why the run stops")}
    </div>
  );
}

function ExtractForm({ n, step, set }: { n: number; step: Of<"extract">; set: SetFn<Of<"extract">> }) {
  const kind = step.kind ?? "regex";
  return (
    <div className="form-grid" style={{ marginTop: 8 }}>
      <label>Variable</label>
      <input aria-label={`Step ${n} variable`} className="mono" value={step.name ?? ""} onChange={(e) => set({ name: e.target.value })} />
      <label>Read</label>
      <div className="row">
        <select aria-label={`Step ${n} kind`} value={kind} onChange={(e) => set({ kind: e.target.value as ExtractType })}>
          <option value="regex">regex (group 1)</option>
          <option value="json">JSON pointer</option>
          <option value="header">header</option>
          <option value="cookie">cookie</option>
          <option value="html_input">HTML input value</option>
        </select>
        <input aria-label={`Step ${n} expression`} className="grow mono" placeholder={EXPR_HINT[kind]} value={step.expr ?? ""} onChange={(e) => set({ expr: e.target.value })} />
      </div>
      {kind === "regex" && (
        <>
          <label>Group</label>
          <input aria-label={`Step ${n} group`} type="number" min={0} placeholder="1" value={step.group ?? ""} onChange={(e) => set({ group: e.target.value === "" ? null : Number(e.target.value) })} style={{ width: 80 }} />
        </>
      )}
      <label>From</label>
      <div className="row">
        <select aria-label={`Step ${n} source`} value={step.side ?? "response"} onChange={(e) => set({ side: e.target.value as Side })}>
          <option value="response">the response</option>
          <option value="request" disabled={kind === "html_input"}>the request</option>
        </select>
        <label className="small"><input type="checkbox" aria-label={`Step ${n} optional`} checked={!!step.optional} onChange={(e) => set({ optional: e.target.checked })} /> optional: go on when nothing is found</label>
      </div>
    </div>
  );
}

function TransformForm({ n, step, set }: { n: number; step: Of<"transform">; set: SetFn<Of<"transform">> }) {
  const ops = step.ops ?? [];
  return (
    <div className="form-grid" style={{ marginTop: 8 }}>
      <label>Variable</label>
      <input aria-label={`Step ${n} variable`} className="mono" value={step.name ?? ""} onChange={(e) => set({ name: e.target.value })} />
      <label>Starts as</label>
      <input aria-label={`Step ${n} value`} className="mono" placeholder="{{token}} or user:{{name}}" value={step.value ?? ""} onChange={(e) => set({ value: e.target.value })} />
      <label>Then apply</label>
      <div className="row">
        {ops.map((o, k) => (
          <span key={k} className="chip mono">
            {o}{" "}
            <button className="btn small" aria-label={`Remove ${o}`} onClick={() => set({ ops: ops.filter((_, j) => j !== k) })}>×</button>
          </span>
        ))}
        <select aria-label={`Step ${n} add operation`} value="" onChange={(e) => e.target.value && set({ ops: [...ops, e.target.value] })}>
          <option value="">add an operation…</option>
          {TRANSFORMS.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
        </select>
      </div>
    </div>
  );
}

function SendForm({ n, step, set }: { n: number; step: Of<"send">; set: SetFn<Of<"send">> }) {
  const edits = step.edits ?? [];
  const setEdit = (k: number, e: Edit) => set({ edits: edits.map((x, j) => (j === k ? e : x)) });
  const kindOf = (e: Edit) => e.op;
  const fresh = (op: Edit["op"]): Edit =>
    op === "set_header" ? { op, name: "", value: "" } : op === "remove_header" ? { op, name: "" } : op === "set_param" ? { op, name: "", value: "" } : { op, find: "", replace: "" };
  return (
    <div className="form-grid" style={{ marginTop: 8 }}>
      <label>Send to</label>
      <input aria-label={`Step ${n} target`} className="mono" placeholder="scheme://host:port (empty: the current exchange's server)" value={step.url ?? ""} onChange={(e) => set({ url: nul(e.target.value) })} />
      <label>Request</label>
      <div>
        <textarea
          aria-label={`Step ${n} request`}
          className="mono"
          rows={6}
          spellCheck={false}
          style={{ width: "100%" }}
          placeholder="empty: send the current exchange's request, with the edits below"
          value={step.raw ?? ""}
          onChange={(e) => set({ raw: nul(e.target.value) })}
        />
        <div className="small muted">
          {"{{variable}}"} and {"{{secret:NAME}}"} are filled in when the step runs. The target cannot contain variables.
        </div>
      </div>
      <label>Edits</label>
      <div>
        {edits.map((e, k) => (
          <div key={k} className="row" style={{ marginBottom: 4 }}>
            <select aria-label={`Step ${n} edit ${k + 1} kind`} value={kindOf(e)} onChange={(ev) => setEdit(k, fresh(ev.target.value as Edit["op"]))}>
              <option value="set_header">set header</option>
              <option value="remove_header">remove header</option>
              <option value="set_param">set parameter</option>
              <option value="replace_text">replace text</option>
            </select>
            {(e.op === "set_header" || e.op === "remove_header" || e.op === "set_param") && (
              <input aria-label={`Step ${n} edit ${k + 1} name`} className="mono" placeholder="name" value={e.name} onChange={(ev) => setEdit(k, { ...e, name: ev.target.value })} style={{ width: 150 }} />
            )}
            {(e.op === "set_header" || e.op === "set_param") && (
              <input aria-label={`Step ${n} edit ${k + 1} value`} className="grow mono" placeholder="value, e.g. Bearer {{token}}" value={e.value} onChange={(ev) => setEdit(k, { ...e, value: ev.target.value })} />
            )}
            {e.op === "replace_text" && (
              <>
                <input aria-label={`Step ${n} edit ${k + 1} find`} className="mono" placeholder="find" value={e.find} onChange={(ev) => setEdit(k, { ...e, find: ev.target.value })} style={{ width: 170 }} />
                <input aria-label={`Step ${n} edit ${k + 1} replace`} className="grow mono" placeholder="replace with" value={e.replace} onChange={(ev) => setEdit(k, { ...e, replace: ev.target.value })} />
                <label className="small"><input type="checkbox" checked={!!e.regex} onChange={(ev) => setEdit(k, { ...e, regex: ev.target.checked })} /> regex</label>
              </>
            )}
            <button className="btn" aria-label={`Remove edit ${k + 1}`} onClick={() => set({ edits: edits.filter((_, j) => j !== k) })}>×</button>
          </div>
        ))}
        <button className="btn small" onClick={() => set({ edits: [...edits, fresh("set_header")] })}>Add edit</button>
      </div>
      <label>Send as</label>
      <input aria-label={`Step ${n} identity`} placeholder="a test identity (empty: as written)" value={step.identity ?? ""} onChange={(e) => set({ identity: nul(e.target.value) })} style={{ width: 240 }} />
    </div>
  );
}
