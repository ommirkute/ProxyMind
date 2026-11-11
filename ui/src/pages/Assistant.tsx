import { useEffect, useRef, useState } from "react";
import { api, fmtTime, toast } from "../api";
import { Empty, ErrorBox, useAction, useLoad, useNav } from "../components";

type Block =
  | { type: "text"; text: string }
  | { type: "tool_use"; id: string; name: string; input: unknown }
  | { type: "tool_result"; tool_use_id: string; content: string; is_error: boolean };

interface Message {
  role: "user" | "assistant";
  content: Block[];
}

interface Config {
  provider: "anthropic" | "openai";
  base_url: string;
  model: string;
  api_key_env: string;
  max_steps: number;
  max_tokens: number;
}

interface State {
  config: Config;
  local: boolean;
  cloud_models_allowed: boolean;
  problem: string | null;
  acts_as: string;
  key?: { source: string; hint?: string };
  chats: { id: number; title: string; updated_ms: number }[];
}

interface Chat {
  id: number;
  title: string;
  messages: Message[];
}

interface Turn {
  chat_id: number;
  messages: Message[];
  note?: string;
}

const PRESETS: { label: string; cfg: Partial<Config> }[] = [
  { label: "Ollama (local)", cfg: { provider: "openai", base_url: "http://127.0.0.1:11434/v1", api_key_env: "" } },
  { label: "LM Studio (local)", cfg: { provider: "openai", base_url: "http://127.0.0.1:1234/v1", api_key_env: "" } },
  { label: "Anthropic", cfg: { provider: "anthropic", base_url: "https://api.anthropic.com/v1", api_key_env: "ANTHROPIC_API_KEY" } },
  { label: "OpenAI", cfg: { provider: "openai", base_url: "https://api.openai.com/v1", api_key_env: "OPENAI_API_KEY" } },
];

export default function Assistant() {
  const { go } = useNav();
  const state = useLoad(() => api.get<State>("/assistant"), []);
  const [chatId, setChatId] = useState<number | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [text, setText] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [draft, setDraft] = useState<Config | null>(null);
  const action = useAction();
  const save = useAction();
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => endRef.current?.scrollIntoView?.({ block: "end" }), [messages, action.busy]);

  const open = (id: number | null) => {
    setNote(null);
    action.setError(null);
    setChatId(id);
    if (id == null) return setMessages([]);
    api.get<Chat>(`/assistant/chats/${id}`).then((c) => setMessages(c.messages)).catch((e) => action.setError(e.message));
  };

  const send = () => {
    const t = text.trim();
    if (!t) return;
    setText("");
    setNote(null);
    setMessages((m) => [...m, { role: "user", content: [{ type: "text", text: t }] }]);
    action.run(async () => {
      try {
        const turn = await api.post<Turn>("/assistant/send", { chat_id: chatId, text: t });
        setChatId(turn.chat_id);
        // The server's copy replaces the optimistic user message.
        const chat = await api.get<Chat>(`/assistant/chats/${turn.chat_id}`);
        setMessages(chat.messages);
        setNote(turn.note ?? null);
      } finally {
        state.reload();
      }
    });
  };

  const cfg = draft ?? state.data?.config ?? null;
  const setCfg = (p: Partial<Config>) => cfg && setDraft({ ...cfg, ...p });
  const saveCfg = () =>
    cfg &&
    save.run(async () => {
      await api.put("/assistant/config", cfg);
      setDraft(null);
      state.reload();
    });

  const s = state.data;
  return (
    <div className="content assistant">
      <div className="assistant-layout">
        <aside className="panel chats">
          <button className="btn primary" style={{ width: "100%" }} onClick={() => open(null)}>New chat</button>
          <div className="chat-list">
            {s?.chats.map((c) => (
              <button key={c.id} className={`nav ${chatId === c.id ? "active" : ""}`} onClick={() => open(c.id)} title={fmtTime(c.updated_ms)}>
                <span className="ellipsis">{c.title}</span>
              </button>
            ))}
          </div>
        </aside>
        <section className="panel convo">
          <div className="row small muted" style={{ marginBottom: 8 }}>
            <span className="grow">
              {s ? (
                <>
                  {s.config.model} via <code>{s.config.base_url}</code> ({s.local ? "local" : "cloud"}) · acts as <code>{s.acts_as}</code>, within
                  the rules of engagement
                </>
              ) : (
                "Loading…"
              )}
            </span>
            <button className="btn" onClick={() => setSettingsOpen((o) => !o)}>{settingsOpen ? "Hide settings" : "Settings"}</button>
          </div>
          {s?.problem && (
            <div className="error" role="alert" data-testid="assistant-problem">
              {s.problem}
            </div>
          )}
          {settingsOpen && cfg && (
            <div className="assistant-settings">
              <div className="row small" style={{ marginBottom: 8 }}>
                Presets:
                {PRESETS.map((p) => (
                  <button key={p.label} className="btn" onClick={() => setCfg(p.cfg)}>{p.label}</button>
                ))}
              </div>
              <div className="form-grid">
                <label>API format</label>
                <select aria-label="Provider" value={cfg.provider} onChange={(e) => setCfg({ provider: e.target.value as Config["provider"] })}>
                  <option value="openai">OpenAI-compatible (OpenAI, Ollama, LM Studio, vLLM)</option>
                  <option value="anthropic">Anthropic</option>
                </select>
                <label>Base URL</label>
                <input aria-label="Base URL" value={cfg.base_url} onChange={(e) => setCfg({ base_url: e.target.value })} />
                <label>Model</label>
                <input aria-label="Model" placeholder="model name as the server lists it" value={cfg.model} onChange={(e) => setCfg({ model: e.target.value })} />
                <label>API key variable</label>
                <input
                  aria-label="API key environment variable"
                  placeholder="e.g. ANTHROPIC_API_KEY (empty for local servers)"
                  value={cfg.api_key_env}
                  onChange={(e) => setCfg({ api_key_env: e.target.value })}
                />
                <label>API key</label>
                <KeyField name={cfg.api_key_env} status={s?.config.api_key_env === cfg.api_key_env ? s?.key : undefined} onChange={state.reload} />
                <label>Max steps per message</label>
                <input aria-label="Max steps" type="number" min={1} max={50} value={cfg.max_steps} onChange={(e) => setCfg({ max_steps: Number(e.target.value) })} />
              </div>
              <p className="small muted">
                Paste the key here and press Save key: it is kept on this computer only (in your ProxyMind folder, readable by you),
                never in the project file, and never shown again. An environment variable of the same name, if set, takes precedence.
                The AI scan uses the same model and key. Cloud models also need{" "}
                <code>allow_cloud_models: true</code> in the rules of engagement
                {s && ` (currently ${s.cloud_models_allowed ? "allowed" : "not allowed"})`}.
              </p>
              <ErrorBox error={save.error} />
              <button className="btn primary" data-testid="assistant-save" disabled={!draft || save.busy} onClick={saveCfg}>Save settings</button>
            </div>
          )}
          <div className="transcript" data-testid="assistant-transcript">
            {messages.length === 0 && (
              <Empty>
                Ask about the traffic you recorded, e.g. “Which endpoints take an object id, and has anyone tested them for IDOR?” The assistant reads
                history and can send requests, but only within scope; risky steps wait for your approval.
              </Empty>
            )}
            {messages.map((m, i) => (
              <MessageView key={i} m={m} />
            ))}
            {action.busy && <div className="muted small">Thinking…</div>}
            {note && <div className="notice">{note}</div>}
            <ErrorBox error={action.error} />
            <div ref={endRef} />
          </div>
          <Playbooks onPick={(t) => setText(t)} />
          <div className="row composer">
            <textarea
              aria-label="Message"
              rows={3}
              className="grow"
              placeholder="Message the assistant (Enter to send, Shift+Enter for a new line)"
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  send();
                }
              }}
            />
            <button className="btn primary" data-testid="assistant-send" disabled={action.busy || !text.trim()} onClick={send}>Send</button>
          </div>
          <p className="small muted" style={{ marginBottom: 0 }}>
            Requests it wants to send that need approval appear in <a href="#" onClick={(e) => { e.preventDefault(); go("approvals"); }}>Approvals</a>. Everything it does is in the audit log.
          </p>
        </section>
      </div>
    </div>
  );
}

function MessageView({ m }: { m: Message }) {
  return (
    <>
      {m.content.map((b, i) => {
        if (b.type === "text") {
          return (
            <div key={i} className={`bubble ${m.role}`}>
              {b.text}
            </div>
          );
        }
        if (b.type === "tool_use") {
          return (
            <div key={i} className="tool-call" data-testid="tool-call">
              → <strong>{b.name}</strong> <span className="mono small muted">{JSON.stringify(b.input).slice(0, 300)}</span>
            </div>
          );
        }
        return (
          <details key={i} className={`tool-result ${b.is_error ? "bad" : ""}`}>
            <summary className="small">{b.is_error ? "tool error" : "tool result"} ({b.content.length} chars)</summary>
            <pre className="raw">{b.content.slice(0, 5000)}</pre>
          </details>
        );
      })}
    </>
  );
}

interface Skill { name: string; title: string; description: string; args: string[]; source: string }

/** Testing playbooks (skills): picking one puts its steps in the message box, with an optional focus. */
function Playbooks({ onPick }: { onPick: (text: string) => void }) {
  const [skills, setSkills] = useState<Skill[]>([]);
  const [name, setName] = useState("");
  const [focus, setFocus] = useState("");
  useEffect(() => {
    api.get<Skill[]>("/skills").then(setSkills).catch(() => {});
  }, []);
  const pick = async () => {
    if (!name) return;
    const r = await api.post<{ text: string }>(`/skills/${encodeURIComponent(name)}`, focus.trim() ? { focus: focus.trim() } : {});
    onPick(r.text);
  };
  if (skills.length === 0) return null;
  const chosen = skills.find((s) => s.name === name);
  return (
    <div className="row small" data-testid="playbooks">
      <select aria-label="Playbook" value={name} onChange={(e) => setName(e.target.value)}>
        <option value="">Playbook…</option>
        {skills.map((s) => (
          <option key={s.name} value={s.name}>{s.title}{s.source === "user" ? " (yours)" : ""}</option>
        ))}
      </select>
      {chosen?.args.includes("focus") && (
        <input aria-label="Playbook focus" placeholder="focus (optional), e.g. /api/orders" value={focus} onChange={(e) => setFocus(e.target.value)} style={{ width: 220 }} />
      )}
      <button className="btn" disabled={!name} onClick={() => void pick()} data-testid="playbook-use">Use</button>
      {chosen && <span className="muted">{chosen.description}</span>}
    </div>
  );
}

/** Saves the model API key on this computer (never in the project); shows only where it comes from. */
function KeyField({ name, status, onChange }: { name: string; status?: { source: string; hint?: string }; onChange: () => void }) {
  const [key, setKey] = useState("");
  const action = useAction();
  if (!name) return <span className="small muted">Not needed for local servers. Set the variable name above first for a cloud API.</span>;
  const save = () =>
    action.run(async () => {
      await api.put("/assistant/key", { name, key });
      setKey("");
      toast("API key saved on this computer");
      onChange();
    });
  const remove = () =>
    action.run(async () => {
      await api.del(`/assistant/key/${encodeURIComponent(name)}`);
      toast("Saved API key removed");
      onChange();
    });
  return (
    <div className="row small" data-testid="assistant-key">
      <input type="password" autoComplete="off" aria-label="API key" placeholder={`paste the ${name} value`} value={key} onChange={(e) => setKey(e.target.value)} style={{ width: 260 }} />
      <button className="btn" disabled={!key.trim() || action.busy} onClick={save} data-testid="assistant-key-save">Save key</button>
      {status?.source === "saved" && <button className="btn" disabled={action.busy} onClick={remove}>Remove</button>}
      <span className="muted" data-testid="assistant-key-status">
        {status?.source === "saved" ? `saved (${status.hint})` : status?.source === "environment" ? `from the environment (${status.hint})` : "no key yet"}
      </span>
      <ErrorBox error={action.error} />
    </div>
  );
}
