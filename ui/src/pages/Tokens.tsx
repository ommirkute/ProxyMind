// API tokens (`pm3_…`) for agents, CI jobs and plugins (ADR-0022 step 5). Shown in two places: the Account page (server
// mode) and About (single-user mode). A token is shown once, in the answer of the create call; the list never has it.
// Tokens can't manage tokens: this panel is a person's.
import { useState, type FormEvent } from "react";
import { api, fmtDateTime, toast } from "../api";
import type {
  OkResponse,
  TierName,
  TokenCreated,
  TokenKindName,
  TokenRoleName,
  TokenView,
} from "../api-types.gen";
import { CopyButton, Field } from "../authparts";
import { Empty, ErrorBox, Panel, useAction, useLoad } from "../components";

const when = (secs: number | null | undefined) => (secs ? fmtDateTime(secs * 1000) : "never");

const STATUS: Record<string, string> = { active: "ok", expired: "warn", revoked: "bad" };

const CAPS: Array<[TierName | "", string]> = [
  ["", "no cap (the rules decide)"],
  ["read", "read only"],
  ["passive", "passive (sends nothing)"],
  ["active_safe", "safe requests (GET, HEAD, OPTIONS)"],
  ["active_intrusive", "state-changing requests"],
];

/**
 * `serverMode`: tokens belong to accounts; owners of the project may list everyone's and make tokens for others (which
 * asks for a fresh sign-in; the API client repeats the call after it).
 */
export function TokensPanel({ serverMode = false, isOwner = false }: { serverMode?: boolean; isOwner?: boolean }) {
  const [everyone, setEveryone] = useState(false);
  const list = useLoad(() => api.get<TokenView[]>(`/tokens${everyone ? "?all=true" : ""}`), [everyone]);
  const [kind, setKind] = useState<TokenKindName>("agent");
  const [name, setName] = useState("");
  const [role, setRole] = useState<TokenRoleName>("tester");
  const [cap, setCap] = useState<TierName | "">("");
  const [days, setDays] = useState("30");
  const [forUser, setForUser] = useState("");
  const [made, setMade] = useState<TokenCreated | null>(null);
  const { busy, error, run } = useAction();
  const create = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const n = Math.max(1, Math.min(365, Math.round(Number(days)) || 30));
      const body: Record<string, unknown> = { kind, name: name.trim(), role, expires_days: n };
      if (cap) body.tier_cap = cap;
      if (serverMode && isOwner && forUser.trim()) body.for_user = forUser.trim();
      setMade(await api.post<TokenCreated>("/tokens", body));
      setName("");
      list.reload();
    });
  };
  const revoke = (t: TokenView) =>
    void run(async () => {
      if (!window.confirm(`Revoke ${t.actor}? It stops working at its next request.`)) return;
      await api.del<OkResponse>(`/tokens/${encodeURIComponent(t.id)}`);
      toast(`${t.actor} revoked`);
      if (made?.id === t.id) setMade(null);
      list.reload();
    });
  const rows = list.data ?? [];
  return (
    <Panel
      title="API tokens"
      actions={
        serverMode && isOwner ? (
          <label className="small">
            <input type="checkbox" checked={everyone} onChange={(e) => setEveryone(e.target.checked)} data-testid="tokens-all" />{" "}
            Everyone's tokens
          </label>
        ) : undefined
      }
    >
      <p className="small muted" data-testid="tokens-intro">
        For agents, CI jobs and plugins. A token acts as <span className="mono">agent:&lt;name&gt;</span> (or{" "}
        <span className="mono">ci:</span>, <span className="mono">plugin:</span>), never as you, with at most the role
        you pick{serverMode ? " and never more than its owner's role" : ""}, and at most the highest tier you allow; the
        rules of engagement can only narrow that further. It is sent as <span className="mono">Authorization: Bearer</span>,
        shown once here, and a token cannot create or revoke tokens.
      </p>
      <form onSubmit={create} className="row" style={{ alignItems: "flex-end", flexWrap: "wrap", marginBottom: 12 }}>
        <div className="field" style={{ margin: 0 }}>
          <label>
            <span>Acts as</span>
            <select value={kind} onChange={(e) => setKind(e.target.value as TokenKindName)} data-testid="token-kind">
              <option value="agent">agent</option>
              <option value="ci">ci</option>
              <option value="plugin">plugin</option>
            </select>
          </label>
        </div>
        <Field label="Name" value={name} onChange={setName} testid="token-name" hint="letters, digits and - _ . @" />
        <div className="field" style={{ margin: 0 }}>
          <label>
            <span>Role at most</span>
            <select value={role} onChange={(e) => setRole(e.target.value as TokenRoleName)} data-testid="token-role">
              <option value="tester">tester</option>
              <option value="viewer">viewer (read only)</option>
            </select>
          </label>
        </div>
        <div className="field" style={{ margin: 0 }}>
          <label>
            <span>Highest tier</span>
            <select value={cap} onChange={(e) => setCap(e.target.value as TierName | "")} data-testid="token-cap">
              {CAPS.map(([v, text]) => (
                <option key={v} value={v}>{text}</option>
              ))}
            </select>
          </label>
        </div>
        <div className="field" style={{ margin: 0 }}>
          <label>
            <span>Expires in (days)</span>
            <input type="number" min={1} max={365} value={days} onChange={(e) => setDays(e.target.value)} data-testid="token-days" />
          </label>
        </div>
        {serverMode && isOwner && (
          <Field label="For user (optional)" value={forUser} onChange={setForUser} testid="token-for-user" hint="another member; asks you to sign in again" />
        )}
        <button className="btn primary" type="submit" disabled={busy || !name.trim()} data-testid="token-create">Create token</button>
      </form>
      <ErrorBox error={error ?? list.error} />
      {made && (
        <div className="notice" data-testid="token-made">
          <p>
            <b>{made.actor}</b> is ready. Copy the token now: it is shown once and ProxyMind keeps only a hash of it.
          </p>
          <div className="row">
            <input className="mono" readOnly value={made.token} style={{ flex: 1 }} onFocus={(e) => e.target.select()} data-testid="token-value" aria-label="The new token" />
            <CopyButton text={made.token} label="Copy token" testid="token-copy" />
            <button className="btn sm" onClick={() => setMade(null)} data-testid="token-dismiss">I've saved it</button>
          </div>
        </div>
      )}
      {rows.length === 0 ? (
        <Empty>No tokens yet.</Empty>
      ) : (
        <table className="grid" data-testid="tokens-table">
          <thead>
            <tr>
              <th>Actor</th>
              {serverMode && <th>Owner</th>}
              <th>Role</th>
              <th>Highest tier</th>
              <th>Status</th>
              <th>Expires</th>
              <th>Last used</th>
              <th>Uses</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((t) => (
              <tr key={t.id} data-testid={`token-${t.actor}`}>
                <td className="mono">{t.actor}</td>
                {serverMode && <td>{t.owner_name ?? "–"}</td>}
                <td>{t.role}</td>
                <td>{t.tier_cap ?? "rules decide"}</td>
                <td><span className={`chip ${STATUS[t.status] ?? ""}`}>{t.status}</span></td>
                <td>{when(t.expires_at)}</td>
                <td>{when(t.last_used_at)}</td>
                <td>{t.use_count}</td>
                <td>
                  {t.status === "active" && (
                    <button className="btn sm bad" disabled={busy} onClick={() => revoke(t)} data-testid={`token-revoke-${t.actor}`}>Revoke</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
