// Server mode only: the signed-in person's account (sessions, password, authenticator, recovery codes) and, for server
// administrators and project owners, users and invites. Sensitive actions answer 403 `fresh_login_required`; the API
// client (api.ts) then asks the person to sign in again and repeats the action once.
import { useState, type FormEvent } from "react";
import { api, fmtDateTime, toast } from "../api";
import type {
  EnrolmentLinkCreated,
  InviteCreated,
  InviteView,
  MemberView,
  OkResponse,
  PasskeyRequiredResponse,
  PasskeyView,
  RecoveryCodesResponse,
  RevokedResponse,
  RoleName,
  SessionView,
  StateResponse,
  TotpEnrolmentResponse,
  UserView,
} from "../api-types.gen";
import { CopyButton, Field, RecoveryCodesView, TotpSecret, useAuth } from "../authparts";
import { Empty, ErrorBox, Panel, useAction, useLoad } from "../components";
import { LinkedIdentities, OidcProviders } from "../oidcparts";
import { PasskeyAdd, usePasskeyUse } from "../passkeyparts";
import { TokensPanel } from "./Tokens";

const when = (secs: number | null | undefined) => (secs ? fmtDateTime(secs * 1000) : "never");

export default function Account() {
  const auth = useAuth();
  const [tick, setTick] = useState(0);
  if (!auth) return <Empty>Accounts exist only when ProxyMind runs as a project server (proxymind serve).</Empty>;
  const { me } = auth;
  return (
    <div className="content" data-testid="account-page">
      <div className="page-head">
        <div>
          <h1>My account</h1>
          <p>Who you are on this server, where you are signed in, and how you prove it.</p>
        </div>
      </div>
      <Panel title="Who I am">
        <dl className="kv" data-testid="account-who">
          <dt>User</dt>
          <dd>{me.user.display_name ? `${me.user.display_name} (${me.user.username})` : me.user.username}</dd>
          <dt>Actor</dt>
          <dd className="mono" data-testid="account-actor">{me.actor}</dd>
          <dt>Role in this project</dt>
          <dd data-testid="account-role">{me.role ?? "none"}</dd>
          <dt>Server administrator</dt>
          <dd>{me.user.server_admin ? "yes" : "no"}</dd>
          <dt>Project</dt>
          <dd className="mono">{me.project_id}</dd>
          <dt>This session</dt>
          <dd>{me.session.auth_method.replace(/\+/g, " + ")}, signed in {when(me.session.authenticated_at)}</dd>
        </dl>
      </Panel>
      <Sessions reloadKey={tick} />
      {me.role && me.role !== "viewer" && <TokensPanel serverMode isOwner={me.role === "owner"} />}
      <Passkeys onChanged={() => setTick((t) => t + 1)} />
      <LinkedIdentities />
      <Password onChanged={() => setTick((t) => t + 1)} />
      <Authenticator />
      <RecoveryCodes />
      <Panel title="Sign out">
        <p className="small muted">Ends this session in this browser.</p>
        <button className="btn" data-testid="account-sign-out" onClick={() => void auth.logout()}>Sign out</button>
      </Panel>
    </div>
  );
}

// ---- sessions --------------------------------------------------------------------------------------------------

function Sessions({ reloadKey }: { reloadKey: number }) {
  const list = useLoad(() => api.get<SessionView[]>("/auth/sessions"), [reloadKey]);
  const { busy, error, run } = useAction();
  const rows = list.data ?? [];
  const others = rows.filter((s) => !s.current);
  return (
    <Panel
      title="My sessions"
      actions={
        <button
          className="btn sm"
          data-testid="sessions-revoke-others"
          disabled={busy || others.length === 0}
          onClick={() =>
            void run(async () => {
              const r = await api.post<RevokedResponse>("/auth/sessions/revoke-all", { keep_current: true });
              toast(`Signed out of ${r.revoked} other session${r.revoked === 1 ? "" : "s"}`);
              list.reload();
            })
          }
        >
          Sign out everywhere else
        </button>
      }
    >
      <ErrorBox error={error ?? list.error} />
      {rows.length === 0 ? (
        <Empty>No sessions.</Empty>
      ) : (
        <table className="grid" data-testid="sessions-table">
          <thead>
            <tr>
              <th>Browser</th>
              <th>Address</th>
              <th>Signed in</th>
              <th>Last seen</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.reference} data-testid={s.current ? "session-current" : "session-other"}>
                <td title={s.user_agent ?? ""}>
                  <span className="ellipsis" style={{ maxWidth: 320 }}>{s.user_agent ?? "unknown"}</span>
                </td>
                <td className="mono">{s.client_addr ?? "–"}</td>
                <td>{when(s.authenticated_at)}</td>
                <td>{when(s.last_seen_at)}</td>
                <td>
                  {s.current ? (
                    <span className="chip ok">this session</span>
                  ) : (
                    <button
                      className="btn sm bad"
                      disabled={busy}
                      onClick={() =>
                        void run(async () => {
                          await api.del<OkResponse>(`/auth/sessions/${encodeURIComponent(s.reference)}`);
                          toast("Session signed out");
                          list.reload();
                        })
                      }
                    >
                      Sign out
                    </button>
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

// ---- passkeys --------------------------------------------------------------------------------------------------

/** The account's passkeys: add, rename, remove. Adding and removing need a fresh sign-in (api.ts asks for it). */
function Passkeys({ onChanged }: { onChanged: () => void }) {
  const auth = useAuth()!;
  const use = usePasskeyUse();
  const list = useLoad(() => api.get<PasskeyView[]>("/auth/passkeys"), []);
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null);
  const { busy, error, run } = useAction();
  const rows = list.data ?? [];
  const changed = () => {
    list.reload();
    void auth.refresh();
    onChanged();
  };
  const rename = (e: FormEvent) => {
    e.preventDefault();
    if (!renaming) return;
    void run(async () => {
      await api.put<OkResponse>(`/auth/passkeys/${encodeURIComponent(renaming.id)}`, { name: renaming.name });
      setRenaming(null);
      toast("Passkey renamed");
      list.reload();
    });
  };
  const remove = (p: PasskeyView) =>
    void run(async () => {
      if (!window.confirm(`Remove the passkey “${p.name}”? You will be signed out of your other sessions.`)) return;
      await api.del<OkResponse>(`/auth/passkeys/${encodeURIComponent(p.id)}`);
      toast("Passkey removed. Your other sessions were signed out.");
      changed();
    });
  return (
    <Panel title="Passkeys">
      <p className="small muted">
        A passkey signs you in with your device's fingerprint, face, PIN or a security key, and cannot be phished. Add one
        for each device you use; a password and authenticator app stay as a fallback.
        {use.rpId && <> They are bound to the host name <span className="mono" data-testid="passkey-rp">{use.rpId}</span>: if the
        server's name changes, they stop working.</>}
      </p>
      <ErrorBox error={error ?? list.error} />
      {rows.length === 0 ? (
        <Empty>No passkeys yet.</Empty>
      ) : (
        <table className="grid" data-testid="passkeys-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Added</th>
              <th>Last used</th>
              <th>Kind</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <tr key={p.id} data-testid="passkey-row">
                <td>
                  {renaming?.id === p.id ? (
                    <form onSubmit={rename} className="row">
                      <input
                        aria-label="Passkey name"
                        value={renaming.name}
                        onChange={(e) => setRenaming({ id: p.id, name: e.target.value })}
                        autoFocus
                        data-testid="passkey-rename-input"
                      />
                      <button className="btn sm primary" type="submit" disabled={busy} data-testid="passkey-rename-save">Save</button>
                      <button className="btn sm ghost" type="button" onClick={() => setRenaming(null)}>Cancel</button>
                    </form>
                  ) : (
                    <span data-testid="passkey-name-cell">{p.name}</span>
                  )}
                </td>
                <td>{when(p.created_at)}</td>
                <td>{when(p.last_used_at)}</td>
                <td>
                  {p.transports.length ? p.transports.join(", ") : "–"}
                  {p.backup_state && <span className="chip plain" style={{ marginLeft: 6 }}>synced</span>}
                </td>
                <td>
                  <div className="row">
                    <button className="btn sm" disabled={busy} onClick={() => setRenaming({ id: p.id, name: p.name })} data-testid="passkey-rename">Rename</button>
                    <button className="btn sm bad" disabled={busy} onClick={() => remove(p)} data-testid="passkey-remove">Remove</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div style={{ marginTop: 12 }}>
        <PasskeyAdd onAdded={() => { toast("Passkey added"); changed(); }} />
      </div>
    </Panel>
  );
}

// ---- password --------------------------------------------------------------------------------------------------

function Password({ onChanged }: { onChanged: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [local, setLocal] = useState<string | null>(null);
  const { busy, error, run } = useAction();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (next !== again) return setLocal("The two new passwords are not the same.");
    setLocal(null);
    void run(async () => {
      await api.post<OkResponse>("/auth/password", { current, new_password: next });
      setCurrent("");
      setNext("");
      setAgain("");
      toast("Password changed. Your other sessions were signed out.");
      onChanged();
    });
  };
  return (
    <Panel title="Password">
      <form onSubmit={submit} style={{ maxWidth: 380 }}>
        <Field label="Current password" type="password" value={current} onChange={setCurrent} autoComplete="current-password" testid="pw-current" required />
        <Field label="New password" type="password" value={next} onChange={setNext} autoComplete="new-password" testid="pw-new" hint="At least 12 characters." required />
        <Field label="Confirm new password" type="password" value={again} onChange={setAgain} autoComplete="new-password" testid="pw-again" required />
        <ErrorBox error={local ?? error} />
        <button className="btn" type="submit" disabled={busy} data-testid="pw-submit">Change password</button>
      </form>
    </Panel>
  );
}

// ---- authenticator ---------------------------------------------------------------------------------------------

function Authenticator() {
  const auth = useAuth()!;
  const [enrol, setEnrol] = useState<TotpEnrolmentResponse | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const { busy, error, run, setError } = useAction();
  const confirm = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const r = await api.post<RecoveryCodesResponse>("/auth/totp/confirm", { code: code.replace(/\s+/g, "") });
      setEnrol(null);
      setCode("");
      setCodes(r.recovery_codes);
      void auth.refresh();
    });
  };
  return (
    <Panel title="Authenticator app">
      {codes ? (
        <RecoveryCodesView codes={codes} onDone={() => setCodes(null)} />
      ) : enrol ? (
        <form onSubmit={confirm} style={{ maxWidth: 520 }}>
          <p>Scan the code with your authenticator app, then enter the 6-digit code it shows. The old authenticator stops working once this is confirmed.</p>
          <TotpSecret enrol={enrol} />
          <Field label="Authentication code" value={code} onChange={setCode} autoComplete="one-time-code" inputMode="numeric" testid="totp-code" autoFocus required />
          <ErrorBox error={error} />
          <div className="row">
            <button className="btn primary" type="submit" disabled={busy} data-testid="totp-confirm">Confirm</button>
            <button type="button" className="btn ghost" onClick={() => { setEnrol(null); setError(null); }}>Cancel</button>
          </div>
        </form>
      ) : (
        <>
          <p className="small muted">
            Sign-in asks for a code from your authenticator app. Setting up a new one replaces the old one and gives you new
            recovery codes.
          </p>
          <ErrorBox error={error} />
          <div className="row">
            <button
              className="btn"
              disabled={busy}
              data-testid="totp-begin"
              onClick={() => void run(async () => setEnrol(await api.post<TotpEnrolmentResponse>("/auth/totp/begin")))}
            >
              Set up a new authenticator
            </button>
            <button
              className="btn bad"
              disabled={busy}
              data-testid="totp-disable"
              onClick={() =>
                void run(async () => {
                  if (!window.confirm("Turn off the authenticator? You will be signed out everywhere. (Some accounts must keep one.)")) return;
                  await api.post<OkResponse>("/auth/totp/disable");
                  auth.sessionEnded();
                })
              }
            >
              Turn off authenticator
            </button>
          </div>
        </>
      )}
    </Panel>
  );
}

function RecoveryCodes() {
  const [codes, setCodes] = useState<string[] | null>(null);
  const { busy, error, run } = useAction();
  return (
    <Panel title="Recovery codes">
      {codes ? (
        <RecoveryCodesView codes={codes} onDone={() => setCodes(null)} />
      ) : (
        <>
          <p className="small muted">Single-use codes that sign you in if you lose your authenticator. New codes replace all earlier ones.</p>
          <ErrorBox error={error} />
          <button
            className="btn"
            disabled={busy}
            data-testid="recovery-regenerate"
            onClick={() =>
              void run(async () => {
                if (!window.confirm("Make new recovery codes? The old ones stop working.")) return;
                setCodes((await api.post<RecoveryCodesResponse>("/auth/recovery-codes")).recovery_codes);
              })
            }
          >
            Make new recovery codes
          </button>
        </>
      )}
    </Panel>
  );
}

// ---- administration --------------------------------------------------------------------------------------------

export function Admin() {
  const auth = useAuth();
  if (!auth) return <Empty>Accounts exist only when ProxyMind runs as a project server (proxymind serve).</Empty>;
  const isAdmin = auth.me.user.server_admin;
  const isOwner = auth.me.role === "owner";
  if (!isAdmin && !isOwner) return <Empty>Only server administrators and project owners can manage users and invites.</Empty>;
  return (
    <div className="content" data-testid="admin-page">
      <div className="page-head">
        <div>
          <h1>Users &amp; invites</h1>
          <p>Who has an account on this server, and the links that let new people join the project.</p>
        </div>
      </div>
      {isAdmin && <PasskeyRule />}
      {isAdmin && <OidcProviders />}
      {isOwner && <Members selfId={auth.me.user.id} />}
      {isAdmin && <Users selfId={auth.me.user.id} />}
      <Invites />
    </div>
  );
}

/** "Require a passkey" (server administrators). Turning it on needs a passkey on your own account. */
function PasskeyRule() {
  const auth = useAuth()!;
  const state = useLoad(() => api.get<StateResponse>("/auth/state"), []);
  const { busy, error, run } = useAction();
  const on = state.data?.passkey_required ?? false;
  const set = (required: boolean) =>
    void run(async () => {
      await api.put<PasskeyRequiredResponse>("/auth/settings/passkey-required", { required });
      toast(required ? "Passkeys are now required" : "Passkeys are no longer required");
      state.reload();
      void auth.refresh();
    });
  return (
    <Panel title="Passkeys on this server">
      <p className="small muted" data-testid="passkey-rule-text">
        With this on, every account must have a passkey. An account that has none can still sign in with its password and
        authenticator, but only to add one; an account that has one can sign in with it alone (a password is refused).
        You need a passkey on your own account first. Tokens for agents and CI are not affected.
      </p>
      <ErrorBox error={error ?? state.error} />
      <label className="row" style={{ gap: 8 }}>
        <input
          type="checkbox"
          checked={on}
          disabled={busy || state.loading}
          onChange={(e) => set(e.target.checked)}
          data-testid="passkey-required-toggle"
        />
        <span>Require a passkey for every account</span>
      </label>
    </Panel>
  );
}

/** A recovery link for someone who lost every way to sign in: shown once, with a copy button. */
function RecoveryLink({ created, onHide }: { created: EnrolmentLinkCreated; onHide: () => void }) {
  return (
    <div className="notice" data-testid="enrol-link-created">
      <p style={{ marginTop: 0 }}>
        <b>Recovery link for {created.username}</b>, valid until {when(created.expires_at)}. It replaces how they sign in,
        and their sessions and tokens were ended. The link is shown <b>only now</b>: send it to them.
      </p>
      <div className="row">
        <input aria-label="Recovery link" className="grow mono" readOnly value={created.url} onFocus={(e) => e.currentTarget.select()} data-testid="enrol-link-url" />
        <CopyButton text={created.url} label="Copy link" testid="enrol-link-copy" />
        <button className="btn ghost sm" onClick={onHide}>Hide</button>
      </div>
    </div>
  );
}

/** The project's members and their roles (owners). The server refuses to demote or remove the last owner. */
function Members({ selfId }: { selfId: string }) {
  const list = useLoad(() => api.get<MemberView[]>("/auth/members"), []);
  const auth = useAuth();
  const { busy, error, run } = useAction();
  const [link, setLink] = useState<EnrolmentLinkCreated | null>(null);
  const recover = (m: MemberView) =>
    void run(async () => {
      if (!window.confirm(`Make a recovery link for ${m.username}? Their sessions end, their tokens are revoked, and the link replaces how they sign in.`)) return;
      setLink(await api.post<EnrolmentLinkCreated>(`/auth/users/${encodeURIComponent(m.user_id)}/enrolment-link`));
    });
  const setRole = (m: MemberView, role: RoleName) =>
    void run(async () => {
      if (role === m.role) return;
      await api.put<OkResponse>(`/auth/members/${encodeURIComponent(m.user_id)}`, { role });
      toast(`${m.username} is now ${role}`);
      list.reload();
      // Changing your own role changes what this page may show.
      if (m.user_id === selfId) void auth?.refresh();
    });
  const remove = (m: MemberView) =>
    void run(async () => {
      if (!window.confirm(`Remove ${m.username} from the project? Their sessions end and their tokens stop working.`)) return;
      await api.del<OkResponse>(`/auth/members/${encodeURIComponent(m.user_id)}`);
      toast(`${m.username} removed`);
      list.reload();
    });
  return (
    <Panel title="Members">
      <p className="small muted">
        What each role may do is in <code>docs/access.md</code>: owners manage the project, testers send traffic and write
        findings, viewers read the traffic with secrets hidden. A demotion ends the person's sessions at once; a promotion
        shows at their next request.
      </p>
      <ErrorBox error={error ?? list.error} />
      {link && <RecoveryLink created={link} onHide={() => setLink(null)} />}
      {(list.data ?? []).length === 0 ? (
        <Empty>No members.</Empty>
      ) : (
        <table className="grid" data-testid="members-table">
          <thead>
            <tr>
              <th>Username</th>
              <th>Name</th>
              <th>Role</th>
              <th>Status</th>
              <th>Member since</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(list.data ?? []).map((m) => (
              <tr key={m.user_id} data-testid={`member-${m.username}`}>
                <td>
                  {m.username}
                  {m.you && <span className="chip plain" style={{ marginLeft: 6 }}>you</span>}
                </td>
                <td>{m.display_name || "–"}</td>
                <td>
                  <select
                    aria-label={`Role of ${m.username}`}
                    value={m.role}
                    disabled={busy}
                    onChange={(e) => setRole(m, e.target.value as RoleName)}
                    data-testid={`member-role-${m.username}`}
                  >
                    <option value="owner">owner</option>
                    <option value="tester">tester</option>
                    <option value="viewer">viewer</option>
                  </select>
                </td>
                <td><span className={`chip ${m.status === "active" ? "ok" : "bad"}`}>{m.status}</span></td>
                <td>{when(m.since)}</td>
                <td>
                  <div className="row">
                    {!m.you && m.role !== "owner" && (
                      <button className="btn sm" disabled={busy} onClick={() => recover(m)} data-testid={`member-recover-${m.username}`}>
                        Recovery link
                      </button>
                    )}
                    <button className="btn sm bad" disabled={busy} onClick={() => remove(m)} data-testid={`member-remove-${m.username}`}>
                      Remove
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}

function Users({ selfId }: { selfId: string }) {
  const list = useLoad(() => api.get<UserView[]>("/auth/users"), []);
  const { busy, error, run } = useAction();
  const [link, setLink] = useState<EnrolmentLinkCreated | null>(null);
  const recover = (u: UserView) =>
    void run(async () => {
      if (!window.confirm(`Make a recovery link for ${u.username}? Their sessions end, their tokens are revoked, and the link replaces how they sign in.`)) return;
      setLink(await api.post<EnrolmentLinkCreated>(`/auth/users/${encodeURIComponent(u.id)}/enrolment-link`));
    });
  const act = (u: UserView, what: "disable" | "enable" | "reset-second-factor", done: string) =>
    void run(async () => {
      if (what === "reset-second-factor" && !window.confirm(`Remove ${u.username}'s second factor and end their sessions? They set up a new one at their next sign-in.`)) return;
      await api.post<OkResponse>(`/auth/users/${encodeURIComponent(u.id)}/${what}`);
      toast(`${u.username}: ${done}`);
      list.reload();
    });
  return (
    <Panel title="Users">
      <ErrorBox error={error ?? list.error} />
      {link && <RecoveryLink created={link} onHide={() => setLink(null)} />}
      {(list.data ?? []).length === 0 ? (
        <Empty>No users.</Empty>
      ) : (
        <table className="grid" data-testid="users-table">
          <thead>
            <tr>
              <th>Username</th>
              <th>Name</th>
              <th>Role</th>
              <th>Status</th>
              <th>Last sign-in</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(list.data ?? []).map((u) => (
              <tr key={u.id} data-testid={`user-${u.username}`}>
                <td>
                  {u.username}
                  {u.server_admin && <span className="chip accent" style={{ marginLeft: 6 }}>admin</span>}
                  {u.id === selfId && <span className="chip plain" style={{ marginLeft: 6 }}>you</span>}
                </td>
                <td>{u.display_name || "–"}</td>
                <td>{u.role ?? "no access"}</td>
                <td><span className={`chip ${u.status === "active" ? "ok" : "bad"}`}>{u.status}</span></td>
                <td>{when(u.last_login_at)}</td>
                <td>
                  {u.id !== selfId && (
                    <div className="row">
                      {u.status === "active" ? (
                        <button className="btn sm bad" disabled={busy} onClick={() => act(u, "disable", "disabled")}>Disable</button>
                      ) : (
                        <button className="btn sm ok" disabled={busy} onClick={() => act(u, "enable", "enabled")}>Enable</button>
                      )}
                      <button className="btn sm" disabled={busy} onClick={() => act(u, "reset-second-factor", "second factor reset")}>Reset second factor</button>
                      <button className="btn sm" disabled={busy} onClick={() => recover(u)} data-testid={`user-recover-${u.username}`}>Recovery link</button>
                    </div>
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

function inviteStatus(i: InviteView): { text: string; cls: string } {
  if (i.revoked_at) return { text: "revoked", cls: "bad" };
  if (i.used_at) return { text: "used", cls: "info" };
  if (i.expires_at * 1000 < Date.now()) return { text: "expired", cls: "warn" };
  return { text: "active", cls: "ok" };
}

function Invites() {
  const list = useLoad(() => api.get<InviteView[]>("/auth/invites"), []);
  const [role, setRole] = useState<RoleName>("tester");
  const [hours, setHours] = useState("72");
  const [created, setCreated] = useState<InviteCreated | null>(null);
  const { busy, error, run } = useAction();
  const create = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const n = Math.max(1, Math.min(720, Math.round(Number(hours)) || 72));
      setCreated(await api.post<InviteCreated>("/auth/invites", { role, ttl_hours: n }));
      list.reload();
    });
  };
  return (
    <Panel title="Invites">
      <form onSubmit={create} className="row" style={{ alignItems: "flex-end", marginBottom: 12 }}>
        <div className="field" style={{ margin: 0 }}>
          <label>
            <span>Role</span>
            <select value={role} onChange={(e) => setRole(e.target.value as RoleName)} data-testid="invite-role">
              <option value="owner">owner</option>
              <option value="tester">tester</option>
              <option value="viewer">viewer</option>
            </select>
          </label>
        </div>
        <div className="field" style={{ margin: 0 }}>
          <label>
            <span>Expires in (hours)</span>
            <input type="number" min={1} max={720} value={hours} onChange={(e) => setHours(e.target.value)} data-testid="invite-hours" />
          </label>
        </div>
        <button className="btn primary" type="submit" disabled={busy} data-testid="invite-create">Create invite</button>
      </form>
      <ErrorBox error={error ?? list.error} />
      {created && (
        <div className="notice" data-testid="invite-created">
          <p style={{ marginTop: 0 }}>
            <b>Invite for a {created.role}</b>, valid until {when(created.expires_at)}. The link is shown <b>only now</b>:
            copy it and send it to the person.
          </p>
          <div className="row">
            <input
              aria-label="Invite link"
              className="grow mono"
              readOnly
              value={created.url}
              onFocus={(e) => e.currentTarget.select()}
              data-testid="invite-url"
            />
            <CopyButton text={created.url} label="Copy link" testid="invite-copy" />
            <button className="btn ghost sm" onClick={() => setCreated(null)}>Hide</button>
          </div>
        </div>
      )}
      {(list.data ?? []).length === 0 ? (
        <Empty>No invites yet.</Empty>
      ) : (
        <table className="grid" data-testid="invites-table">
          <thead>
            <tr>
              <th>Role</th>
              <th>Created</th>
              <th>Expires</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(list.data ?? []).map((i) => {
              const st = inviteStatus(i);
              return (
                <tr key={i.id} data-testid={`invite-${i.id}`}>
                  <td>{i.role}</td>
                  <td>{when(i.created_at)}</td>
                  <td>{when(i.expires_at)}</td>
                  <td><span className={`chip ${st.cls}`}>{st.text}</span></td>
                  <td>
                    {st.text === "active" && (
                      <button
                        className="btn sm bad"
                        disabled={busy}
                        onClick={() =>
                          void run(async () => {
                            await api.del<OkResponse>(`/auth/invites/${encodeURIComponent(i.id)}`);
                            toast("Invite revoked");
                            list.reload();
                          })
                        }
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
