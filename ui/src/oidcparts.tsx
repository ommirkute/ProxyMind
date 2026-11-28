// Server mode: signing in with an identity provider (ADR-0022 step 8), the pieces shared by the sign-in screens
// (Root.tsx), the account page (linked identities) and the admin page (providers). The provider does the signing in;
// the browser only navigates to the server's `/api/v1/auth/oidc/…` routes and comes back to `/` (see oidc.ts).
import { createContext, useContext, useState, type FormEvent } from "react";
import { api, fmtDateTime, toast } from "./api";
import type {
  OidcIdentityView,
  OidcProviderBody,
  OidcProviderPublic,
  OidcProviderView,
  OidcStartResponse,
  OidcTestResponse,
  OkResponse,
  StateResponse,
} from "./api-types.gen";
import { CopyButton, Field, useAuth } from "./authparts";
import { Empty, ErrorBox, Panel, useAction, useLoad } from "./components";
import { Icon } from "./icons";
import { formatGroupRoles, parseGroupRoles, parseList, startUrl } from "./oidc";

/** The enabled providers the server listed in `GET /auth/state`. */
export const OidcContext = createContext<OidcProviderPublic[]>([]);
export const useOidcProviders = () => useContext(OidcContext);

const when = (secs: number | null | undefined) => (secs ? fmtDateTime(secs * 1000) : "never");

/**
 * "Sign in with <provider>" buttons. A plain sign-in is a link to the server, which redirects to the provider. With
 * `invite` the invite is handed to the server first (it comes back with the provider's address). With `again`
 * (re-authentication) the person returns to the page they were on and repeats what they were doing.
 */
export function OidcButtons({ next, invite, again }: { next: string; invite?: string; again?: boolean }) {
  const providers = useOidcProviders();
  const { busy, error, run } = useAction();
  if (providers.length === 0) return null;
  return (
    <div className="oidc-buttons" data-testid="oidc-buttons">
      <ErrorBox error={error} />
      {providers.map((p) => {
        const label = again ? `Sign in again with ${p.name}` : `Sign in with ${p.name}`;
        if (!invite) {
          return (
            <a key={p.id} className="btn" href={startUrl(p.id, next)} data-testid={`oidc-signin-${p.id}`}>
              <Icon name="shield" size={14} /> {label}
            </a>
          );
        }
        return (
          <button
            key={p.id}
            type="button"
            className="btn"
            disabled={busy}
            data-testid={`oidc-invite-${p.id}`}
            onClick={() =>
              void run(async () => {
                const r = await api.post<OidcStartResponse>(`/auth/oidc/${encodeURIComponent(p.id)}/invite`, { invite, next });
                window.location.assign(r.url);
              })
            }
          >
            <Icon name="shield" size={14} /> {label}
          </button>
        );
      })}
    </div>
  );
}

// ---- the account page: linked identities ------------------------------------------------------------------------

const HOW: Record<string, string> = {
  self: "linked by you",
  email: "linked by verified email",
  invite: "made by an invite",
  auto: "made on first sign-in",
};

export function LinkedIdentities() {
  // The providers an administrator configures change under an open page: read the list again on arriving here.
  const known = useOidcProviders();
  const state = useLoad(() => api.get<StateResponse>("/auth/state"), []);
  const providers = state.data?.oidc_providers ?? known;
  const auth = useAuth()!;
  const list = useLoad(() => api.get<OidcIdentityView[]>("/auth/oidc/identities"), []);
  const { busy, error, run } = useAction();
  const rows = list.data ?? [];
  if (providers.length === 0 && rows.length === 0 && !list.loading) return null;
  const linkedProviders = new Set(rows.map((r) => r.provider_id));
  const unlink = (i: OidcIdentityView) =>
    void run(async () => {
      if (!window.confirm(`Unlink ${i.provider_name}${i.email ? ` (${i.email})` : ""}? You will be signed out of your other sessions.`)) return;
      await api.del<OkResponse>(`/auth/oidc/identities/${encodeURIComponent(i.id)}`);
      toast("Identity unlinked. Your other sessions were signed out.");
      list.reload();
      void auth.refresh();
    });
  const link = (p: OidcProviderPublic) =>
    void run(async () => {
      const here = window.location.pathname + window.location.search + window.location.hash;
      const r = await api.post<OidcStartResponse>(`/auth/oidc/${encodeURIComponent(p.id)}/link`, { next: here });
      window.location.assign(r.url);
    });
  return (
    <Panel title="Sign in with an identity provider">
      <p className="small muted">
        Link your account to an identity at your organisation's provider to sign in with it. ProxyMind recognises the
        provider's account by its issuer and subject, not by email; the email shown is only what the provider last said.
        You can always keep a passkey or password too: an owner or administrator must.
      </p>
      <ErrorBox error={error ?? list.error} />
      {rows.length === 0 ? (
        <Empty>No identity linked.</Empty>
      ) : (
        <table className="grid" data-testid="identities-table">
          <thead>
            <tr>
              <th>Provider</th>
              <th>Shown as</th>
              <th>How</th>
              <th>Linked</th>
              <th>Last used</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((i) => (
              <tr key={i.id} data-testid="identity-row">
                <td data-testid="identity-provider">{i.provider_name}</td>
                <td data-testid="identity-email">{i.email ?? i.name ?? "–"}</td>
                <td>{HOW[i.linked_by] ?? i.linked_by}</td>
                <td>{when(i.created_at)}</td>
                <td>{when(i.last_used_at)}</td>
                <td>
                  <button className="btn sm bad" disabled={busy} onClick={() => unlink(i)} data-testid="identity-unlink">Unlink</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="row" style={{ marginTop: 12, gap: 8 }}>
        {providers
          .filter((p) => !linkedProviders.has(p.id))
          .map((p) => (
            <button key={p.id} className="btn" disabled={busy} onClick={() => link(p)} data-testid={`oidc-link-${p.id}`}>
              <Icon name="shield" size={14} /> Link {p.name}
            </button>
          ))}
      </div>
    </Panel>
  );
}

// ---- the admin page: providers ----------------------------------------------------------------------------------

interface FormState {
  name: string;
  issuer: string;
  client_id: string;
  client_secret: string;
  scopes: string;
  group_claim: string;
  group_roles: string;
  auto_create_domains: string;
  email_linking: boolean;
  required_acr: string;
  required_amr: string;
  enabled: boolean;
}

const blank: FormState = {
  name: "",
  issuer: "",
  client_id: "",
  client_secret: "",
  scopes: "profile email",
  group_claim: "",
  group_roles: "",
  auto_create_domains: "",
  email_linking: false,
  required_acr: "",
  required_amr: "",
  enabled: true,
};

const formOf = (p: OidcProviderView): FormState => ({
  name: p.name,
  issuer: p.issuer,
  client_id: p.client_id,
  // The mask stands for the stored secret: leaving it keeps the secret, emptying the field removes it.
  client_secret: p.client_secret ?? "",
  scopes: p.scopes.join(" "),
  group_claim: p.group_claim ?? "",
  group_roles: formatGroupRoles(p.group_roles),
  auto_create_domains: p.auto_create_domains.join(" "),
  email_linking: p.email_linking,
  required_acr: p.required_acr.join(" "),
  required_amr: p.required_amr.join(" "),
  enabled: p.enabled,
});

const bodyOf = (f: FormState): OidcProviderBody => ({
  name: f.name.trim(),
  issuer: f.issuer.trim(),
  client_id: f.client_id.trim(),
  client_secret: f.client_secret,
  scopes: parseList(f.scopes),
  group_claim: f.group_claim.trim() || null,
  group_roles: parseGroupRoles(f.group_roles),
  auto_create_domains: parseList(f.auto_create_domains),
  email_linking: f.email_linking,
  required_acr: parseList(f.required_acr),
  required_amr: parseList(f.required_amr),
  enabled: f.enabled,
});

/** Identity providers (server administrators): the list, the form, a test of the discovery document and keys. */
export function OidcProviders() {
  const auth = useAuth()!;
  const list = useLoad(() => api.get<OidcProviderView[]>("/auth/oidc/providers"), []);
  const [editing, setEditing] = useState<{ id: string | null; form: FormState } | null>(null);
  const [tested, setTested] = useState<{ id: string; result: OidcTestResponse } | null>(null);
  const { busy, error, run, setError } = useAction();
  const rows = list.data ?? [];
  const save = (e: FormEvent) => {
    e.preventDefault();
    if (!editing) return;
    void run(async () => {
      let body: OidcProviderBody;
      try {
        body = bodyOf(editing.form);
      } catch (err) {
        setError((err as Error).message);
        return;
      }
      if (editing.id) await api.put<OidcProviderView>(`/auth/oidc/providers/${encodeURIComponent(editing.id)}`, body);
      else await api.post<OidcProviderView>("/auth/oidc/providers", body);
      toast("Provider saved");
      setEditing(null);
      list.reload();
      void auth.refresh();
    });
  };
  const remove = (p: OidcProviderView) =>
    void run(async () => {
      if (!window.confirm(`Delete “${p.name}”? The identities linked through it are unlinked.`)) return;
      await api.del<OkResponse>(`/auth/oidc/providers/${encodeURIComponent(p.id)}`);
      toast("Provider deleted");
      list.reload();
      void auth.refresh();
    });
  const test = (p: OidcProviderView) =>
    void run(async () => {
      setTested({ id: p.id, result: await api.post<OidcTestResponse>(`/auth/oidc/providers/${encodeURIComponent(p.id)}/test`) });
    });
  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => editing && setEditing({ ...editing, form: { ...editing.form, [k]: v } });
  return (
    <Panel
      title="Identity providers"
      actions={
        !editing && (
          <button className="btn sm primary" data-testid="oidc-add" onClick={() => setEditing({ id: null, form: blank })}>
            Add a provider
          </button>
        )
      }
    >
      <p className="small muted">
        People can sign in with an OpenID Connect provider (Keycloak, Entra ID, Google, GitLab, Okta…). Joining stays by
        invite unless you list email domains for automatic accounts, which get the viewer role at most. A group claim can
        give tester or viewer, never owner. Owners and administrators keep a passkey or a password with an authenticator.
      </p>
      <ErrorBox error={error ?? list.error} />
      {!editing && rows.length === 0 && <Empty>No provider configured.</Empty>}
      {!editing && rows.length > 0 && (
        <table className="grid" data-testid="oidc-providers-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Issuer</th>
              <th>Client</th>
              <th>Secret</th>
              <th>Joining</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <tr key={p.id} data-testid="oidc-provider-row">
                <td>
                  {p.name} {!p.enabled && <span className="chip warn">off</span>}
                </td>
                <td className="mono">{p.issuer}</td>
                <td className="mono">{p.client_id}</td>
                <td className="mono" data-testid="oidc-secret-cell">{p.client_secret ?? "none (public client)"}</td>
                <td>
                  {p.auto_create_domains.length ? `auto-create: ${p.auto_create_domains.join(", ")}` : "invite only"}
                  {p.email_linking && <> · links by email</>}
                  {p.group_claim && <> · groups from “{p.group_claim}”</>}
                </td>
                <td>
                  <div className="row">
                    <button className="btn sm" disabled={busy} onClick={() => test(p)} data-testid="oidc-test">Test</button>
                    <button className="btn sm" disabled={busy} onClick={() => setEditing({ id: p.id, form: formOf(p) })} data-testid="oidc-edit">Edit</button>
                    <button className="btn sm bad" disabled={busy} onClick={() => remove(p)} data-testid="oidc-delete">Delete</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {tested && !editing && <TestResult result={tested.result} />}
      {rows[0] && !editing && (
        <p className="small muted" style={{ marginTop: 12 }}>
          Register this redirect URI with each provider:{" "}
          <span className="mono" data-testid="oidc-redirect-uri">{rows[0].redirect_uri}</span>{" "}
          <CopyButton text={rows[0].redirect_uri} label="Copy" testid="oidc-redirect-copy" />
        </p>
      )}
      {editing && (
        <form onSubmit={save} style={{ maxWidth: 560 }} data-testid="oidc-form">
          <Field label="Name on the button" value={editing.form.name} onChange={(v) => set("name", v)} testid="oidc-name" required />
          <Field label="Issuer" value={editing.form.issuer} onChange={(v) => set("issuer", v)} testid="oidc-issuer" required hint="Exactly the issuer the provider uses, e.g. https://login.example.com/realms/team. Its discovery document is read from it." />
          <Field label="Client id" value={editing.form.client_id} onChange={(v) => set("client_id", v)} testid="oidc-client-id" required />
          <Field label="Client secret" type="password" value={editing.form.client_secret} onChange={(v) => set("client_secret", v)} testid="oidc-client-secret" autoComplete="off" hint="Shown as ******** when one is stored and never read back; leave it to keep it, empty it to remove it (a public client uses PKCE alone)." />
          <Field label="Scopes" value={editing.form.scopes} onChange={(v) => set("scopes", v)} testid="oidc-scopes" hint="Besides openid. Add the one that carries groups if the provider needs one." />
          <Field label="Group claim (optional)" value={editing.form.group_claim} onChange={(v) => set("group_claim", v)} testid="oidc-group-claim" hint="The ID token claim that lists groups, e.g. groups." />
          <div className="field">
            <label>
              <span>Groups to roles (one per line: group = tester or viewer)</span>
              <textarea rows={3} value={editing.form.group_roles} onChange={(e) => set("group_roles", e.target.value)} data-testid="oidc-group-roles" spellCheck={false} />
            </label>
            <div className="small muted">Only tester and viewer. A claim never makes an owner or an administrator.</div>
          </div>
          <Field label="Email domains that may create an account" value={editing.form.auto_create_domains} onChange={(v) => set("auto_create_domains", v)} testid="oidc-domains" hint="Verified emails only; the new account is a viewer. Empty: people join by invite." />
          <label className="row" style={{ gap: 8, margin: "8px 0" }}>
            <input type="checkbox" checked={editing.form.email_linking} onChange={(e) => set("email_linking", e.target.checked)} data-testid="oidc-email-linking" />
            <span>Link an existing account whose username is the verified email (never an owner or administrator)</span>
          </label>
          <Field label="Required acr values (optional)" value={editing.form.required_acr} onChange={(v) => set("required_acr", v)} testid="oidc-acr" />
          <Field label="Required amr values (optional)" value={editing.form.required_amr} onChange={(v) => set("required_amr", v)} testid="oidc-amr" hint="For example mfa or otp. The token must carry all of them." />
          <label className="row" style={{ gap: 8, margin: "8px 0" }}>
            <input type="checkbox" checked={editing.form.enabled} onChange={(e) => set("enabled", e.target.checked)} data-testid="oidc-enabled" />
            <span>Enabled (shown on the sign-in page)</span>
          </label>
          <div className="row" style={{ gap: 8 }}>
            <button className="btn primary" type="submit" disabled={busy} data-testid="oidc-save">Save</button>
            <button className="btn ghost" type="button" onClick={() => { setEditing(null); setError(null); }}>Cancel</button>
          </div>
        </form>
      )}
    </Panel>
  );
}

function TestResult({ result }: { result: OidcTestResponse }) {
  return (
    <div className={`notice ${result.ok ? "" : "warn"}`} data-testid="oidc-test-result" style={{ marginTop: 12 }}>
      <b>{result.ok ? "The provider answers as ProxyMind needs." : "The test failed."}</b>
      {result.ok && (
        <ul className="small" style={{ margin: "6px 0 0 18px" }}>
          <li>Issuer: <span className="mono">{result.issuer}</span></li>
          <li>Signing keys: {result.key_count} ({result.algorithms.join(", ")})</li>
          <li>Client authentication at the token endpoint: {result.token_auth}</li>
          <li>{result.iss_parameter_supported ? "Sends the iss response parameter (required here)." : "Does not announce the iss response parameter."}</li>
        </ul>
      )}
      {result.problems.length > 0 && (
        <ul className="small" style={{ margin: "6px 0 0 18px" }}>
          {result.problems.map((p, i) => <li key={i}>{p}</li>)}
        </ul>
      )}
    </div>
  );
}
