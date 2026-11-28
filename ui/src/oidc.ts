// Signing in with an identity provider (ADR-0022 step 8): the pure helpers the screens share. No React, no storage.

/** What the server shows for an `oidc_error` code in the address bar. The server never passes text from the provider. */
const ERRORS: Record<string, string> = {
  denied: "The sign-in was cancelled or refused at the identity provider.",
  provider_error: "The identity provider reported a problem. Try again, or ask an administrator.",
  provider_unreachable: "The identity provider could not be reached, or its settings are not acceptable. Try again later.",
  invalid_state: "That sign-in could not be matched to this browser (it may have expired, or been opened twice). Start again from here.",
  invalid_token: "The identity provider's answer was not valid, so nobody was signed in.",
  assurance_not_met: "The provider did not confirm the sign-in strength this server requires (for example a second factor).",
  no_account: "No ProxyMind account is linked to that identity. Ask a project owner for an invite.",
  not_permitted: "That account cannot sign in this way.",
  owner_needs_local_factor: "Owners and administrators must also have a passkey, or a password with an authenticator, before a provider can be used.",
  owner_invite: "An owner invite cannot be redeemed through a provider: use a passkey or a password.",
  account_exists: "An account with that name already exists. Ask a project owner to link it or to invite you.",
  identity_in_use: "That identity is already linked to another account.",
  already_linked: "This account already has an identity from that provider.",
  invalid_invite: "That invite is not valid any more. Ask for a new one.",
  link_expired: "The link took too long or your session ended. Sign in again and repeat it.",
  throttled: "Too many attempts from your address. Wait a little and try again.",
  unknown_provider: "That identity provider is not available.",
  internal: "Something went wrong on the server.",
};

export const oidcErrorText = (code: string): string =>
  ERRORS[code] ?? "The sign-in with the identity provider did not work.";

/**
 * Reads `oidc_error` and `oidc_linked` from a query string and returns the same query without them (the `#route` is
 * untouched), so a reload does not show them again.
 */
export function splitOidcNotice(search: string): { error: string | null; linked: boolean; rest: string } {
  const p = new URLSearchParams(search);
  const error = p.get("oidc_error");
  const linked = p.get("oidc_linked") === "1";
  p.delete("oidc_error");
  p.delete("oidc_linked");
  const rest = p.toString();
  return { error, linked, rest: rest ? `?${rest}` : "" };
}

/** Where a sign-in with provider `id` starts; `next` is a path on this origin (the server checks it again). */
export const startUrl = (id: string, next: string): string =>
  `/api/v1/auth/oidc/${encodeURIComponent(id)}/start?next=${encodeURIComponent(next)}`;

export const ROLES = ["tester", "viewer"] as const;

/** `group = role` lines to the API's list. Only `tester` and `viewer` exist: a group can never mean `owner`. */
export function parseGroupRoles(text: string): { value: string; role: string }[] {
  const out: { value: string; role: string }[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const i = line.lastIndexOf("=");
    if (i < 1) throw new Error(`“${line}”: write it as group = tester or group = viewer.`);
    const value = line.slice(0, i).trim();
    const role = line.slice(i + 1).trim().toLowerCase();
    if (!value) throw new Error(`“${line}”: the group name is missing.`);
    if (!(ROLES as readonly string[]).includes(role)) {
      throw new Error(`“${line}”: a group can give tester or viewer, never ${role || "nothing"}. Owners are made by owners.`);
    }
    out.push({ value, role });
  }
  return out;
}

export const formatGroupRoles = (m: { value: string; role: string }[]): string =>
  m.map((x) => `${x.value} = ${x.role}`).join("\n");

/** A list typed with spaces, commas or new lines. */
export const parseList = (text: string): string[] => text.split(/[\s,]+/).filter(Boolean);
