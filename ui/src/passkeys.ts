// Passkeys (WebAuthn) in the browser: base64url conversion and the two calls, `navigator.credentials.create()` and
// `.get()`, in the shapes the server speaks (`/api/v1/auth/passkey…`). Pure of React; no secret is kept here.
import type { AssertionBody, RegistrationBody } from "./api-types.gen";

/** The server's options: WebAuthn's JSON form, with the binary values as base64url strings. */
export interface CredentialDescriptorJSON {
  type: "public-key";
  id: string;
}
export interface CreationOptionsJSON {
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  timeout?: number;
  excludeCredentials?: CredentialDescriptorJSON[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
}
export interface RequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId: string;
  allowCredentials?: CredentialDescriptorJSON[];
  userVerification?: UserVerificationRequirement;
}

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** RFC 4648 base64url without padding. */
export function bytesToB64url(input: ArrayBuffer | Uint8Array): string {
  const b = input instanceof Uint8Array ? input : new Uint8Array(input);
  let out = "";
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i] << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    const chars = Math.min(3, b.length - i) + 1;
    for (let j = 0; j < chars; j++) out += ALPHABET[(n >> (18 - 6 * j)) & 63];
  }
  return out;
}

/** Strict inverse of [bytesToB64url]: the URL-safe alphabet only, no padding. Throws on anything else. */
export function b64urlToBytes(text: string): Uint8Array {
  if (text.length % 4 === 1) throw new Error("not base64url");
  const out: number[] = [];
  let buf = 0;
  let bits = 0;
  for (const c of text) {
    const v = ALPHABET.indexOf(c);
    if (v < 0) throw new Error("not base64url");
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 255);
      buf &= (1 << bits) - 1;
    }
  }
  return new Uint8Array(out);
}

/** Can this page use passkeys at all (a secure context with the WebAuthn API)? */
export function passkeysAvailable(): boolean {
  return typeof window !== "undefined" && window.isSecureContext && !!window.PublicKeyCredential && !!navigator.credentials;
}

/**
 * Is this page at an address a passkey made for `rpId` works at? A browser accepts an RP id that is the page's host
 * name or a parent domain of it, so the page's host must be the id or end with `.id`.
 */
export function atRpHost(rpId: string | null | undefined, host: string = window.location.hostname): boolean {
  if (!rpId) return false;
  return host === rpId || host.endsWith(`.${rpId}`);
}

const buf = (b64: string): ArrayBuffer => {
  const u = b64urlToBytes(b64);
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
};

/** The options the server sent, as `navigator.credentials.create()` wants them (binary values as buffers). */
export function creationOptions(o: CreationOptionsJSON): PublicKeyCredentialCreationOptions {
  return {
    rp: o.rp,
    user: { id: buf(o.user.id), name: o.user.name, displayName: o.user.displayName },
    challenge: buf(o.challenge),
    pubKeyCredParams: o.pubKeyCredParams,
    timeout: o.timeout,
    excludeCredentials: (o.excludeCredentials ?? []).map((d) => ({ type: d.type, id: buf(d.id) })),
    authenticatorSelection: o.authenticatorSelection,
    attestation: o.attestation ?? "none",
  };
}

export function requestOptions(o: RequestOptionsJSON): PublicKeyCredentialRequestOptions {
  return {
    challenge: buf(o.challenge),
    timeout: o.timeout,
    rpId: o.rpId,
    allowCredentials: (o.allowCredentials ?? []).map((d) => ({ type: d.type, id: buf(d.id) })),
    userVerification: o.userVerification ?? "required",
  };
}

/** Makes a passkey with the authenticator the person picks; the answer is what `POST /auth/passkeys…` takes. */
export async function createPasskey(options: CreationOptionsJSON): Promise<RegistrationBody> {
  const cred = (await navigator.credentials.create({ publicKey: creationOptions(options) })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was made.");
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: bytesToB64url(cred.rawId),
    client_data_json: bytesToB64url(r.clientDataJSON),
    attestation_object: bytesToB64url(r.attestationObject),
    transports: typeof r.getTransports === "function" ? r.getTransports() : [],
  };
}

/** Signs a challenge with a passkey; the answer is what `POST /auth/passkey/login` takes. */
export async function getPasskey(options: RequestOptionsJSON): Promise<AssertionBody> {
  const cred = (await navigator.credentials.get({ publicKey: requestOptions(options) })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was used.");
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: bytesToB64url(cred.rawId),
    client_data_json: bytesToB64url(r.clientDataJSON),
    authenticator_data: bytesToB64url(r.authenticatorData),
    signature: bytesToB64url(r.signature),
    user_handle: r.userHandle && r.userHandle.byteLength > 0 ? bytesToB64url(r.userHandle) : null,
  };
}

/** A plain sentence for what the browser or authenticator said went wrong. */
export function passkeyErrorText(e: unknown): string {
  if (e instanceof DOMException) {
    switch (e.name) {
      case "NotAllowedError":
        return "The passkey request was cancelled or timed out. Try again.";
      case "InvalidStateError":
        return "This authenticator already has a passkey for this account.";
      case "SecurityError":
        return "The browser refused to use a passkey at this address. Open the server at its configured host name.";
      case "NotSupportedError":
        return "This browser or authenticator cannot make a passkey the server accepts.";
      case "AbortError":
        return "The passkey request was interrupted.";
    }
  }
  return e instanceof Error ? e.message : String(e);
}
