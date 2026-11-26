// Server mode: the passkey pieces shared by the sign-in screens (Root.tsx), the account page and the admin page.
// A passkey is made and used with `navigator.credentials` (see passkeys.ts); the server verifies it. Nothing here is
// kept in storage, and nothing is logged.
import { createContext, useContext, useState, type FormEvent } from "react";
import { api } from "./api";
import type { LoginResponse, PasskeyAdded, PasskeyOptionsResponse } from "./api-types.gen";
import { errText, Field } from "./authparts";
import { ErrorBox, useAction } from "./components";
import { Icon } from "./icons";
import {
  atRpHost,
  createPasskey,
  getPasskey,
  passkeyErrorText,
  passkeysAvailable,
  type CreationOptionsJSON,
  type RequestOptionsJSON,
} from "./passkeys";

/** What the server said about passkeys (`GET /auth/state`). */
export interface PasskeyEnv {
  supported: boolean;
  rpId: string | null;
  note: string | null;
  required: boolean;
}

export const PasskeyEnvContext = createContext<PasskeyEnv>({ supported: false, rpId: null, note: null, required: false });

/**
 * Whether this page can use a passkey now, and if not why in a sentence: the server needs a host name to bind them to,
 * the browser needs a secure context with WebAuthn, and the page must be at that host name.
 */
export function usePasskeyUse(): { usable: boolean; reason: string | null; required: boolean; rpId: string | null } {
  const env = useContext(PasskeyEnvContext);
  const base = { required: env.required, rpId: env.rpId };
  if (!env.supported) return { ...base, usable: false, reason: env.note ?? "This server cannot use passkeys." };
  if (!passkeysAvailable()) {
    return { ...base, usable: false, reason: "This browser cannot use passkeys on this page (it needs HTTPS, or localhost)." };
  }
  if (!atRpHost(env.rpId)) {
    return {
      ...base,
      usable: false,
      reason: `Passkeys on this server are bound to ${env.rpId}. Open the server at that address to use or add one.`,
    };
  }
  return { ...base, usable: true, reason: null };
}

/** The text of a failed passkey call: the server's, or the browser's. */
const failText = (e: unknown) => (e instanceof DOMException ? passkeyErrorText(e) : errText(e));

/** "Sign in with a passkey". With `username` (re-authentication) only that account's passkeys are offered. */
export function PasskeySignIn({ username, next, onResponse, label = "Sign in with a passkey" }: {
  username?: string;
  next?: string;
  onResponse: (r: LoginResponse) => void;
  label?: string;
}) {
  const use = usePasskeyUse();
  const { busy, error, run, setError } = useAction();
  if (!use.usable) return null;
  const go = () =>
    void run(async () => {
      try {
        const o = await api.post<PasskeyOptionsResponse>("/auth/passkey/login/options", username ? { username } : {});
        const response = await getPasskey(o.options as unknown as RequestOptionsJSON);
        onResponse(await api.post<LoginResponse>("/auth/passkey/login", { response, next }));
      } catch (e) {
        setError(failText(e));
      }
    });
  return (
    <div>
      <ErrorBox error={error} />
      <button type="button" className="btn" disabled={busy} data-testid="passkey-signin" onClick={go}>
        <Icon name="key" size={14} /> {label}
      </button>
    </div>
  );
}

/**
 * Adds a passkey to the signed-in account: a name and a button. The server wants a fresh sign-in for it; `api.ts`
 * asks for one and repeats the call. `onAdded` runs once the passkey is stored.
 */
export function PasskeyAdd({ onAdded, label = "Add a passkey", primary }: { onAdded: () => void; label?: string; primary?: boolean }) {
  const use = usePasskeyUse();
  const [name, setName] = useState("");
  const { busy, error, run, setError } = useAction();
  if (!use.usable) return <p className="small muted" data-testid="passkey-unavailable">{use.reason}</p>;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      try {
        const o = await api.post<PasskeyOptionsResponse>("/auth/passkeys/options");
        const response = await createPasskey(o.options as unknown as CreationOptionsJSON);
        await api.post<PasskeyAdded>("/auth/passkeys", { name: name.trim() || undefined, response });
        setName("");
        onAdded();
      } catch (err) {
        setError(failText(err));
      }
    });
  };
  return (
    <form onSubmit={submit} style={{ maxWidth: 420 }}>
      <Field label="Name (optional)" value={name} onChange={setName} testid="passkey-name" hint="So you can tell your passkeys apart, e.g. “Work laptop”." />
      <ErrorBox error={error} />
      <button className={`btn ${primary ? "primary" : ""}`} type="submit" disabled={busy} data-testid="passkey-add">
        <Icon name="key" size={14} /> {label}
      </button>
    </form>
  );
}

/** The choice on the setup, invite and enrolment-link screens: a passkey (recommended) or a password. */
export function CredentialChoice({ mode, onMode }: { mode: "passkey" | "password"; onMode: (m: "passkey" | "password") => void }) {
  const use = usePasskeyUse();
  return (
    <fieldset className="choice" style={{ border: 0, padding: 0, margin: "0 0 12px" }}>
      <legend className="small muted">How will you sign in?</legend>
      <label style={{ display: "block" }}>
        <input type="radio" name="credential" checked={mode === "passkey"} disabled={!use.usable} onChange={() => onMode("passkey")} data-testid="choice-passkey" />{" "}
        <b>A passkey</b> (recommended): your device's fingerprint, face, PIN or a security key. Nothing to type, and it cannot be phished.
      </label>
      <label style={{ display: "block", marginTop: 6 }}>
        <input type="radio" name="credential" checked={mode === "password"} onChange={() => onMode("password")} data-testid="choice-password" />{" "}
        <b>A password and an authenticator app</b>: for devices without passkeys.
      </label>
      {!use.usable && <p className="small muted" data-testid="passkey-unavailable">{use.reason}</p>}
    </fieldset>
  );
}

/**
 * Makes a passkey for a new account or a recovery and finishes it on the server: `optionsPath` with `optionsBody`
 * gives the options, the browser makes the passkey, and `finishPath` gets it with `finishExtra`. A refusal by the
 * browser or authenticator becomes an `Error` with a plain sentence.
 */
export async function registerWithPasskey(
  optionsPath: string,
  optionsBody: object,
  finishPath: string,
  finishExtra: object,
): Promise<LoginResponse> {
  const o = await api.post<PasskeyOptionsResponse>(optionsPath, optionsBody);
  let response;
  try {
    response = await createPasskey(o.options as unknown as CreationOptionsJSON);
  } catch (e) {
    throw new Error(failText(e));
  }
  return api.post<LoginResponse>(finishPath, { ...finishExtra, response });
}
