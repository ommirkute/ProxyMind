// Server mode: the pieces shared by the sign-in screens (Root.tsx), the re-authentication dialog and the Account page.
// Nothing here runs in single-user mode. Secrets (passwords, codes, TOTP secrets, recovery codes, tokens) live only in
// component state: never in storage, never in the console.
import { createContext, useContext, useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import { api, ApiError } from "./api";
import type { LoginResponse, MeResponse, TotpEnrolmentResponse } from "./api-types.gen";
import { copyText, ErrorBox, useAction } from "./components";
import { Icon } from "./icons";

// ---- context ---------------------------------------------------------------------------------------------------

export interface AuthCtx {
  me: MeResponse;
  /** Reads `/auth/me` again (after a re-authentication, a password change…). */
  refresh: () => Promise<void>;
  /** Ends this session and shows the sign-in screen. */
  logout: () => Promise<void>;
  /** The session is gone (the server ended it): show the sign-in screen. */
  sessionEnded: () => void;
}

export const AuthContext = createContext<AuthCtx | null>(null);
/** The signed-in account in server mode; `null` in single-user mode. */
export const useAuth = () => useContext(AuthContext);
/** The role on this project: `owner` in single-user mode (a person there is the implicit owner). */
export const useRole = (): "owner" | "tester" | "viewer" => {
  const r = useContext(AuthContext)?.me.role;
  return r === "tester" || r === "viewer" ? r : "owner";
};

// ---- small helpers ---------------------------------------------------------------------------------------------

/** The text of a failed call, with the wait when the server throttled the sign-in. */
export function errText(e: unknown): string {
  if (e instanceof ApiError) {
    // The throttle's own text already says how long to wait; add it only if a proxy swapped the text.
    return e.status === 429 && e.retryAfter && !/try again/i.test(e.message) ? `${e.message} (try again in ${e.retryAfter} s)` : e.message;
  }
  return e instanceof Error ? e.message : String(e);
}

/** A path on this origin the page may navigate to (the server already sanitises `next`; this is the second check). */
export function sameOriginPath(next: string | null | undefined): string | null {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.includes("\\")) return null;
  try {
    const u = new URL(next, window.location.origin);
    return u.origin === window.location.origin ? u.pathname + u.search + u.hash : null;
  } catch {
    return null;
  }
}

/** Where the person is now, as a `next` for the sign-in (path, query and the page's own `#/route`). */
export function currentLocation(): string {
  return window.location.pathname + window.location.search + window.location.hash;
}

/** An SVG string as an image source (shown through <img>, so nothing in it can run). */
const svgSrc = (svg: string) => `data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(svg)))}`;

// ---- building blocks -------------------------------------------------------------------------------------------

export function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark"><Icon name="logo" size={17} stroke={2} /></span>
      <span className="brand-name">Proxy<span>Mind</span></span>
    </div>
  );
}

/** A full-page card (the same look as the "Not signed in" page). */
export function AuthScreen({ children, wide }: { children: ReactNode; wide?: boolean }) {
  return (
    <div className="signin">
      <div className={`signin-card ${wide ? "wide" : ""}`}>
        <Brand />
        {children}
      </div>
    </div>
  );
}

export function Field(props: {
  label: string;
  value: string;
  onChange?: (v: string) => void;
  type?: "text" | "password";
  autoComplete?: string;
  testid?: string;
  hint?: ReactNode;
  autoFocus?: boolean;
  inputMode?: "numeric" | "text";
  readOnly?: boolean;
  required?: boolean;
}) {
  const hintId = useId();
  return (
    <div className="field">
      <label>
        <span>{props.label}</span>
        <input
          type={props.type ?? "text"}
          name={props.label.toLowerCase().replace(/[^a-z]+/g, "-")}
          value={props.value}
          onChange={(e) => props.onChange?.(e.target.value)}
          autoComplete={props.autoComplete ?? "off"}
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          autoFocus={props.autoFocus}
          inputMode={props.inputMode}
          readOnly={props.readOnly}
          required={props.required}
          aria-describedby={props.hint ? hintId : undefined}
          data-testid={props.testid}
        />
      </label>
      {props.hint && <small id={hintId} className="muted">{props.hint}</small>}
    </div>
  );
}

/** Copies text; the label changes to "Copied" (no timer: it stays until the text changes). */
export function CopyButton({ text, label = "Copy", testid }: { text: string; label?: string; testid?: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => setDone(false), [text]);
  return (
    <button
      type="button"
      className="btn sm"
      data-testid={testid}
      onClick={() => {
        void copyText(text).then(() => setDone(true));
      }}
    >
      <Icon name={done ? "check" : "file"} size={13} /> {done ? "Copied" : label}
    </button>
  );
}

/** The authenticator secret: a QR code (rendered by the server), the secret as text and a copy button. */
export function TotpSecret({ enrol }: { enrol: TotpEnrolmentResponse }) {
  return (
    <div className="totp-secret">
      {enrol.qr_svg && (
        <img
          data-testid="totp-qr"
          alt="QR code for your authenticator app"
          src={svgSrc(enrol.qr_svg)}
          width={196}
          height={196}
        />
      )}
      <div>
        <p className="small muted">Or type this secret into the app (time-based, 6 digits):</p>
        <span className="mono secret" data-testid="totp-secret">{enrol.secret_base32}</span>
        <div className="row" style={{ marginTop: 8 }}>
          <CopyButton text={enrol.secret_base32} label="Copy secret" testid="totp-copy" />
        </div>
      </div>
    </div>
  );
}

/** Recovery codes, shown once, with copy and download. `onDone` is the "I've saved them" button. */
export function RecoveryCodesView({ codes, onDone, doneLabel = "I've saved them" }: { codes: string[]; onDone: () => void; doneLabel?: string }) {
  const text = codes.join("\n") + "\n";
  return (
    <div data-testid="recovery-codes">
      <h2>Save your recovery codes</h2>
      <p>
        Each code signs you in once if you lose your authenticator. They are shown <b>only now</b>; store them somewhere
        safe, such as a password manager.
      </p>
      <ul className="codes" data-testid="recovery-code-list">
        {codes.map((c) => (
          <li key={c} className="mono">{c}</li>
        ))}
      </ul>
      <div className="auth-actions">
        <CopyButton text={text} label="Copy codes" testid="recovery-copy" />
        <a
          className="btn sm"
          data-testid="recovery-download"
          download="proxymind-recovery-codes.txt"
          href={`data:text/plain;charset=utf-8,${encodeURIComponent(text)}`}
        >
          Download
        </a>
        <span className="grow" />
        <button type="button" className="btn primary" data-testid="recovery-done" onClick={onDone}>
          {doneLabel}
        </button>
      </div>
    </div>
  );
}

/** Username, display name and passwords: the form of the setup and the invite screens. */
export function NewAccountForm({ submitLabel, onSubmit, busy, error }: {
  submitLabel: string;
  onSubmit: (v: { username: string; display_name: string; password: string }) => void;
  busy: boolean;
  error: string | null;
}) {
  const [username, setUsername] = useState("");
  const [display, setDisplay] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [local, setLocal] = useState<string | null>(null);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (pw !== pw2) return setLocal("The two passwords are not the same.");
    setLocal(null);
    onSubmit({ username: username.trim(), display_name: display.trim(), password: pw });
  };
  return (
    <form onSubmit={submit}>
      <Field label="Username" value={username} onChange={setUsername} autoComplete="username" testid="auth-username" autoFocus required />
      <Field label="Display name (optional)" value={display} onChange={setDisplay} autoComplete="name" testid="auth-display-name" />
      <Field label="Password" type="password" value={pw} onChange={setPw} autoComplete="new-password" testid="auth-password" hint="At least 12 characters." required />
      <Field label="Confirm password" type="password" value={pw2} onChange={setPw2} autoComplete="new-password" testid="auth-password2" required />
      <ErrorBox error={local ?? error} />
      <div className="auth-actions">
        <button className="btn primary" type="submit" disabled={busy} data-testid="auth-submit">{submitLabel}</button>
      </div>
    </form>
  );
}

// ---- the steps after the password ------------------------------------------------------------------------------

function SecondFactor({ pending, next, onResult, onRestart }: {
  pending: string;
  next?: string;
  onResult: (r: LoginResponse) => void;
  onRestart: (message: string) => void;
}) {
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState(false);
  const { busy, error, run } = useAction();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      try {
        onResult(await api.post<LoginResponse>("/auth/login/second-factor", { pending, code: code.replace(/\s+/g, ""), next }));
      } catch (err) {
        if (err instanceof ApiError && err.code === "invalid_pending") return onRestart("That sign-in timed out. Enter your password again.");
        throw err;
      }
    });
  };
  return (
    <form onSubmit={submit}>
      <h2>{recovery ? "Use a recovery code" : "Two-step verification"}</h2>
      <p>{recovery ? "Enter one of your recovery codes. It works once." : "Enter the 6-digit code from your authenticator app."}</p>
      <Field
        key={recovery ? "recovery" : "totp"}
        label={recovery ? "Recovery code" : "Authentication code"}
        value={code}
        onChange={setCode}
        autoComplete="one-time-code"
        inputMode={recovery ? "text" : "numeric"}
        testid="auth-code"
        autoFocus
        required
      />
      <ErrorBox error={error} />
      <div className="auth-actions">
        <button className="btn primary" type="submit" disabled={busy} data-testid="auth-submit">Verify</button>
        <button type="button" className="btn ghost" data-testid="auth-toggle-recovery" onClick={() => { setRecovery(!recovery); setCode(""); }}>
          {recovery ? "Use an authenticator code" : "Use a recovery code"}
        </button>
        <button type="button" className="btn ghost" onClick={() => onRestart("")}>Start over</button>
      </div>
    </form>
  );
}

function Enrol({ pending, next, onResult, onRestart }: {
  pending: string;
  next?: string;
  onResult: (r: LoginResponse) => void;
  onRestart: (message: string) => void;
}) {
  const [enrol, setEnrol] = useState<TotpEnrolmentResponse | null>(null);
  const [code, setCode] = useState("");
  const { busy, error, run, setError } = useAction();
  // The secret is handed out once per call: ask once (the ref also survives the development double-mount).
  const asked = useRef(false);
  useEffect(() => {
    if (asked.current) return;
    asked.current = true;
    api.post<TotpEnrolmentResponse>("/auth/login/enrol", { pending }).then(setEnrol).catch((err) => {
      if (err instanceof ApiError && err.code === "invalid_pending") onRestart("That sign-in timed out. Enter your password again.");
      else setError(errText(err));
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pending]);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      try {
        onResult(await api.post<LoginResponse>("/auth/login/enrol/confirm", { pending, code: code.replace(/\s+/g, ""), next }));
      } catch (err) {
        if (err instanceof ApiError && err.code === "invalid_pending") return onRestart("That sign-in timed out. Enter your password again.");
        throw err;
      }
    });
  };
  return (
    <form onSubmit={submit}>
      <h2>Set up your authenticator</h2>
      <p>
        This account needs two-step verification. Scan the code with an authenticator app (or type the secret in), then
        enter the 6-digit code it shows.
      </p>
      {enrol && <TotpSecret enrol={enrol} />}
      <Field label="Authentication code" value={code} onChange={setCode} autoComplete="one-time-code" inputMode="numeric" testid="auth-code" autoFocus required />
      <ErrorBox error={error} />
      <div className="auth-actions">
        <button className="btn primary" type="submit" disabled={busy || !enrol} data-testid="auth-submit">Confirm and sign in</button>
        <button type="button" className="btn ghost" onClick={() => onRestart("")}>Start over</button>
      </div>
    </form>
  );
}

/**
 * Everything that follows a first answer of the server (`login`, `setup` or `invite/accept`): the second factor, the
 * enrolment, the recovery codes. Calls `onDone` once signed in (and, after an enrolment, once the person has said they
 * saved the recovery codes). `onRestart` goes back to the first form, with a message.
 */
export function Steps({ first, next, onDone, onRestart }: {
  first: LoginResponse;
  next?: string;
  onDone: (r: LoginResponse) => void;
  onRestart: (message: string) => void;
}) {
  const [cur, setCur] = useState(first);
  const finished = useRef(false);
  const done = () => {
    if (finished.current) return;
    finished.current = true;
    onDone(cur);
  };
  const signedInNow = cur.step === "authenticated" && !cur.recovery_codes?.length;
  useEffect(() => {
    if (signedInNow) done();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signedInNow]);
  if (cur.step === "authenticated") {
    return cur.recovery_codes?.length ? <RecoveryCodesView codes={cur.recovery_codes} onDone={done} /> : <p>Signing in…</p>;
  }
  if (!cur.pending) return <ErrorBox error="The server's answer was not understood." />;
  return cur.step === "second_factor_required" ? (
    <SecondFactor pending={cur.pending} next={next} onResult={setCur} onRestart={onRestart} />
  ) : (
    <Enrol pending={cur.pending} next={next} onResult={setCur} onRestart={onRestart} />
  );
}

/** Username and password (the sign-in form, and with `fixedUser` the re-authentication form). */
export function PasswordForm({ next, fixedUser, onResponse, notice, submitLabel = "Sign in" }: {
  next?: string;
  fixedUser?: string;
  onResponse: (r: LoginResponse) => void;
  notice?: string | null;
  submitLabel?: string;
}) {
  const [username, setUsername] = useState(fixedUser ?? "");
  const [pw, setPw] = useState("");
  const { busy, error, run } = useAction();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const r = await api.post<LoginResponse>("/auth/login", { username: username.trim(), password: pw, next });
      setPw("");
      onResponse(r);
    });
  };
  return (
    <form onSubmit={submit}>
      {notice && <div className="notice" role="status" data-testid="auth-notice">{notice}</div>}
      <Field label="Username" value={username} onChange={setUsername} autoComplete="username" testid="auth-username" autoFocus={!fixedUser} readOnly={!!fixedUser} required />
      <Field label="Password" type="password" value={pw} onChange={setPw} autoComplete="current-password" testid="auth-password" autoFocus={!!fixedUser} required />
      <ErrorBox error={error} />
      <div className="auth-actions">
        <button className="btn primary" type="submit" disabled={busy} data-testid="auth-submit">{submitLabel}</button>
      </div>
    </form>
  );
}
