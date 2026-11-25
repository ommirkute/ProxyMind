// The start of the UI. It asks the server which mode it runs in:
//  * single-user mode (`/api/v1/auth/state` answers `server_mode: false`, or 401 without the install-token cookie): the
//    app is shown at once, exactly as before;
//  * server mode (`server_mode: true`): setup, invite or sign-in screens come first and the app shell only renders for a
//    signed-in member of the served project.
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import App from "./App";
import { api, authHooks } from "./api";
import type { LoginResponse, MeResponse, StateResponse } from "./api-types.gen";
import {
  AuthContext,
  AuthScreen,
  currentLocation,
  errText,
  Field,
  NewAccountForm,
  PasswordForm,
  sameOriginPath,
  Steps,
  type AuthCtx,
} from "./authparts";
import { ErrorBox, useAction } from "./components";

type Stage =
  | { k: "loading" }
  | { k: "single" }
  | { k: "error"; message: string }
  | { k: "setup"; state: StateResponse }
  | { k: "invite"; token: string }
  | { k: "signin"; next: string; notice?: string }
  | { k: "notmember"; me: MeResponse }
  | { k: "app"; me: MeResponse };

/** Reads the one-time tokens from the URL fragment (`#setup=…`, `#invite=…`). Nothing is stored. */
function readFragmentTokens(): { setup: string | null; invite: string | null } {
  const p = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  return { setup: p.get("setup") || null, invite: p.get("invite") || null };
}

/** Takes a token out of the address bar and the history entry (it is never sent to the server by the browser). */
function clearFragment() {
  window.history.replaceState(null, "", window.location.pathname + window.location.search);
}

export default function Root() {
  const [stage, setStage] = useState<Stage>({ k: "loading" });
  const tokens = useRef<{ setup: string | null; invite: string | null } | null>(null);
  tokens.current ??= readFragmentTokens();

  const loadMe = useCallback(async (): Promise<void> => {
    try {
      const me = await api.get<MeResponse>("/auth/me");
      // Unchanged answers keep the same object, so the periodic read below does not re-render the app.
      setStage((prev) =>
        prev.k === "app" && me.role != null && JSON.stringify(prev.me) === JSON.stringify(me)
          ? prev
          : me.role == null
            ? { k: "notmember", me }
            : { k: "app", me },
      );
    } catch (e) {
      const status = (e as { status?: number }).status;
      // `sessionEnded` may already have set the sign-in with its notice (a session lost while the app was shown).
      if (status === 401) setStage((prev) => (prev.k === "signin" ? prev : { k: "signin", next: currentLocation() }));
      else setStage({ k: "error", message: errText(e) });
    }
  }, []);

  // One re-authentication dialog at a time: calls that need it together share its answer.
  const [reauth, setReauth] = useState(false);
  const reauthPromise = useRef<Promise<boolean> | null>(null);
  const reauthDone = useRef<((ok: boolean) => void) | null>(null);

  // A signed-in page that sees its session end (any 401) returns to the sign-in; afterwards, to where it was.
  const sessionEnded = useCallback(() => {
    reauthDone.current?.(false);
    setStage((s) =>
      s.k === "app" || s.k === "notmember"
        ? { k: "signin", next: currentLocation(), notice: "Your session ended. Sign in again to continue." }
        : s,
    );
  }, []);
  const installHooks = useCallback(() => {
    authHooks.serverMode = true;
    authHooks.onUnauthenticated = sessionEnded;
    authHooks.onNotMember = () => void loadMe();
    authHooks.onForbidden = () => void loadMe();
    authHooks.reauthenticate = () => {
      reauthPromise.current ??= new Promise<boolean>((resolve) => {
        reauthDone.current = (ok) => {
          reauthPromise.current = null;
          reauthDone.current = null;
          setReauth(false);
          resolve(ok);
        };
        setReauth(true);
      });
      return reauthPromise.current;
    };
  }, [sessionEnded, loadMe]);

  // The role can change under an open page (an owner promotes or demotes), and a removed member's session ends. No
  // polling (ADR-0018): the event stream says so (`role`, or it drops), and coming back to the tab reads it again.
  // A 401 then shows the sign-in.
  const inApp = stage.k === "app";
  useEffect(() => {
    if (!inApp) return;
    const again = () => void loadMe();
    const visible = () => document.visibilityState === "visible" && again();
    window.addEventListener("pm-role-changed", again);
    document.addEventListener("visibilitychange", visible);
    return () => {
      window.removeEventListener("pm-role-changed", again);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [inApp, loadMe]);

  // Mode detection, once.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      let state: StateResponse | null = null;
      try {
        state = await api.get<StateResponse>("/auth/state");
      } catch {
        state = null; // 401 without the install token, or an older server: single-user mode
      }
      if (cancelled) return;
      if (!state?.server_mode) return setStage({ k: "single" });
      installHooks();
      const { setup, invite } = tokens.current!;
      if (setup || invite) clearFragment();
      if (state.setup_required) return setStage({ k: "setup", state });
      if (invite) return setStage({ k: "invite", token: invite });
      await loadMe();
    })();
    return () => {
      cancelled = true;
    };
  }, [loadMe, installHooks]);

  /** Signed in: go where the server says (a path on this origin) and load the account. */
  const enter = useCallback(
    async (res: LoginResponse) => {
      window.history.replaceState(null, "", sameOriginPath(res.next) ?? "/");
      await loadMe();
    },
    [loadMe],
  );
  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      // already gone: the sign-in screen is right either way
    }
    window.history.replaceState(null, "", "/");
    setStage({ k: "signin", next: "/" });
  }, []);

  const ctx = useMemo<AuthCtx | null>(
    () => (stage.k === "app" ? { me: stage.me, refresh: loadMe, logout, sessionEnded } : null),
    [stage, loadMe, logout, sessionEnded],
  );

  switch (stage.k) {
    case "loading":
      return null;
    case "single":
      return <App />;
    case "error":
      return (
        <AuthScreen>
          <h2>Can't reach the server</h2>
          <ErrorBox error={stage.message} />
          <div className="auth-actions">
            <button className="btn primary" onClick={() => window.location.reload()}>Try again</button>
          </div>
        </AuthScreen>
      );
    case "setup":
      return <SetupScreen state={stage.state} token={tokens.current!.setup} onDone={enter} />;
    case "invite":
      return <InviteScreen token={stage.token} onDone={enter} />;
    case "signin":
      return <SignInScreen key={stage.notice ?? "plain"} next={stage.next} notice={stage.notice} onDone={enter} />;
    case "notmember":
      return (
        <AuthScreen>
          <h2>Not a member of this project</h2>
          <p data-testid="not-member">
            You're signed in as <b>{stage.me.user.display_name || stage.me.user.username}</b> ({stage.me.user.username}), but
            you are not a member of the project this server serves. Ask a project owner for an invite or to add you.
          </p>
          {stage.me.user.server_admin && (
            <p className="small muted">Being a server administrator manages accounts; it gives no access to the project's data.</p>
          )}
          <div className="auth-actions">
            <button className="btn primary" data-testid="sign-out" onClick={() => void logout()}>Sign out</button>
          </div>
        </AuthScreen>
      );
    case "app":
      return (
        <AuthContext.Provider value={ctx}>
          <App />
          {reauth && <ReauthDialog me={stage.me} onResult={(ok) => reauthDone.current?.(ok)} refresh={loadMe} />}
        </AuthContext.Provider>
      );
  }
}

// ---- the screens -----------------------------------------------------------------------------------------------

function SignInScreen({ next, notice, onDone }: { next: string; notice?: string; onDone: (r: LoginResponse) => void }) {
  const [first, setFirst] = useState<LoginResponse | null>(null);
  const [message, setMessage] = useState<string | null>(notice ?? null);
  return (
    <AuthScreen wide={!!first}>
      {!first && <h2>Sign in</h2>}
      {first ? (
        <Steps
          first={first}
          next={next}
          onDone={onDone}
          onRestart={(m) => {
            setMessage(m || null);
            setFirst(null);
          }}
        />
      ) : (
        <PasswordForm next={next} notice={message} onResponse={setFirst} />
      )}
    </AuthScreen>
  );
}

function SetupScreen({ state, token, onDone }: { state: StateResponse; token: string | null; onDone: (r: LoginResponse) => void }) {
  const [pasted, setPasted] = useState("");
  const [first, setFirst] = useState<LoginResponse | null>(null);
  const { busy, error, run } = useAction();
  // The token from the link, or one pasted from the console (the whole URL or just the token).
  const given = token ?? (pasted.includes("#setup=") ? pasted.split("#setup=")[1] : pasted).trim();
  const [claimed, setClaimed] = useState(false);

  if (!state.setup_allowed) {
    return (
      <AuthScreen>
        <h2>Set up this server</h2>
        <p data-testid="setup-not-allowed">
          Setup is only served over HTTPS, or from the computer the server runs on. Open this server through its HTTPS
          address (or at <code>http://127.0.0.1</code> on the server itself) to create the first account.
        </p>
      </AuthScreen>
    );
  }
  if (first) {
    return (
      <AuthScreen wide>
        <Steps first={first} onDone={onDone} onRestart={() => window.location.reload()} />
      </AuthScreen>
    );
  }
  if (!token && !claimed) {
    return (
      <AuthScreen>
        <h2>Set up this server</h2>
        <p data-testid="setup-no-token">
          This server has no owner yet. When it started it printed a one-time setup link on its console (it ends in{" "}
          <span className="mono">#setup=…</span>, works once and lasts an hour). Open that link, or paste it here.
        </p>
        <form
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            if (given) setClaimed(true);
          }}
        >
          <Field label="Setup link or token" value={pasted} onChange={setPasted} testid="setup-token" autoFocus required />
          <div className="auth-actions">
            <button className="btn primary" type="submit" data-testid="auth-submit">Continue</button>
          </div>
        </form>
      </AuthScreen>
    );
  }
  return (
    <AuthScreen>
      <h2>Create the owner account</h2>
      <p>
        You are the first person here. This account becomes the server administrator and the owner of the project. You will
        add an authenticator app next.
      </p>
      <NewAccountForm
        submitLabel="Create account"
        busy={busy}
        error={error}
        onSubmit={(v) => void run(async () => setFirst(await api.post<LoginResponse>("/auth/setup", { setup_token: given, ...v })))}
      />
    </AuthScreen>
  );
}

function InviteScreen({ token, onDone }: { token: string; onDone: (r: LoginResponse) => void }) {
  const [first, setFirst] = useState<LoginResponse | null>(null);
  const { busy, error, run } = useAction();
  if (first) {
    return (
      <AuthScreen wide>
        <Steps first={first} onDone={onDone} onRestart={() => window.location.reload()} />
      </AuthScreen>
    );
  }
  return (
    <AuthScreen>
      <h2>Join this project</h2>
      <p>You have been invited. Choose a username and password; you will add an authenticator app next.</p>
      <NewAccountForm
        submitLabel="Create account"
        busy={busy}
        error={error}
        onSubmit={(v) => void run(async () => setFirst(await api.post<LoginResponse>("/auth/invite/accept", { invite: token, ...v })))}
      />
    </AuthScreen>
  );
}

/** A sensitive action needs a recent sign-in: password (and code), then the action is repeated by the caller. */
function ReauthDialog({ me, onResult, refresh }: { me: MeResponse; onResult: (ok: boolean) => void; refresh: () => Promise<void> }) {
  const [first, setFirst] = useState<LoginResponse | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const finish = async () => {
    await refresh();
    onResult(true);
  };
  return (
    <div className="modal-back" data-testid="reauth-backdrop">
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="reauth-title" data-testid="reauth-dialog">
        <h2 id="reauth-title">Confirm it's you</h2>
        <p className="small muted">This needs a recent sign-in. Sign in again as {me.user.username} to continue.</p>
        {first ? (
          <Steps
            first={first}
            onDone={() => void finish()}
            onRestart={(m) => {
              setMessage(m || null);
              setFirst(null);
            }}
          />
        ) : (
          <PasswordForm fixedUser={me.user.username} notice={message} onResponse={setFirst} submitLabel="Sign in again" />
        )}
        <div className="auth-actions">
          <button className="btn ghost" data-testid="reauth-cancel" onClick={() => onResult(false)}>Cancel</button>
        </div>
      </div>
    </div>
  );
}
