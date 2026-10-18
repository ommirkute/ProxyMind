import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import type { Counters } from "./api";

export type Page = "history" | "intercept" | "rules" | "repeater" | "approvals" | "authz" | "model" | "findings" | "audit";

export interface Nav {
  page: Page;
  /** Optional argument for the page, e.g. an exchange id for the Repeater. */
  arg?: number | string;
  go: (page: Page, arg?: number | string) => void;
  counters: Counters | null;
}

export const NavContext = createContext<Nav>({ page: "history", go: () => {}, counters: null });
export const useNav = () => useContext(NavContext);

/** Loads data, reloading when `deps` change. */
export function useLoad<T>(load: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const reload = useCallback(() => {
    setLoading(true);
    load()
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(reload, [reload]);
  return { data, error, loading, reload, setData };
}

/** Runs an action, tracking busy state and errors. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      setError((e as Error).message);
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, run, setError };
}

export function ErrorBox({ error }: { error: string | null | undefined }) {
  return error ? <div className="error" role="alert">{error}</div> : null;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

const CHIP: Record<string, string> = {
  // verdicts / statuses
  denied: "ok",
  same_as_owner: "bad",
  allowed_different: "info",
  inconclusive: "",
  error: "warn",
  needs_approval: "warn",
  not_allowed: "",
  pending: "warn",
  approved: "ok",
  used: "",
  ok: "ok",
  logged_out: "bad",
  unknown: "",
  suspected: "warn",
  proven: "bad",
  confirmed: "bad",
  false_positive: "",
  reported: "accent",
  untested: "warn",
  open: "info",
  testing: "info",
  refuted: "ok",
  allow: "ok",
  deny: "",
  response: "accent",
  // severities
  critical: "bad",
  high: "bad",
  medium: "warn",
  low: "info",
  info: "",
};

export function Chip({ value, title }: { value: string; title?: string }) {
  const cls = CHIP[value] ?? (value.startsWith("pending") ? "warn" : value.startsWith("rejected") ? "bad" : "");
  return (
    <span className={`chip ${cls}`} title={title}>
      {value.replace(/_/g, " ")}
    </span>
  );
}

export function StatusCode({ status, error }: { status: number | null; error?: string | null }) {
  if (status == null) return <span className="status-err" title={error ?? ""}>ERR</span>;
  return <span className={`status-${String(status)[0]}`}>{status}</span>;
}

export function Raw({ text, label }: { text: string | null | undefined; label?: string }) {
  if (text == null) return <Empty>{label ?? "Nothing to show"}</Empty>;
  return <pre className="raw">{text}</pre>;
}

export function Panel({ title, actions, children }: { title?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      {(title || actions) && (
        <div className="row" style={{ marginBottom: 10 }}>
          {title && <h2 style={{ margin: 0 }} className="grow">{title}</h2>}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

/** Link-like button that jumps to an exchange in History. */
export function ExchangeLink({ id }: { id: number | null | undefined }) {
  const { go } = useNav();
  if (id == null) return <span className="muted">–</span>;
  return (
    <a href="#" onClick={(e) => { e.preventDefault(); go("history", id); }}>
      #{id}
    </a>
  );
}
