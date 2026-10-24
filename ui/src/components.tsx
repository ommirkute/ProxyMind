import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import type { Counters } from "./api";

export type Page = "overview" | "scans" | "library" | "history" | "intercept" | "rules" | "repeater" | "intruder" | "approvals" | "authz" | "model" | "issues" | "tools" | "findings" | "audit" | "network" | "assistant" | "sitemap" | "engagement" | "setup" | "wshistory" | "sessions";

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
  // scan tasks and tiers
  done: "ok",
  crawling: "info",
  auditing: "info",
  cancelled: "",
  failed: "bad",
  destructive: "bad",
  active_intrusive: "warn",
  active_safe: "info",
  // severities
  critical: "crit",
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
        <div className="panel-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="actions">{actions}</div>}
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

/** Copies text; falls back to a hidden textarea where the clipboard API is blocked (plain http). */
export async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const t = document.createElement("textarea");
    t.value = text;
    document.body.append(t);
    t.select();
    document.execCommand("copy");
    t.remove();
  }
}

/** Hex dump: offset, 16 bytes, printable ASCII. */
export function hexDump(bytes: Uint8Array, max = 256 * 1024): string {
  const lines: string[] = [];
  const n = Math.min(bytes.length, max);
  for (let off = 0; off < n; off += 16) {
    const row = bytes.subarray(off, Math.min(off + 16, n));
    const hex = Array.from(row, (b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const ascii = Array.from(row, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${off.toString(16).padStart(8, "0")}  ${hex}  ${ascii}`);
  }
  if (bytes.length > n) lines.push(`… ${bytes.length - n} more bytes`);
  return lines.join("\n");
}

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** The head as is and the body pretty-printed when it's JSON (or a decoded body is given). */
/** Removes the wrapper that marks target content for models; people see the content itself. */
export function unwrapUntrusted(s: string | null | undefined): string | null | undefined {
  const m = s?.match(/^<untrusted_target_content>\n?([\s\S]*?)\n?<\/untrusted_target_content>$/);
  return m ? m[1] : s;
}

export function prettyMessage(raw: string, decodedBody?: string | null): string {
  decodedBody = unwrapUntrusted(decodedBody);
  const i = raw.indexOf("\r\n\r\n");
  const j = i >= 0 ? i + 4 : raw.indexOf("\n\n") >= 0 ? raw.indexOf("\n\n") + 2 : raw.length;
  const head = raw.slice(0, j).replace(/\r\n/g, "\n");
  const body = decodedBody ?? raw.slice(j);
  const t = body.trim();
  if ((t.startsWith("{") || t.startsWith("[")) && t.length < 2_000_000) {
    try {
      return head + JSON.stringify(JSON.parse(t), null, 2);
    } catch {
      /* not JSON after all */
    }
  }
  return head + body;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Text with every match of `q` highlighted (case-insensitive, at most 1000 marks). */
export function Highlighted({ text, q }: { text: string; q: string }) {
  if (!q) return <>{text}</>;
  const parts = text.split(new RegExp(`(${escapeRe(q)})`, "i"));
  const out: ReactNode[] = [];
  let marks = 0;
  for (let i = 0; i < parts.length; i++) {
    if (i % 2 === 1 && marks < 1000) {
      out.push(<mark key={i}>{parts[i]}</mark>);
      marks++;
    } else out.push(parts[i]);
  }
  return <>{out}</>;
}

export type ViewMode = "pretty" | "raw" | "hex";

/**
 * A request or response with Pretty / Raw / Hex views and a search box.
 * `loadB64` fetches the exact bytes for the hex view on demand.
 */
const HEX_MAX = 256 * 1024;
const PRETTY_MAX = 2_000_000;
const fmtSize = (n: number) => (n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} bytes`);

export function MessageView({
  text,
  decodedBody,
  loadB64,
  empty,
  testid,
  truncated,
  onShowAll,
}: {
  text: string | null | undefined;
  decodedBody?: string | null;
  loadB64?: () => Promise<string | null | undefined>;
  empty?: string;
  testid?: string;
  /** Full length in bytes when `text` was cut. */
  truncated?: number | null;
  onShowAll?: () => void;
}) {
  const [mode, setMode] = useState<ViewMode>(() => {
    try {
      return (localStorage.getItem("pm.viewMode") as ViewMode) || "pretty";
    } catch {
      return "pretty";
    }
  });
  const [q, setQ] = useState("");
  const [hex, setHex] = useState<string | null>(null);
  useEffect(() => setHex(null), [text]);
  useEffect(() => {
    if (mode !== "hex" || hex !== null || text == null) return;
    // Hex is four times the size of the bytes: show the start of big ones.
    const dump = (b: Uint8Array) => setHex(hexDump(b.subarray(0, HEX_MAX)) + (b.length > HEX_MAX ? `\n… ${fmtSize(b.length - HEX_MAX)} more` : ""));
    const fallback = () => dump(new TextEncoder().encode(text));
    if (!loadB64) return fallback();
    loadB64()
      .then((b) => (b ? dump(b64ToBytes(b)) : fallback()))
      .catch(fallback);
  }, [mode, hex, text, loadB64]);
  const choose = (m: ViewMode) => {
    setMode(m);
    try {
      localStorage.setItem("pm.viewMode", m);
    } catch {
      /* storage blocked */
    }
  };
  if (text == null) return <Empty>{empty ?? "Nothing to show"}</Empty>;
  // Pretty-printing very large messages would freeze the page.
  const pretty = mode === "pretty" && text.length <= PRETTY_MAX;
  const shown = mode === "hex" ? (hex ?? "Loading…") : pretty ? prettyMessage(text, decodedBody) : text;
  const count = q ? shown.split(new RegExp(escapeRe(q), "i")).length - 1 : 0;
  return (
    <div className="msgview" data-testid={testid}>
      <div className="msgbar">
        {(["pretty", "raw", "hex"] as ViewMode[]).map((m) => (
          <button key={m} className={`seg ${mode === m ? "on" : ""}`} onClick={() => choose(m)} aria-pressed={mode === m}>
            {m[0].toUpperCase() + m.slice(1)}
          </button>
        ))}
        <input className="grow" aria-label="Search in message" placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} />
        {q && <span className="small muted" data-testid="search-count">{count} match{count === 1 ? "" : "es"}</span>}
        <button className="seg" title="Copy" onClick={() => copyText(shown)}>Copy</button>
      </div>
      {truncated ? (
        <div className="notice small" data-testid="truncated">
          Showing the first {fmtSize(text.length)} of {fmtSize(truncated)}.{" "}
          {onShowAll && <button className="btn small" onClick={onShowAll}>Show all</button>}
        </div>
      ) : null}
      {mode === "pretty" && !pretty && <div className="small muted">Too large to pretty-print; showing raw.</div>}
      <pre className={`raw ${mode === "hex" ? "hex" : ""}`}>
        <Highlighted text={shown} q={q} />
      </pre>
    </div>
  );
}

export interface MenuItem {
  label: string;
  hint?: string;
  onClick?: () => void;
  disabled?: boolean;
  /** Colour swatch rows (highlights). */
  swatches?: { color: string | null; onClick: () => void }[];
}

/** A right-click menu at (x, y); closes on any click, scroll or Escape. */
export function ContextMenu({ x, y, items, onClose }: { x: number; y: number; items: MenuItem[]; onClose: () => void }) {
  useEffect(() => {
    const close = () => onClose();
    const key = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("click", close);
    window.addEventListener("blur", close);
    window.addEventListener("keydown", key);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("blur", close);
      window.removeEventListener("keydown", key);
    };
  }, [onClose]);
  const left = Math.min(x, window.innerWidth - 260);
  const top = Math.min(y, window.innerHeight - items.length * 30 - 20);
  return (
    <div className="ctxmenu" role="menu" style={{ left, top }} onContextMenu={(e) => e.preventDefault()}>
      {items.map((it, i) =>
        it.swatches ? (
          <div key={i} className="ctx-swatches" role="group" aria-label={it.label}>
            <span className="small muted">{it.label}</span>
            {it.swatches.map((sw) => (
              <button
                key={sw.color ?? "none"}
                className={`swatch ${sw.color ? `hl-${sw.color}` : "none"}`}
                title={sw.color ?? "none"}
                aria-label={`Highlight ${sw.color ?? "none"}`}
                onClick={sw.onClick}
              />
            ))}
          </div>
        ) : (
          <button key={i} role="menuitem" className="ctx-item" disabled={it.disabled} onClick={it.onClick}>
            <span>{it.label}</span>
            {it.hint && <span className="muted small">{it.hint}</span>}
          </button>
        ),
      )}
    </div>
  );
}

export const HIGHLIGHTS = ["red", "orange", "yellow", "green", "blue", "purple", "gray"] as const;

/** Reads and writes a per-browser preference; storage may be blocked. */
export function usePref<T>(key: string, initial: T): [T, (v: T) => void] {
  const [v, setV] = useState<T>(() => {
    try {
      const s = localStorage.getItem(key);
      if (!s) return initial;
      const parsed = JSON.parse(s);
      // Objects gain fields added since they were saved; plain values are used as they are.
      const isObj = (x: unknown) => typeof x === "object" && x !== null && !Array.isArray(x);
      return isObj(initial) && isObj(parsed) ? { ...initial, ...parsed } : (parsed as T);
    } catch {
      return initial;
    }
  });
  const set = (x: T) => {
    setV(x);
    try {
      localStorage.setItem(key, JSON.stringify(x));
    } catch {
      /* storage blocked */
    }
  };
  return [v, set];
}
