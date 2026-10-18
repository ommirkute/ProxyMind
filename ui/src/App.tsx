import { useEffect, useMemo, useState } from "react";
import { api, type Counters, type Status } from "./api";
import { NavContext, type Page } from "./components";
import History from "./pages/History";
import Intercept from "./pages/Intercept";
import Repeater from "./pages/Repeater";
import Approvals from "./pages/Approvals";
import Authz from "./pages/Authz";
import Model from "./pages/Model";
import Findings from "./pages/Findings";
import Audit from "./pages/Audit";

const PAGES: { id: Page; label: string }[] = [
  { id: "history", label: "History" },
  { id: "intercept", label: "Intercept" },
  { id: "repeater", label: "Repeater" },
  { id: "approvals", label: "Approvals" },
  { id: "authz", label: "Identities & Authz" },
  { id: "model", label: "Model & Coverage" },
  { id: "findings", label: "Findings" },
  { id: "audit", label: "Audit log" },
];

function parseHash(): { page: Page; arg?: string } {
  const [p, arg] = window.location.hash.replace(/^#\/?/, "").split("/");
  const page = (PAGES.find((x) => x.id === p)?.id ?? "history") as Page;
  return { page, arg: arg ? decodeURIComponent(arg) : undefined };
}

export default function App() {
  const [route, setRoute] = useState(parseHash);
  const [status, setStatus] = useState<Status | null>(null);
  const [counters, setCounters] = useState<Counters | null>(null);
  const [live, setLive] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  useEffect(() => {
    const onHash = () => setRoute(parseHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    api
      .get<Status>("/status")
      .then((s) => {
        setStatus(s);
        setCounters(s.counters);
      })
      .catch((e) => setAuthError(e.message));
  }, []);

  // Live updates: the server pushes counters when anything changes.
  useEffect(() => {
    if (!status) return;
    const es = new EventSource("/api/v1/events");
    es.addEventListener("counters", (e) => setCounters(JSON.parse((e as MessageEvent).data)));
    es.onopen = () => setLive(true);
    es.onerror = () => setLive(false);
    return () => es.close();
  }, [status]);

  const nav = useMemo(
    () => ({
      page: route.page,
      arg: route.arg,
      counters,
      go: (page: Page, arg?: number | string) => {
        window.location.hash = arg === undefined ? `#/${page}` : `#/${page}/${encodeURIComponent(String(arg))}`;
      },
    }),
    [route, counters],
  );

  if (authError) {
    return (
      <div className="panel" style={{ maxWidth: 560, margin: "80px auto" }}>
        <h2>Not signed in</h2>
        <p>{authError}</p>
        <p className="muted">
          Open the link printed by <code>proxymind ui</code> (it looks like
          <code> http://127.0.0.1:7777/auth?token=…</code>).
        </p>
      </div>
    );
  }

  const PageView = {
    history: History,
    intercept: Intercept,
    repeater: Repeater,
    approvals: Approvals,
    authz: Authz,
    model: Model,
    findings: Findings,
    audit: Audit,
  }[route.page];

  return (
    <NavContext.Provider value={nav}>
      <div className="app">
        <nav className="sidebar" aria-label="Main">
          <div className="brand">
            Proxy<span>Mind</span>
          </div>
          {PAGES.map((p) => (
            <button
              key={p.id}
              className={`nav ${route.page === p.id ? "active" : ""}`}
              onClick={() => nav.go(p.id)}
              aria-current={route.page === p.id ? "page" : undefined}
            >
              <span>{p.label}</span>
              {p.id === "intercept" && (counters?.intercepted ?? 0) > 0 && (
                <span className="badge" data-testid="intercept-badge">{counters?.intercepted}</span>
              )}
              {p.id === "approvals" && (counters?.pending_approvals ?? 0) > 0 && (
                <span className="badge" data-testid="approvals-badge">{counters?.pending_approvals}</span>
              )}
              {p.id === "findings" && (counters?.findings ?? 0) > 0 && (
                <span className="chip">{counters?.findings}</span>
              )}
            </button>
          ))}
          <div className="sidebar-foot">
            <div>
              <span className={`live ${live ? "" : "off"}`} />
              {live ? "Live" : "Reconnecting…"}
            </div>
            <div>{counters?.exchanges ?? 0} exchanges</div>
            <div title={status?.project}>{status?.you_are}</div>
            <div>v{status?.version}</div>
          </div>
        </nav>
        <main className="main">
          <header className="topbar">
            <h1>{PAGES.find((p) => p.id === route.page)?.label}</h1>
            <span className="meta">{status?.engagement ?? "No engagement name"}</span>
            <span className="meta grow">Scope: {status?.in_scope.join(", ")}</span>
          </header>
          <PageView />
        </main>
      </div>
    </NavContext.Provider>
  );
}
