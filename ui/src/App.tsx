import { useEffect, useMemo, useState } from "react";
import { api, type Counters, type Status } from "./api";
import { NavContext, type Page } from "./components";
import History from "./pages/History";
import Intercept from "./pages/Intercept";
import Repeater from "./pages/Repeater";
import Intruder from "./pages/Intruder";
import Rules from "./pages/Rules";
import Approvals from "./pages/Approvals";
import Assistant from "./pages/Assistant";
import Authz from "./pages/Authz";
import Model from "./pages/Model";
import Network from "./pages/Network";
import Findings from "./pages/Findings";
import Issues from "./pages/Issues";
import Tools from "./pages/Tools";
import Audit from "./pages/Audit";
import SiteMap from "./pages/SiteMap";
import Engagement from "./pages/Engagement";
import Setup from "./pages/Setup";
import WsHistory from "./pages/WsHistory";

interface Group {
  id: string;
  label: string;
  pages: { id: Page; label: string }[];
}

/** Top tabs and their sub-tabs, laid out like Burp. */
const GROUPS: Group[] = [
  { id: "dashboard", label: "Dashboard", pages: [
    { id: "findings", label: "Findings" },
    { id: "issues", label: "Scanner issues" },
    { id: "approvals", label: "Approvals" },
    { id: "audit", label: "Audit log" },
  ] },
  { id: "target", label: "Target", pages: [
    { id: "sitemap", label: "Site map & Search" },
    { id: "model", label: "Model & Coverage" },
    { id: "engagement", label: "Scope & rules" },
  ] },
  { id: "proxy", label: "Proxy", pages: [
    { id: "intercept", label: "Intercept" },
    { id: "history", label: "HTTP history" },
    { id: "wshistory", label: "WebSockets history" },
    { id: "rules", label: "Match & replace" },
    { id: "setup", label: "Proxy setup" },
  ] },
  { id: "intruder", label: "Intruder", pages: [{ id: "intruder", label: "Intruder" }] },
  { id: "repeater", label: "Repeater", pages: [{ id: "repeater", label: "Repeater" }] },
  { id: "authz", label: "Authz", pages: [{ id: "authz", label: "Identities & Authz" }] },
  { id: "tools", label: "Tools", pages: [{ id: "tools", label: "Decoder, Comparer, Sequencer" }] },
  { id: "assistant", label: "Assistant", pages: [{ id: "assistant", label: "Assistant" }] },
  { id: "settings", label: "Settings", pages: [{ id: "network", label: "Network" }] },
];

const PAGES = GROUPS.flatMap((g) => g.pages);
const groupOf = (p: Page) => GROUPS.find((g) => g.pages.some((x) => x.id === p)) ?? GROUPS[2];
/** The sub-tab last opened in each group, so a top tab returns to it. */
const lastIn: Record<string, Page> = {};

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
    const load = () =>
      api
        .get<Status>("/status")
        .then((s) => {
          setStatus(s);
          setCounters(s.counters);
        })
        .catch((e) => setAuthError(e.message));
    load();
    // Pages that change what the header shows (e.g. the engagement) ask for a refresh.
    window.addEventListener("pm-status-changed", load);
    return () => window.removeEventListener("pm-status-changed", load);
  }, []);

  // Live updates: the server pushes counters when anything changes.
  const signedIn = status != null;
  useEffect(() => {
    if (!signedIn) return;
    const es = new EventSource("/api/v1/events");
    es.addEventListener("counters", (e) => setCounters(JSON.parse((e as MessageEvent).data)));
    es.onopen = () => setLive(true);
    es.onerror = () => setLive(false);
    return () => es.close();
  }, [signedIn]);

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
    assistant: Assistant,
    intercept: Intercept,
    rules: Rules,
    repeater: Repeater,
    intruder: Intruder,
    approvals: Approvals,
    authz: Authz,
    model: Model,
    issues: Issues,
    tools: Tools,
    sitemap: SiteMap,
    engagement: Engagement,
    setup: Setup,
    wshistory: WsHistory,
    findings: Findings,
    audit: Audit,
    network: Network,
  }[route.page];

  const group = groupOf(route.page);
  lastIn[group.id] = route.page;
  const badge = (id: Page) =>
    id === "intercept" ? counters?.intercepted ?? 0 : id === "approvals" ? counters?.pending_approvals ?? 0 : 0;
  const groupBadge = (g: Group) => g.pages.reduce((n, p) => n + badge(p.id), 0);

  return (
    <NavContext.Provider value={nav}>
      <div className="app">
        <header className="topnav">
          <div className="topnav-row">
            <div className="brand">
              Proxy<span>Mind</span>
            </div>
            <nav className="maintabs" aria-label="Main">
              {GROUPS.map((g) => (
                <button
                  key={g.id}
                  className={`maintab ${group.id === g.id ? "active" : ""}`}
                  aria-current={group.id === g.id ? "page" : undefined}
                  onClick={() => nav.go(lastIn[g.id] ?? g.pages[0].id)}
                  data-testid={`tab-${g.id}`}
                >
                  {g.label}
                  {groupBadge(g) > 0 && (
                    <span
                      className="badge"
                      data-testid={g.id === "proxy" ? "intercept-badge" : g.id === "dashboard" ? "approvals-badge" : undefined}
                    >
                      {groupBadge(g)}
                    </span>
                  )}
                  {g.id === "dashboard" && (counters?.findings ?? 0) > 0 && <span className="chip">{counters?.findings}</span>}
                </button>
              ))}
            </nav>
            <div className="topnav-status">
              <span title={live ? "Live" : "Reconnecting…"}>
                <span className={`live ${live ? "" : "off"}`} />
                {counters?.exchanges ?? 0} exchanges
              </span>
              <span title={status?.project}>{status?.you_are}</span>
              <span className="muted">v{status?.version}</span>
            </div>
          </div>
          <div className="topnav-row sub">
            {group.pages.length > 1 ? (
              <nav className="subtabs" aria-label={group.label}>
                {group.pages.map((p) => (
                  <button
                    key={p.id}
                    className={`subtab ${route.page === p.id ? "active" : ""}`}
                    aria-current={route.page === p.id ? "page" : undefined}
                    onClick={() => nav.go(p.id)}
                  >
                    {p.label}
                    {badge(p.id) > 0 && <span className="badge">{badge(p.id)}</span>}
                  </button>
                ))}
              </nav>
            ) : (
              <span className="subtitle">{group.pages[0].label}</span>
            )}
            <span className="meta grow" title={status?.in_scope.join(", ")}>
              {status?.engagement ?? "No engagement name"} · Scope: {status?.in_scope.join(", ")}
            </span>
          </div>
        </header>
        <main className="main">
          <PageView />
        </main>
      </div>
    </NavContext.Provider>
  );
}
