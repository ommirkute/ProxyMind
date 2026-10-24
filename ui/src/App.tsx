import { useEffect, useMemo, useState } from "react";
import { api, openBrowser, toast, type Counters, type Status } from "./api";
import { NavContext, usePref, type Page } from "./components";
import { Icon } from "./icons";
import Overview from "./pages/Overview";
import Scans from "./pages/Scans";
import Library from "./pages/Library";
import { CommandPalette } from "./palette";
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
import Sessions from "./pages/Sessions";

interface Group {
  id: string;
  label: string;
  icon: string;
  /** Sidebar section the group sits in. */
  section: string;
  pages: { id: Page; label: string }[];
}

/** Sidebar entries and their sub-pages (shown as tabs in the header). */
const GROUPS: Group[] = [
  { id: "dashboard", label: "Dashboard", icon: "dashboard", section: "Workspace", pages: [
    { id: "overview", label: "Overview" },
    { id: "findings", label: "Findings" },
    { id: "issues", label: "Scanner issues" },
    { id: "scans", label: "Scans" },
    { id: "approvals", label: "Approvals" },
    { id: "audit", label: "Audit log" },
  ] },
  { id: "target", label: "Target", icon: "target", section: "Workspace", pages: [
    { id: "sitemap", label: "Site map & Search" },
    { id: "model", label: "Model & Coverage" },
    { id: "engagement", label: "Scope & rules" },
  ] },
  { id: "proxy", label: "Proxy", icon: "proxy", section: "Testing", pages: [
    { id: "intercept", label: "Intercept" },
    { id: "history", label: "HTTP history" },
    { id: "wshistory", label: "WebSockets history" },
    { id: "rules", label: "Match & replace" },
    { id: "setup", label: "Proxy setup" },
  ] },
  { id: "repeater", label: "Repeater", icon: "repeater", section: "Testing", pages: [{ id: "repeater", label: "Repeater" }] },
  { id: "intruder", label: "Intruder", icon: "intruder", section: "Testing", pages: [{ id: "intruder", label: "Intruder" }] },
  { id: "authz", label: "Authz", icon: "authz", section: "Testing", pages: [{ id: "authz", label: "Identities & Authz" }] },
  { id: "tools", label: "Tools", icon: "tools", section: "Utilities", pages: [{ id: "tools", label: "Decoder, Comparer, Sequencer" }, { id: "library", label: "Issue library" }] },
  { id: "assistant", label: "Assistant", icon: "assistant", section: "Utilities", pages: [{ id: "assistant", label: "Assistant" }] },
  { id: "settings", label: "Settings", icon: "settings", section: "Utilities", pages: [{ id: "sessions", label: "Sessions" }, { id: "network", label: "Network" }] },
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
  const [theme, setTheme] = usePref<"system" | "light" | "dark">("pm-theme", "system");
  const [collapsed, setCollapsed] = usePref<boolean>("pm-sidebar-collapsed", false);
  const [palette, setPalette] = useState(false);
  const [browserOk, setBrowserOk] = useState(false);
  const [notice, setNotice] = useState<{ message: string; kind: string } | null>(null);
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onToast = (e: Event) => {
      setNotice((e as CustomEvent).detail);
      clearTimeout(timer);
      timer = setTimeout(() => setNotice(null), 4500);
    };
    window.addEventListener("pm-toast", onToast);
    return () => window.removeEventListener("pm-toast", onToast);
  }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  useEffect(() => {
    if (theme === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

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
    api.get<{ browser_available?: boolean }>("/setup").then((s) => setBrowserOk(!!s.browser_available)).catch(() => {});
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
      <div className="signin">
        <div className="signin-card">
          <div className="brand">
            <span className="brand-mark"><Icon name="logo" size={17} stroke={2} /></span>
            <span className="brand-name">Proxy<span>Mind</span></span>
          </div>
          <h2>Not signed in</h2>
          <p>{authError}</p>
          <p className="small">
            Open the link printed by <code style={{ display: "inline" }}>proxymind ui</code>. It looks like
            <code>http://127.0.0.1:7777/auth?token=…</code>
          </p>
        </div>
      </div>
    );
  }

  const PageView = {
    overview: Overview,
    scans: Scans,
    library: Library,
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
    sessions: Sessions,
    findings: Findings,
    audit: Audit,
    network: Network,
  }[route.page];

  const group = groupOf(route.page);
  lastIn[group.id] = route.page;
  const badge = (id: Page) =>
    id === "intercept" ? counters?.intercepted ?? 0 : id === "approvals" ? counters?.pending_approvals ?? 0 : 0;
  const groupBadge = (g: Group) => g.pages.reduce((n, p) => n + badge(p.id), 0);

  const sections = [...new Set(GROUPS.map((g) => g.section))];
  const nextTheme = { system: "light", light: "dark", dark: "system" } as const;
  const scope = status?.in_scope.join(", ") ?? "";

  return (
    <NavContext.Provider value={nav}>
      <div className={`app ${collapsed ? "collapsed" : ""}`}>
        <aside className="sidebar">
          <div className="brand">
            <span className="brand-mark"><Icon name="logo" size={17} stroke={2} /></span>
            <span className="brand-name">Proxy<span>Mind</span></span>
          </div>
          <nav className="maintabs" aria-label="Main">
            {sections.map((sec) => (
              <div key={sec} style={{ display: "contents" }}>
                <div className="nav-section">{sec}</div>
                {GROUPS.filter((g) => g.section === sec).map((g) => (
                  <button
                    key={g.id}
                    className={`maintab ${group.id === g.id ? "active" : ""}`}
                    aria-current={group.id === g.id ? "page" : undefined}
                    onClick={() => nav.go(lastIn[g.id] ?? g.pages[0].id)}
                    data-testid={`tab-${g.id}`}
                    title={g.label}
                  >
                    <Icon name={g.icon} size={17} />
                    <span className="label">{g.label}</span>
                    {groupBadge(g) > 0 && (
                      <span
                        className="badge"
                        data-testid={g.id === "proxy" ? "intercept-badge" : g.id === "dashboard" ? "approvals-badge" : undefined}
                      >
                        {groupBadge(g)}
                      </span>
                    )}
                    {g.id === "dashboard" && groupBadge(g) === 0 && (counters?.findings ?? 0) > 0 && (
                      <span className="chip plain">{counters?.findings}</span>
                    )}
                  </button>
                ))}
              </div>
            ))}
          </nav>
          <div className="sidebar-foot">
            <div className="project-card" title={status?.project}>
              <span className="avatar">{(status?.you_are ?? "?").replace(/^\w+:/, "").slice(0, 2)}</span>
              <div className="who">
                <b>{status?.you_are ?? "…"}</b>
                <span>{(status?.project ?? "").split(/[\\/]/).pop()}</span>
              </div>
            </div>
            <div className="foot-actions">
              <button
                className="icon-btn"
                onClick={() => setTheme(nextTheme[theme])}
                aria-label={`Theme: ${theme}`}
                title={`Theme: ${theme} (click to change)`}
              >
                <Icon name={theme === "dark" ? "moon" : theme === "light" ? "sun" : "monitor"} size={15} />
                <span className="label">{theme === "system" ? "Auto" : theme === "dark" ? "Dark" : "Light"}</span>
              </button>
              <button
                className="icon-btn"
                onClick={() => setCollapsed(!collapsed)}
                aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
                title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              >
                <Icon name="panel" size={15} />
                <span className="label">v{status?.version}</span>
              </button>
            </div>
          </div>
        </aside>
        <div className="main-col">
          <header className="topnav">
            <div className="crumbs">
              {group.pages.length === 1 && group.pages[0].label !== group.label ? (
                <>
                  <span>{group.label}</span>
                  <Icon name="chevron" size={14} />
                  <b>{group.pages[0].label}</b>
                </>
              ) : group.pages.length === 1 ? (
                <b>{group.label}</b>
              ) : (
                <span>{group.label}</span>
              )}
            </div>
            {group.pages.length > 1 && (
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
            )}
            <div className="topnav-status">
              {browserOk && (
                <button
                  className="btn primary sm"
                  data-testid="open-browser"
                  title="Open a browser that goes through ProxyMind and trusts its CA"
                  onClick={() =>
                    openBrowser()
                      .then((b) => toast(`Browser opened at ${b.url}`))
                      .catch((e) => toast(e.message, "bad"))
                  }
                >
                  <Icon name="globe" size={14} /> Open browser
                </button>
              )}
              <button className="pill search-pill" onClick={() => setPalette(true)} aria-label="Open command palette">
                <Icon name="search" size={13} />
                <span className="hide-narrow">Jump to…</span>
                <kbd>{/Mac/.test(navigator.platform) ? "⌘K" : "Ctrl K"}</kbd>
              </button>
              <span className="pill hide-narrow" title={`Scope: ${scope}`}>
                <Icon name="globe" size={13} />
                <span className="ellipsis-text meta">
                  {status?.engagement ? <b>{status.engagement}</b> : "No engagement"} · {scope || "no scope"}
                </span>
              </span>
              <span className="pill" title={live ? "Live: updates stream in" : "Reconnecting…"}>
                <span className={`live ${live ? "" : "off"}`} />
                {(counters?.exchanges ?? 0).toLocaleString()} exchanges
              </span>
            </div>
          </header>
          <main className="main">
            <PageView />
          </main>
          {notice && (
            <div className={`toast ${notice.kind}`} role="status" data-testid="toast">
              <Icon name={notice.kind === "bad" ? "alert" : "check"} size={15} />
              <span>{notice.message}</span>
            </div>
          )}
          <CommandPalette
            open={palette}
            onClose={() => setPalette(false)}
            items={GROUPS.flatMap((g) =>
              g.pages.map((p) => ({
                id: p.id,
                label: p.label,
                group: g.label,
                icon: g.icon,
                run: () => nav.go(p.id),
              })),
            )}
          />
        </div>
      </div>
    </NavContext.Provider>
  );
}
