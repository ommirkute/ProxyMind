//! ProxyMind desktop: the proxy, the API and the web UI in one window.
//!
//! The app starts the same stack as `proxymind ui` inside this process (API
//! on a random loopback port, proxy on 127.0.0.1:8080 when free) and opens
//! a webview at the login link. The page is a remote (http://127.0.0.1)
//! page, so it gets no Tauri IPC: it talks to `/api/v1` like any browser.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use pm_proxy::{Proxy, Recorder};
use pm_service::Service;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_store::Store;
use pm_tls::CertAuthority;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

struct Started {
    url: String,
    proxy: Option<SocketAddr>,
    ca: PathBuf,
}

fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("PROXYMIND_HOME") {
        return h.into();
    }
    let base = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).unwrap_or_else(|| ".".into());
    PathBuf::from(base).join(".proxymind")
}

/// What the app remembers between runs (`~/.proxymind/desktop.json`).
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct Prefs {
    /// Most recent first.
    recent: Vec<PathBuf>,
    /// Chosen in the app: opened on the next start, ahead of arguments.
    switch_to: Option<PathBuf>,
}

fn prefs_path() -> PathBuf {
    home().join("desktop.json")
}

fn load_prefs() -> Prefs {
    std::fs::read_to_string(prefs_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save_prefs(p: &Prefs) -> Result<()> {
    std::fs::create_dir_all(home())?;
    std::fs::write(prefs_path(), serde_json::to_string_pretty(p)?)?;
    Ok(())
}

/// The project to open: one picked in the app, else the argument, the
/// environment, the most recent one, or `~/.proxymind/desktop.pmproj`.
fn project() -> PathBuf {
    let mut prefs = load_prefs();
    if let Some(p) = prefs.switch_to.take() {
        let _ = save_prefs(&prefs);
        return p;
    }
    std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("PROXYMIND_PROJECT").map(PathBuf::from))
        .or_else(|| prefs.recent.first().cloned())
        .unwrap_or_else(|| home().join("desktop.pmproj"))
}

fn remember(project: &Path) {
    let mut prefs = load_prefs();
    let abs = std::fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf());
    prefs.recent.retain(|p| p != &abs);
    prefs.recent.insert(0, abs);
    prefs.recent.truncate(10);
    let _ = save_prefs(&prefs);
}

fn actor() -> Result<Actor> {
    let user = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "local".into());
    let user: String = user.chars().filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c)).collect();
    Ok(Actor::parse(&format!("human:{}", if user.is_empty() { "local" } else { &user }))?)
}

/// Starts the proxy and the API, returning the UI's login link.
async fn start(project: &Path, home: &Path) -> Result<Started> {
    std::fs::create_dir_all(home)?;
    let store = Store::open(project)?;
    let roe =
        store.get_setting("roe")?.with_context(|| format!("{} has no rules of engagement yet", project.display()))?;
    let service = Arc::new(Service::new(store, Policy::new(Roe::parse(&roe)?))?);
    // The user's plugins (ADR-0014, ADR-0015), read from their registry when used.
    service.attach_plugin_home(home.to_path_buf());
    // ROE edits (Engagement page, `proxymind roe use`) apply while the app runs.
    pm_service::watch_roe(service.clone());
    // Scheduled scans start while the app is open.
    tauri::async_runtime::spawn(service.clone().run_scheduler());
    let token = pm_api::load_or_create_token(&home.join("api-token"))?;

    // The proxy, as in `proxymind ui`; the UI still works if 8080 is taken.
    let ca = Arc::new(CertAuthority::load_or_create(home)?);
    let proxy_addr: SocketAddr = std::env::var("PROXYMIND_DESKTOP_PROXY")
        .ok()
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8080)));
    let proxy = match tokio::net::TcpListener::bind(proxy_addr).await {
        Ok(l) => {
            let (recorder, writer) = Recorder::spawn(Store::open(project)?);
            service.attach_recorder(&recorder)?;
            // The recorder's writer thread lives as long as the app.
            std::mem::forget(writer);
            let queue = Arc::new(pm_proxy::InterceptQueue::new());
            service.attach_intercept(queue.clone());
            let rewriter = Arc::new(pm_proxy::Rewriter::new());
            service.attach_rewriter(rewriter.clone())?;
            let hooks = pm_proxy::Hooks {
                rewrite: Some(rewriter.clone()),
                intercept: Some(queue),
                network: Some(service.network().clone()),
                http2: true,
            };
            let p = Proxy::with_hooks(ca.clone(), recorder, false, hooks)?;
            let extra = pm_proxy::Listeners::new(p.clone(), Some(proxy_addr));
            service.attach_listeners(extra.clone())?;
            pm_service::watch_project(project, Some(rewriter), service.network().clone(), Some(extra))?;
            tokio::spawn(p.run(l));
            // The built-in browser (Proxy → Open browser) uses this proxy.
            service.attach_proxy_info(pm_service::ProxyInfo {
                addr: proxy_addr.to_string(),
                ca_pem: ca.ca_pem().to_string(),
                profile_dir: project.with_extension("browser"),
            });
            Some(proxy_addr)
        }
        Err(e) => {
            eprintln!("proxy not started on {proxy_addr}: {e}");
            pm_service::watch_project(project, None, service.network().clone(), None)?;
            None
        }
    };

    let setup = pm_api::ProxySetup { proxy: proxy.map(|p| p.to_string()), ca_pem: Some(ca.ca_pem().to_string()) };
    let state =
        pm_api::AppState::new(service, actor()?, token.clone(), project.display().to_string())?.with_setup(setup);
    remember(project);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = l.local_addr()?.port();
    tokio::spawn(async move {
        if let Err(e) = axum::serve(l, pm_api::router(state)).await {
            eprintln!("API stopped: {e}");
        }
    });
    Ok(Started {
        url: format!("http://127.0.0.1:{port}/auth?token={token}"),
        proxy,
        ca: ca.ca_cert_path().to_path_buf(),
    })
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Opens (or focuses) a local app page, e.g. the project picker.
fn open_local(app: &tauri::AppHandle, label: &str, page: &str, title: &str) {
    if let Some(w) = app.get_webview_window(label) {
        let _ = w.close();
    }
    let built = WebviewWindowBuilder::new(app, label, WebviewUrl::App(page.into()))
        .title(title)
        .inner_size(720.0, 640.0)
        .build();
    if let Err(e) = built {
        eprintln!("cannot open {page}: {e}");
    }
}

fn hash_text(s: &str) -> String {
    s.bytes().map(|b| format!("%{b:02X}")).collect()
}

#[derive(serde::Serialize)]
struct ProjectEntry {
    path: String,
    exists: bool,
}

#[derive(serde::Serialize)]
struct Projects {
    current: Option<String>,
    recent: Vec<ProjectEntry>,
    suggested_dir: String,
}

/// Recent projects, for the picker (a local page; remote pages get no IPC).
#[tauri::command]
fn list_projects(state: tauri::State<'_, Current>) -> Projects {
    let recent = load_prefs()
        .recent
        .into_iter()
        .map(|p| ProjectEntry { exists: p.exists(), path: p.display().to_string() })
        .collect();
    Projects {
        current: state.0.as_ref().map(|p| p.display().to_string()),
        recent,
        suggested_dir: home().join("projects").display().to_string(),
    }
}

/// Checks a project can be opened (it exists and has rules of engagement).
fn check_project(path: &Path) -> Result<()> {
    anyhow::ensure!(path.exists(), "{} does not exist", path.display());
    let store = Store::open(path)?;
    let roe = store.get_setting(pm_service::ROE_SETTING)?.with_context(|| {
        format!("{} has no rules of engagement; create a new project or run `proxymind roe use`", path.display())
    })?;
    Roe::parse(&roe)?;
    Ok(())
}

fn switch(app: &tauri::AppHandle, path: PathBuf) -> Result<()> {
    let mut prefs = load_prefs();
    prefs.switch_to = Some(path);
    save_prefs(&prefs)?;
    app.restart();
}

/// Opens an existing project: the app restarts on it.
#[tauri::command]
fn open_project(app: tauri::AppHandle, path: String) -> Result<(), String> {
    let path = PathBuf::from(path.trim());
    check_project(&path).map_err(|e| format!("{e:#}"))?;
    switch(&app, path).map_err(|e| format!("{e:#}"))
}

/// The ROE for a new project: one engagement name and the targets in scope.
fn new_roe(name: &str, scope: &[String]) -> Result<String> {
    anyhow::ensure!(!scope.is_empty(), "give at least one target URL in scope");
    let quoted: Vec<String> = scope.iter().map(|s| serde_json::to_string(s.trim())).collect::<Result<_, _>>()?;
    let text = format!(
        "version: 1\nengagement:\n  name: {}\nscope:\n  include: [{}]\n",
        serde_json::to_string(name.trim())?,
        quoted.join(", ")
    );
    Roe::parse(&text)?;
    Ok(text)
}

/// Creates a project with rules of engagement for the given targets; the app restarts on it.
#[tauri::command]
fn create_project(app: tauri::AppHandle, path: String, name: String, scope: Vec<String>) -> Result<(), String> {
    let run = || -> Result<()> {
        let path = PathBuf::from(path.trim());
        anyhow::ensure!(!path.exists(), "{} already exists; open it instead", path.display());
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let text = new_roe(&name, &scope)?;
        let mut store = Store::open(&path)?;
        store.set_setting(pm_service::ROE_SETTING, &text)?;
        drop(store);
        switch(&app, path)
    };
    run().map_err(|e| format!("{e:#}"))
}

/// Adds the CA to the current user's trust store, where the OS has a
/// per-user one (it asks the user to confirm). Returns what happened.
fn install_ca(ca: &Path) -> String {
    let ca_s = ca.display().to_string();
    let (program, args): (&str, Vec<String>) = if cfg!(target_os = "macos") {
        let keychain =
            std::env::var("HOME").map(|h| format!("{h}/Library/Keychains/login.keychain-db")).unwrap_or_default();
        (
            "security",
            vec!["add-trusted-cert".into(), "-r".into(), "trustRoot".into(), "-k".into(), keychain, ca_s.clone()],
        )
    } else if cfg!(target_os = "windows") {
        ("certutil", vec!["-user".into(), "-addstore".into(), "Root".into(), ca_s.clone()])
    } else {
        let db = std::env::var("HOME").map(|h| format!("sql:{h}/.pki/nssdb")).unwrap_or_default();
        (
            "certutil",
            vec![
                "-d".into(),
                db,
                "-A".into(),
                "-t".into(),
                "C,,".into(),
                "-n".into(),
                "ProxyMind".into(),
                "-i".into(),
                ca_s.clone(),
            ],
        )
    };
    match std::process::Command::new(program).args(&args).output() {
        Ok(o) if o.status.success() => format!(
            "The ProxyMind CA is now trusted for your user ({program}). Restart your browser.\n\nCertificate: {ca_s}\n\nRemove it when the engagement ends."
        ),
        Ok(o) => format!(
            "{program} failed: {}\n\nInstall it by hand: open the Proxy setup page in ProxyMind for steps.\n\nCertificate: {ca_s}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!(
            "Couldn't run {program} ({e}).\n\nInstall it by hand: open the Proxy setup page in ProxyMind for steps (on Linux, certutil is in libnss3-tools).\n\nCertificate: {ca_s}"
        ),
    }
}

/// The project this run opened, if it opened.
struct Current(Option<PathBuf>);

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![list_projects, open_project, create_project])
        .setup(|app| {
            let (project, home) = (project(), home());
            let started = tauri::async_runtime::block_on(start(&project, &home));
            app.manage(Current(started.is_ok().then(|| project.clone())));
            let (url, title) = match &started {
                Ok(s) => {
                    let proxy = s.proxy.map_or("proxy off: port busy".to_string(), |p| format!("proxy {p}"));
                    (WebviewUrl::External(s.url.parse()?), format!("ProxyMind: {} ({proxy})", project.display()))
                }
                Err(e) => (
                    WebviewUrl::App(
                        format!("setup.html#{}", hash_text(&format!("{}: {e:#}", project.display()))).into(),
                    ),
                    "ProxyMind: choose a project".into(),
                ),
            };
            WebviewWindowBuilder::new(app, "main", url).title(title).inner_size(1360.0, 860.0).build()?;

            let open = MenuItem::with_id(app, "open", "Open ProxyMind", true, None::<&str>)?;
            let switch_item = MenuItem::with_id(app, "switch", "Switch project…", true, None::<&str>)?;
            let ca_path = started.as_ref().ok().map(|s| s.ca.clone());
            let install = MenuItem::with_id(
                app,
                "install_ca",
                "Trust the ProxyMind CA (this user)…",
                ca_path.is_some(),
                None::<&str>,
            )?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &switch_item, &install, &quit])?;
            let mut tray = TrayIconBuilder::new().tooltip("ProxyMind").menu(&menu).on_menu_event(move |app, e| match e
                .id()
                .as_ref()
            {
                "open" => show_main(app),
                "switch" => open_local(app, "picker", "setup.html", "ProxyMind: switch project"),
                "install_ca" => {
                    if let Some(ca) = &ca_path {
                        let msg = install_ca(ca);
                        open_local(
                            app,
                            "notice",
                            &format!("notice.html#{}", hash_text(&msg)),
                            "ProxyMind: CA certificate",
                        );
                    }
                }
                "quit" => app.exit(0),
                _ => {}
            });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("ProxyMind desktop failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_projects_get_valid_rules() {
        let text = new_roe("Acme \"Q4\": test", &["https://app.acme.test/".into()]).unwrap();
        let roe = Roe::parse(&text).unwrap();
        assert_eq!(roe.engagement.name.as_deref(), Some("Acme \"Q4\": test"));
        assert_eq!(roe.include[0].text, "https://app.acme.test/");
        assert!(new_roe("x", &[]).is_err());
        assert!(new_roe("x", &["not a url\n  evil: 1".into()]).is_err());
    }
}
