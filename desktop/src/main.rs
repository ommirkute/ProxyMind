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

fn project() -> PathBuf {
    std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("PROXYMIND_PROJECT").map(PathBuf::from))
        .unwrap_or_else(|| home().join("desktop.pmproj"))
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
    // The user's passive-check plugins (ADR-0014).
    match pm_plugin::Registry::load(home) {
        Ok(r) => service.set_plugins(r.enabled()),
        Err(e) => eprintln!("plugins not loaded: {e}"),
    }
    // ROE edits (Engagement page, `proxymind roe use`) apply while the app runs.
    pm_service::watch_roe(service.clone());
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
            // The recorder's writer thread lives as long as the app.
            std::mem::forget(writer);
            let queue = Arc::new(pm_proxy::InterceptQueue::new());
            service.attach_intercept(queue.clone());
            let rewriter = Arc::new(pm_proxy::Rewriter::new());
            service.attach_rewriter(rewriter.clone())?;
            pm_service::watch_project(project, Some(rewriter.clone()), service.network().clone())?;
            let hooks = pm_proxy::Hooks {
                rewrite: Some(rewriter),
                intercept: Some(queue),
                network: Some(service.network().clone()),
                http2: true,
            };
            let p = Proxy::with_hooks(ca.clone(), recorder, false, hooks)?;
            tokio::spawn(p.run(l));
            Some(proxy_addr)
        }
        Err(e) => {
            eprintln!("proxy not started on {proxy_addr}: {e}");
            pm_service::watch_project(project, None, service.network().clone())?;
            None
        }
    };

    let state = pm_api::AppState::new(service, actor()?, token.clone(), project.display().to_string())?;
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

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let (project, home) = (project(), home());
            let started = tauri::async_runtime::block_on(start(&project, &home));
            let (url, title) = match &started {
                Ok(s) => {
                    let proxy = s.proxy.map_or("proxy off: port busy".to_string(), |p| format!("proxy {p}"));
                    (WebviewUrl::External(s.url.parse()?), format!("ProxyMind: {} ({proxy})", project.display()))
                }
                Err(e) => {
                    let why: String = format!("{e:#}").bytes().map(|b| format!("%{b:02X}")).collect();
                    (WebviewUrl::App(format!("setup.html#{why}").into()), "ProxyMind: set up a project".into())
                }
            };
            WebviewWindowBuilder::new(app, "main", url).title(title).inner_size(1360.0, 860.0).build()?;

            let open = MenuItem::with_id(app, "open", "Open ProxyMind", true, None::<&str>)?;
            let ca_text = match &started {
                Ok(s) => format!("CA certificate: {}", s.ca.display()),
                Err(_) => "No project loaded".into(),
            };
            let ca = MenuItem::with_id(app, "ca", ca_text, false, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &ca, &quit])?;
            let mut tray =
                TrayIconBuilder::new().tooltip("ProxyMind").menu(&menu).on_menu_event(|app, e| match e.id().as_ref() {
                    "open" => show_main(app),
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
