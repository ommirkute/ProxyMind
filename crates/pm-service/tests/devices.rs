//! Devices and mobile onboarding: client addresses in history, names, the `client` filter, the QR page data.

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::{HistoryFilter, NewExchange, Store};
use pm_service::{ProxyInfo, Service};

fn ex(path: &str, ts: i64, client: Option<&str>) -> NewExchange {
    NewExchange {
        ts_ms: ts,
        duration_ms: Some(1),
        source: "proxy".into(),
        actor_id: "human:local".into(),
        scheme: "http".into(),
        host: "shop.test".into(),
        port: 80,
        method: "GET".into(),
        path: path.into(),
        status: Some(200),
        request: format!("GET {path} HTTP/1.1\r\nHost: shop.test\r\n\r\n").into_bytes(),
        response: Some(b"HTTP/1.1 200 OK\r\n\r\nok".to_vec()),
        error: None,
        identity: None,
        hypothesis_id: None,
        client_addr: client.map(str::to_string),
        ..Default::default()
    }
}

fn service(name: &str) -> Service {
    let dir = std::env::temp_dir().join(format!("pm-devices-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("p.pmproj");
    let mut s = Store::open(&path).unwrap();
    s.insert_exchange(&ex("/old", 1, None)).unwrap();
    s.insert_exchange(&ex("/a", 10, Some("192.168.1.23"))).unwrap();
    s.insert_exchange(&ex("/b", 20, Some("192.168.1.24"))).unwrap();
    s.insert_exchange(&ex("/c", 30, Some("192.168.1.23"))).unwrap();
    Service::new(
        Store::open(&path).unwrap(),
        Policy::new(Roe::parse("version: 1\nscope:\n  include: [\"http://shop.test/\"]\n").unwrap()),
    )
    .unwrap()
}

fn paths(s: &Service, f: HistoryFilter) -> Vec<String> {
    let f = HistoryFilter { limit: Some(100), ..f };
    s.history_search(&Actor::parse("human:t").unwrap(), &f).unwrap().exchanges.into_iter().map(|e| e.path).collect()
}

fn by_client(c: &str) -> HistoryFilter {
    HistoryFilter { client: Some(c.into()), ..Default::default() }
}

fn by_query(q: &str) -> HistoryFilter {
    HistoryFilter { q: Some(q.into()), ..Default::default() }
}

#[test]
fn devices_are_listed_named_and_removed() {
    let s = service("names");
    let human = Actor::parse("human:tester").unwrap();
    let list = s.devices_list().unwrap().devices;
    assert_eq!(
        list.iter().map(|d| (d.addr.as_str(), d.exchanges, d.last_seen_ms, d.name.clone())).collect::<Vec<_>>(),
        [("192.168.1.23", 2, Some(30), None), ("192.168.1.24", 1, Some(20), None)],
        "most recent first; rows without a client are not devices"
    );

    // Naming: humans only, an IP address only, a sensible name only.
    assert!(s.device_set_name(&Actor::parse("agent:x").unwrap(), "192.168.1.23", "Pixel 8").is_err());
    assert!(s.device_set_name(&human, "pixel", "Pixel 8").is_err());
    assert!(s.device_set_name(&human, "192.168.1.23", "  ").is_err());
    assert!(s.device_set_name(&human, "192.168.1.23", &"x".repeat(61)).is_err());
    assert!(s.device_set_name(&human, "192.168.1.23", "a\nb").is_err());
    let d = s.device_set_name(&human, "192.168.1.23", " Pixel 8 ").unwrap();
    assert_eq!((d.name.as_deref(), d.exchanges), (Some("Pixel 8"), 2));
    // A named device that has sent nothing yet is listed after the seen ones.
    s.device_set_name(&human, "10.0.0.9", "iPad").unwrap();
    let list = s.devices_list().unwrap().devices;
    assert_eq!(list.iter().map(|d| d.addr.as_str()).collect::<Vec<_>>(), ["192.168.1.23", "192.168.1.24", "10.0.0.9"]);
    assert_eq!(list[2].exchanges, 0);
    assert_eq!(list[2].last_seen_ms, None);

    assert!(s.device_remove_name(&Actor::parse("agent:x").unwrap(), "192.168.1.23").is_err());
    s.device_remove_name(&human, "192.168.1.23").unwrap();
    assert!(s.device_remove_name(&human, "192.168.1.23").is_err(), "nothing left to remove");
    assert_eq!(s.devices_list().unwrap().devices[0].name, None);
    // Naming is audited.
    assert!(s.audit_list(10).unwrap().iter().any(|r| r.action == "device_name"));
}

#[test]
fn history_filters_by_client_address_or_device_name_and_hql() {
    let s = service("filter");
    let human = Actor::parse("human:tester").unwrap();
    s.device_set_name(&human, "192.168.1.23", "Pixel 8").unwrap();
    s.device_set_name(&human, "192.168.1.24", "pixel 8").unwrap(); // the same name on a second address

    assert_eq!(paths(&s, by_client("192.168.1.23")), ["/c", "/a"]);
    assert_eq!(paths(&s, by_client("Pixel 8")), ["/c", "/b", "/a"], "a name means every address that has it");
    assert_eq!(paths(&s, by_client("PIXEL 8")), ["/c", "/b", "/a"], "case-insensitive");
    assert!(paths(&s, by_client("nobody")).is_empty());
    assert!(paths(&s, by_client("192.168.1.2")).is_empty(), "exact");

    assert_eq!(paths(&s, by_query("client:192.168.1.24")), ["/b"]);
    assert_eq!(paths(&s, by_query("client:\"pixel 8\"")), ["/c", "/b", "/a"]);
    assert_eq!(paths(&s, by_query("-client:\"pixel 8\"")), ["/old"]);
    assert_eq!(paths(&s, by_query("device:192.168.1.23 path:/a")), ["/a"]);
    // The filter and the query combine.
    let both = HistoryFilter { client: Some("192.168.1.23".into()), q: Some("path:/c".into()), ..Default::default() };
    assert_eq!(paths(&s, both), ["/c"]);
    // The address is in the summary.
    let page = s.history_search(&Actor::parse("human:t").unwrap(), &by_client("192.168.1.24")).unwrap();
    assert_eq!(page.exchanges[0].client_addr.as_deref(), Some("192.168.1.24"));
}

#[test]
fn mobile_setup_says_what_a_phone_can_reach() {
    let proxy = |addr: &str| ProxyInfo { addr: addr.into(), ca_pem: String::new(), profile_dir: std::env::temp_dir() };

    // No proxy in this process.
    let s = service("mobile-none");
    let m = s.mobile_setup().unwrap();
    assert!(!m.proxy_running && !m.listener_reachable && m.urls.is_empty() && m.qr_svg.is_none());
    assert_eq!(m.setup_host_url, "http://proxymind.setup/");

    // Loopback only: not reachable, and no URL or QR code is offered for it.
    let s = service("mobile-loopback");
    s.attach_proxy_info(proxy("127.0.0.1:8080"));
    let m = s.mobile_setup().unwrap();
    assert!(m.proxy_running && !m.listener_reachable && m.urls.is_empty() && m.qr_svg.is_none());
    assert_eq!(m.listeners, ["127.0.0.1:8080"]);

    // A LAN address: a URL, the proxy address to type into the phone, and a QR code of that URL.
    let s = service("mobile-lan");
    s.attach_proxy_info(proxy("192.168.1.5:8080"));
    let m = s.mobile_setup().unwrap();
    assert!(m.listener_reachable);
    assert_eq!(m.urls, ["http://192.168.1.5:8080/"]);
    assert_eq!(m.proxy_addresses, ["192.168.1.5:8080"]);
    assert_eq!(m.qr_url.as_deref(), Some("http://192.168.1.5:8080/"));
    let svg = m.qr_svg.unwrap();
    assert!(svg.starts_with("<svg ") && !svg.contains("<script"));
}
