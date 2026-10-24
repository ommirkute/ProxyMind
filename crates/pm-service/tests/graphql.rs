//! GraphQL against VulnShop: fetch the schema through the gate, then use an
//! example request to show the invoice resolver leaks other users' invoices.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{GraphQlImportRequest, GraphQlImportResult, ReplayRequest, ReplayResult, ScanFilter, Service};

#[tokio::test]
async fn fetches_the_schema_and_uses_an_example() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let human = Actor::parse("human:tester").unwrap();

    let r = s
        .graphql_import(
            &human,
            GraphQlImportRequest { url: Some(format!("{url}/graphql")), fetch: true, ..Default::default() },
        )
        .await
        .unwrap();
    let GraphQlImportResult::Imported { operations, exchange_id, query_type, .. } = r else { panic!("{r:?}") };
    assert_eq!(query_type.as_deref(), Some("Query"));
    let names: Vec<&str> = operations.iter().map(|o| o.op.name.as_str()).collect();
    assert_eq!(names, ["me", "invoice", "products"]);
    let fetched = exchange_id.expect("the introspection exchange");

    // The passive scan notices introspection is on.
    let issues = s.scan_passive(&human, &ScanFilter::default()).unwrap();
    assert!(issues.iter().any(|i| i.check == "graphql_introspection"), "{issues:?}");

    // Re-importing from the recorded exchange gives the same operations, without sending.
    let before = s.counters().unwrap().exchanges;
    let again = s
        .graphql_import(&human, GraphQlImportRequest { exchange_id: Some(fetched), ..Default::default() })
        .await
        .unwrap();
    let GraphQlImportResult::Imported { operations: ops2, url: u2, .. } = again else { panic!() };
    assert_eq!(ops2.len(), 3);
    assert_eq!(u2.as_deref(), Some(format!("{url}/graphql").as_str()));
    assert_eq!(s.counters().unwrap().exchanges, before);
    assert_eq!(s.graphql_get().unwrap()["operations"].as_array().unwrap().len(), 3);

    // Bob asks for invoice 5001 (alice's): GraphQL hands it over (VS-12).
    let login = "POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 41\r\n\r\n{\"username\":\"bob\",\"password\":\"bob123\"}";
    let sent = s
        .replay_send(
            &human,
            ReplayRequest {
                url: Some(url.clone()),
                raw: Some(login.into()),
                fix_content_length: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let ReplayResult::Sent { exchange_id: login_id, .. } = sent else { panic!("{sent:?}") };
    let resp = String::from_utf8(s.exchange_raw(login_id).unwrap().response.unwrap()).unwrap();
    let session = resp.split("session=").nth(1).unwrap().split(';').next().unwrap().to_string();

    let invoice = operations.iter().find(|o| o.op.name == "invoice").unwrap();
    let raw = invoice.example_request.clone().unwrap().replace("\"id\":\"1\"", "\"id\":\"5001\"");
    let raw = raw.replacen("\r\n", &format!("\r\nCookie: session={session}\r\n"), 1);
    let sent = s
        .replay_send(
            &human,
            ReplayRequest {
                url: Some(url.clone()),
                raw: Some(raw),
                fix_content_length: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let ReplayResult::Sent { exchange_id: leak, .. } = sent else { panic!("{sent:?}") };
    let body = String::from_utf8(s.exchange_raw(leak).unwrap().response.unwrap()).unwrap();
    assert!(body.contains("alice@vulnshop.test"), "{body}");

    // Errors.
    let bad = GraphQlImportRequest { schema: Some("{\"data\":{}}".into()), ..Default::default() };
    assert!(s.graphql_import(&human, bad).await.is_err());
    assert!(s.graphql_import(&human, GraphQlImportRequest { fetch: true, ..Default::default() }).await.is_err());
}

#[tokio::test]
async fn fetching_out_of_scope_is_denied() {
    let roe = "version: 1\nscope:\n  include: [\"https://in.test/\"]\n";
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(roe).unwrap())).unwrap();
    let agent = Actor::parse("agent:a").unwrap();
    let req = GraphQlImportRequest { url: Some("https://out.test/graphql".into()), fetch: true, ..Default::default() };
    let r = s.graphql_import(&agent, req).await.unwrap();
    assert!(matches!(r, GraphQlImportResult::Denied { .. }), "{r:?}");
}
