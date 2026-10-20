//! Importing VulnShop's own OpenAPI description from a recorded response.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{OpenApiImportRequest, OpenApiImportResult, ReplayRequest, ReplayResult, Service};

#[tokio::test]
async fn imports_a_recorded_spec_and_sends_safe_examples() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let human = Actor::parse("human:tester").unwrap();
    let ReplayResult::Sent { exchange_id, .. } = s
        .replay_send(
            &human,
            ReplayRequest {
                url: Some(url.clone()),
                raw: Some("GET /openapi.json HTTP/1.1\r\nHost: x\r\n\r\n".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
    else {
        panic!()
    };

    // Listing only: nothing is sent.
    let r = s
        .openapi_import(&human, OpenApiImportRequest { exchange_id: Some(exchange_id), ..Default::default() })
        .await
        .unwrap();
    let OpenApiImportResult::Imported { title, base_url, operations, sent, .. } = r else { panic!("{r:?}") };
    assert_eq!(title, "VulnShop API");
    assert_eq!(base_url.as_deref(), Some(url.as_str()), "relative server resolved against where the spec came from");
    assert_eq!(operations.len(), 10);
    let order = operations.iter().find(|o| o.path == "/api/orders/{id}").unwrap();
    assert!(order.auth);
    assert!(order.example_request.starts_with("GET /api/orders/1001 HTTP/1.1"), "{}", order.example_request);
    let login = operations.iter().find(|o| o.path == "/api/login").unwrap();
    assert!(login.example_request.ends_with(r#"{"username":"alice","password":"alice123"}"#));
    assert!(sent.is_empty());
    assert_eq!(s.openapi_get().unwrap()["operations"].as_array().unwrap().len(), 10);

    // Sending the GET examples records them, and the model learns the operations.
    let r = s
        .openapi_import(
            &human,
            OpenApiImportRequest { exchange_id: Some(exchange_id), send_examples: true, ..Default::default() },
        )
        .await
        .unwrap();
    let OpenApiImportResult::Imported { sent, .. } = r else { panic!() };
    assert_eq!(sent.len(), 6, "{sent:?}");
    let search = sent.iter().find(|x| x.path == "/api/products/search").unwrap();
    assert_eq!(search.status, Some(200));
    let model = serde_json::to_string(&s.model_get(&Default::default()).unwrap()).unwrap();
    assert!(model.contains("/api/reviews"), "{model}");

    // Agents sending examples need approval only if the ROE asks; bad input is refused.
    assert!(s.openapi_import(&human, OpenApiImportRequest::default()).await.is_err());
    let bad = OpenApiImportRequest { spec: Some("{\"hello\":1}".into()), ..Default::default() };
    assert!(s.openapi_import(&human, bad).await.is_err());
}
