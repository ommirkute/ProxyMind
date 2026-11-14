//! ADR-0017 steps 3 and 4: the recorder, the indexer and audited `Service` writes share one write connection.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_proxy::Recorder;
use pm_service::pm_store::{NewExchange, Store};
use pm_service::{NewFinding, Service};

fn exchange(i: usize) -> NewExchange {
    NewExchange {
        ts_ms: i as i64,
        duration_ms: Some(1),
        source: "proxy".into(),
        actor_id: "human:local".into(),
        scheme: "https".into(),
        host: "shop.test".into(),
        port: 443,
        method: "GET".into(),
        path: format!("/r/{i}"),
        status: Some(200),
        request: format!("GET /r/{i} HTTP/1.1\r\nHost: shop.test\r\n\r\n").into_bytes(),
        response: Some(format!("HTTP/1.1 200 OK\r\n\r\nmarker-{i}").into_bytes()),
        error: None,
        identity: None,
        hypothesis_id: None,
    }
}

#[test]
fn audit_chain_stays_valid_while_the_recorder_writes_through_the_shared_handle() {
    const RECORDS: usize = 3000;
    const THREADS: usize = 4;
    const FINDINGS_EACH: usize = 25;
    let dir = std::env::temp_dir().join(format!("pm-shared-write-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("p.pmproj");
    let roe = Roe::parse("version: 1\nscope:\n  include: [\"https://shop.test/\"]\n").unwrap();
    let svc = Arc::new(Service::new(Store::open(&path).unwrap(), Policy::new(roe)).unwrap());
    let me = Actor::parse("human:local").unwrap();

    let handle = svc.store_handle();
    assert!(Arc::ptr_eq(&handle, &svc.store_handle()), "one shared write connection");
    let first = handle.write(|s| s.insert_exchange(&exchange(0))).unwrap();
    let (recorder, writer) = Recorder::spawn_shared(handle);

    let done = AtomicBool::new(false);
    std::thread::scope(|sc| {
        let verifier = sc.spawn(|| {
            let mut checks = 0;
            while !done.load(Ordering::Relaxed) {
                svc.audit_verify().expect("the chain verifies at every moment");
                checks += 1;
            }
            checks
        });
        let producer = sc.spawn(|| {
            for i in 1..=RECORDS {
                recorder.record(exchange(i));
            }
        });
        let creators: Vec<_> = (0..THREADS)
            .map(|t| {
                let (svc, me) = (&svc, &me);
                sc.spawn(move || {
                    for i in 0..FINDINGS_EACH {
                        svc.finding_create(
                            me,
                            NewFinding {
                                title: format!("F {t}/{i}"),
                                vuln_class: "idor".into(),
                                severity: "low".into(),
                                description: "audited write during recording".into(),
                                url: Some(format!("https://shop.test/f/{t}/{i}")),
                                evidence: vec![first],
                                hypothesis_id: None,
                            },
                        )
                        .unwrap();
                    }
                })
            })
            .collect();
        for c in creators {
            c.join().unwrap();
        }
        producer.join().unwrap();
        done.store(true, Ordering::Relaxed);
        assert!(verifier.join().unwrap() > 0);
    });

    drop(recorder);
    writer.join().unwrap(); // the queue is drained
    let records = svc.audit_verify().unwrap();
    assert!(records >= THREADS * FINDINGS_EACH, "every audited write left a record ({records})");
    let seqs: Vec<i64> = svc.audit_list(10_000).unwrap().iter().map(|r| r.seq).collect();
    assert!(seqs.windows(2).all(|w| w[0] == w[1] + 1), "seq is contiguous (newest first)");
    assert_eq!(svc.counters().unwrap().exchanges, (RECORDS + 1) as i64, "no recorded exchange was lost");
    let _ = std::fs::remove_dir_all(dir);
}
