//! Scan tasks survive a restart and resume where they left off; profiles
//! fill in settings; schedules start tasks when due.

use std::sync::Arc;
use std::time::Duration;

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{Every, ScanSchedule, ScanTaskRequest, ScanTaskStatus, ScanTaskView, Service};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

fn service(path: &std::path::Path, roe: &str) -> Arc<Service> {
    Arc::new(Service::new(Store::open(path).unwrap(), Policy::new(Roe::parse(roe).unwrap())).unwrap())
}

async fn wait(s: &Service, id: &str, until: impl Fn(&ScanTaskView) -> bool) -> ScanTaskView {
    for _ in 0..1200 {
        let v = s.scan_task_status(&human(), id).unwrap();
        if until(&v) {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out: {:?}", s.scan_task_status(&human(), id).unwrap());
}

#[tokio::test]
async fn an_interrupted_task_resumes_without_rescanning() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let dir = std::env::temp_dir().join(format!("pm-resume-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("p.pmproj");
    let _ = std::fs::remove_file(&path);

    let a = service(&path, &roe);
    let req = ScanTaskRequest {
        url: format!("{url}/"),
        max_pages: Some(20),
        browser: Some(false),
        checks: vec!["reflected_input".into(), "sql_error".into()],
        ..Default::default()
    };
    let id = a.scan_task_start(&human(), req).unwrap().task_id;
    let mid = wait(&a, &id, |v| v.status == ScanTaskStatus::Auditing && v.targets_done >= 2).await;
    assert!(mid.targets_total > mid.targets_done + 1, "enough left to resume: {mid:?}");

    // ProxyMind "restarts" while the task runs: the project opens again.
    let b = service(&path, &roe);
    let restored = b.scan_task_status(&human(), &id).unwrap();
    assert_eq!(restored.status, ScanTaskStatus::Paused, "{restored:?}");
    assert!(restored.notes.iter().any(|n| n.starts_with("interrupted")));
    a.scan_task_cancel(&human(), &id).unwrap();
    wait(&a, &id, |v| !v.status.running()).await;

    let resumed = b.scan_task_resume(&human(), &id).unwrap();
    assert_eq!(resumed.status, ScanTaskStatus::Auditing, "the crawl isn't repeated");
    let v = wait(&b, &id, |v| !v.status.running()).await;
    assert_eq!(v.status, ScanTaskStatus::Done, "{v:?}");
    assert_eq!(v.targets_done, v.targets_total);
    let skipped: usize = v
        .notes
        .iter()
        .find_map(|n| n.strip_prefix("resumed: skipped ")?.split(' ').next()?.parse().ok())
        .unwrap_or_else(|| panic!("{v:?}"));
    assert!(skipped >= 2, "{v:?}");
    assert!(b.scan_task_resume(&human(), &id).is_err(), "a finished task can't resume");

    // Pause and resume in one process.
    let req = ScanTaskRequest {
        url: format!("{url}/"),
        crawl: Some(false),
        checks: vec!["reflected_input".into()],
        ..Default::default()
    };
    let id2 = b.scan_task_start(&human(), req).unwrap().task_id;
    wait(&b, &id2, |v| v.targets_done >= 1).await;
    if b.scan_task_pause(&human(), &id2).is_ok() {
        let p = wait(&b, &id2, |v| !v.status.running()).await;
        if p.status == ScanTaskStatus::Paused {
            b.scan_task_resume(&human(), &id2).unwrap();
        }
    }
    assert_eq!(wait(&b, &id2, |v| !v.status.running()).await.status, ScanTaskStatus::Done);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn profiles_and_schedules() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());

    // Saved profiles sit next to the built-in ones; built-in names are taken.
    let names: Vec<String> = s.scan_profiles().unwrap().into_iter().map(|p| p.name).collect();
    assert_eq!(names, vec!["light", "default", "thorough", "api-only"]);
    let mine = pm_service::ScanProfile {
        name: "nightly".into(),
        checks: vec!["sql_error".into()],
        crawl: Some(false),
        ..Default::default()
    };
    s.scan_profile_save(&human(), mine.clone()).unwrap();
    assert!(s.scan_profile_save(&Actor::parse("agent:x").unwrap(), mine).is_err());
    assert!(
        s.scan_profile_save(&human(), pm_service::ScanProfile { name: "light".into(), ..Default::default() }).is_err()
    );
    let v = s
        .scan_task_start(
            &human(),
            ScanTaskRequest { url: format!("{url}/"), profile: Some("NIGHTLY".into()), ..Default::default() },
        )
        .unwrap();
    assert_eq!(v.profile.as_deref(), Some("nightly"));
    assert_eq!(v.status, ScanTaskStatus::Auditing, "the profile turned the crawl off");
    assert!(
        s.scan_task_start(
            &human(),
            ScanTaskRequest { url: url.clone(), profile: Some("nope".into()), ..Default::default() }
        )
        .is_err()
    );

    // A daily schedule fires once when due, as the human who saved it.
    let sched = s
        .schedule_save(
            &human(),
            ScanSchedule {
                name: "nightly scan".into(),
                every: Every::Daily { at: "02:00".into() },
                request: ScanTaskRequest {
                    url: format!("{url}/"),
                    profile: Some("nightly".into()),
                    ..Default::default()
                },
                enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        sched.next_run_ms
            > std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
    );
    assert!(s.schedule_tick(sched.next_run_ms - 1).unwrap().is_empty(), "not due yet");
    let started = s.schedule_tick(sched.next_run_ms).unwrap();
    assert_eq!(started.len(), 1);
    let task = s.scan_task_status(&human(), &started[0]).unwrap();
    assert_eq!(task.schedule_id, Some(sched.id));
    assert_eq!(task.actor, "human:tester");
    let after = s.schedule_list().unwrap().remove(0);
    assert_eq!(after.next_run_ms, sched.next_run_ms + 24 * 3600 * 1000);
    assert_eq!(after.last_task.as_deref(), Some(started[0].as_str()));
    assert!(s.schedule_tick(sched.next_run_ms).unwrap().is_empty(), "fires once per period");
    wait(&s, &started[0], |v| !v.status.running()).await;

    // Disabled schedules don't fire; agents can't change schedules.
    let mut off = after.clone();
    off.enabled = false;
    s.schedule_save(&human(), off).unwrap();
    assert!(s.schedule_tick(after.next_run_ms + 7 * 24 * 3600 * 1000).unwrap().is_empty());
    assert!(s.schedule_delete(&Actor::parse("agent:x").unwrap(), sched.id).is_err());
    assert!(s.schedule_delete(&human(), sched.id).unwrap());
    assert!(s.schedule_list().unwrap().is_empty());
}
