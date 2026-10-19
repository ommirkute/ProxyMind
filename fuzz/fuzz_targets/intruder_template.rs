#![no_main]
//! Intruder templates and planning: bounded output, never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (raw, payloads) = text.split_once('\n').unwrap_or((&text, "a\nb"));
    if let Ok(t) = pm_fuzz::Template::parse(raw) {
        let set: Vec<String> = payloads.lines().take(20).map(str::to_string).collect();
        let sets = vec![set; t.positions().min(3)];
        for mode in [pm_fuzz::Mode::Sniper, pm_fuzz::Mode::BatteringRam, pm_fuzz::Mode::Pitchfork, pm_fuzz::Mode::ClusterBomb] {
            if let Ok(p) = pm_fuzz::plan(&t, mode, &sets) {
                assert!(p.len() <= pm_fuzz::MAX_REQUESTS);
            }
        }
    }
});
