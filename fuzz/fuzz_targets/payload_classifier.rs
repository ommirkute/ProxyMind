#![no_main]
//! Payload-aware tiers: never panic, and never rate a request below its method.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let c = pm_policy::payload::classify_http(data);
    let (tier, _) = pm_policy::Tier::for_http_request(data);
    assert!(tier >= c.tier);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = pm_policy::payload::normalise(s);
    }
});
