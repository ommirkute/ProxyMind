#![no_main]
//! OpenAPI import on hostile specs: never panic, bounded output.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(spec) = pm_openapi::parse(text)
    {
        assert!(spec.operations.len() <= pm_openapi::MAX_OPERATIONS);
    }
});
