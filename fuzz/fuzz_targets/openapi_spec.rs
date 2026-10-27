#![no_main]
//! OpenAPI import on hostile specs: never panic, bounded output.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(spec) = pm_openapi::parse(text)
    {
        assert!(spec.operations.len() <= pm_openapi::MAX_OPERATIONS);
        // The spec may come from the target: each example is one well-formed head.
        for op in &spec.operations {
            let raw = op.example_request.as_bytes();
            let end = pm_http::find_head_end(raw).unwrap().expect("complete head");
            pm_http::parse_request_head(&raw[..end]).expect("valid request head");
        }
    }
});
