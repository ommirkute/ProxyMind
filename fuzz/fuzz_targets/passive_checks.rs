#![no_main]
//! Passive checks on arbitrary responses.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (head, body) = pm_http::split_message(data);
    if let Ok(h) = pm_http::parse_response_head(head) {
        for scheme in ["http", "https"] {
            let _ = pm_scan::check(&pm_scan::Exchange {
                scheme,
                request: b"GET / HTTP/1.1\r\nOrigin: https://x\r\n\r\n",
                status: h.status,
                headers: &h.headers,
                body,
            });
        }
    }
});
