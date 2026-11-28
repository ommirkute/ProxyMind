#![no_main]
//! The HTTP/3 text form (ADR-0021) and `Alt-Svc` parsing: never panic on any input, a request that parses renders
//! as HTTP/3 text, and every alternative a response offers has a protocol and an authority.
use libfuzzer_sys::fuzz_target;
use pm_http::h3text;

fuzz_target!(|data: &[u8]| {
    let _ = h3text::is_http3_request(data);
    let _ = h3text::is_http3_response(data);
    if let Ok(r) = h3text::h3_request(data) {
        let text = h3text::render_h3_request(&r);
        assert!(h3text::is_http3_request(&text));
        let _ = h3text::h3_request(&text);
    }
    if let Some(found) = h3text::alt_svc_h3(data) {
        assert!(found.iter().all(|a| a.is_h3() && !a.protocol.is_empty() && !a.authority.is_empty()));
    }
    if let Ok(s) = std::str::from_utf8(data) {
        for a in h3text::parse_alt_svc(s) {
            assert!(!a.protocol.is_empty() && !a.authority.is_empty());
        }
    }
    let _ = pm_http::h2text::to_http1_response(data);
    if let Ok(r) = pm_http::h2text::h2_response(data) {
        let text = h3text::render_h3_response(r.status, &r.headers, &r.body);
        assert!(h3text::is_http3_response(&text));
    }
});
