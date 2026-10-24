#![no_main]
//! The raw HTTP/1.x parser and HTTP/2 text form: never panic, and the
//! head end is always inside the input.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(end)) = pm_http::find_head_end(data) {
        assert!(end <= data.len());
        if let Ok(h) = pm_http::parse_request_head(&data[..end]) {
            let _ = h.body_kind();
            let _ = h.wants_close();
        }
        if let Ok(h) = pm_http::parse_response_head(&data[..end]) {
            let _ = h.body_kind("GET");
        }
        let mut scan = pm_http::ChunkedScanner::new();
        if let Ok(Some(n)) = scan.scan(&data[end..]) {
            assert!(n <= data.len() - end);
        }
    }
    let _ = pm_http::decode_chunked(data);
    let _ = pm_http::split_message(data);
    let _ = pm_http::h2text::h2_request(data);
    let _ = pm_http::h2text::to_http1_response(data);
    let _ = pm_http::fix_content_length(data);
});
