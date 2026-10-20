#![no_main]
//! HAR files and curl commands from untrusted sources: never panic, and any
//! request built from them has a well-formed head.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Ok((entries, _)) = pm_tools::har::parse_har(&text, 0) {
        for e in entries {
            let end = pm_http::find_head_end(&e.request).unwrap().expect("complete head");
            pm_http::parse_request_head(&e.request[..end]).expect("valid request head");
        }
    }
    if let Ok(c) = pm_tools::curl::parse_curl(&text) {
        let end = pm_http::find_head_end(&c.raw).unwrap().expect("complete head");
        pm_http::parse_request_head(&c.raw[..end]).expect("valid request head");
        let cmd = pm_tools::curl::to_curl("http://x.test/", &c.raw).expect("own request");
        pm_tools::curl::parse_curl(&cmd).expect("own command");
    }
    let _ = pm_tools::curl::shell_words(&text);
});
