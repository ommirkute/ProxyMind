#![no_main]
//! The SOCKS5 handshake parser: greeting, username/password and request never panic on any input, and what they
//! consume stays within the input.
use libfuzzer_sys::fuzz_target;
use pm_http::socks5;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some((g, used))) = socks5::parse_greeting(data) {
        assert!(used <= data.len() && used == 2 + g.methods.len());
        let _ = socks5::choose_method(&g.methods, true);
    }
    if let Ok(Some((c, used))) = socks5::parse_auth(data) {
        assert!(used <= data.len() && used == 3 + c.username.len() + c.password.len());
        let _ = socks5::credentials_match(&c, "u", "p");
    }
    if let Ok(Some((r, used))) = socks5::parse_request(data) {
        assert!(used <= data.len() && used <= socks5::MAX_MESSAGE);
        let host = r.address.host();
        assert!(!host.is_empty() && !host.chars().any(|c| c.is_control() || c.is_whitespace()));
        let _ = socks5::reply(socks5::REP_SUCCEEDED, None);
    }
    for cut in 0..data.len().min(40) {
        let _ = socks5::parse_greeting(&data[..cut]);
        let _ = socks5::parse_auth(&data[..cut]);
        let _ = socks5::parse_request(&data[..cut]);
    }
});
