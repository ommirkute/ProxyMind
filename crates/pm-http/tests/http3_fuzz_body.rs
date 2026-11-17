//! The body of the `http3_text` fuzz target (`fuzz/fuzz_targets/http3_text.rs`) run over pseudo-random and mutated
//! inputs, so a plain `cargo test` catches what the fuzzer would on its first seconds.
use pm_http::h3text;

fn run(data: &[u8]) {
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
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn fuzz_body_holds_on_random_and_mutated_inputs() {
    let mut r = Rng(0x2545_f491_4f6c_dd1d);
    let seeds: Vec<&[u8]> = vec![
        b"GET /a?b=1 HTTP/3\r\nhost: x.test\r\naccept: */*\r\n\r\n",
        b"POST /a HTTP/3\r\nhost: x\r\ncontent-length: 3\r\n\r\nabc",
        b"GET /a\rb HTTP/3\r\nhost: x\r\n\r\n",
        b"HTTP/3 200\r\nalt-svc: h3=\":443\"; ma=60, h2=\"a:1\", clear\r\n\r\nbody",
        b"HTTP/1.1 200 OK\r\nAlt-Svc: h3-29=\":443\"\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/2 204\r\nalt-svc: h3=\"\\\"\"\r\n\r\n",
    ];
    for seed in &seeds {
        run(seed);
        for _ in 0..3000 {
            let mut d = seed.to_vec();
            for _ in 0..1 + r.next() % 4 {
                let at = (r.next() as usize) % d.len().max(1);
                match r.next() % 3 {
                    0 if !d.is_empty() => d[at] = r.next() as u8,
                    1 => d.insert(at.min(d.len()), r.next() as u8),
                    _ if !d.is_empty() => {
                        d.remove(at);
                    }
                    _ => {}
                }
            }
            run(&d);
        }
    }
    for _ in 0..5000 {
        let len = (r.next() % 96) as usize;
        let d: Vec<u8> = (0..len).map(|_| r.next() as u8).collect();
        run(&d);
    }
}
