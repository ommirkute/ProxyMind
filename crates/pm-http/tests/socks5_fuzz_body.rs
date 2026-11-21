//! The body of the `socks5_handshake` fuzz target (`fuzz/fuzz_targets/socks5_handshake.rs`) run over pseudo-random
//! and mutated inputs, so a plain `cargo test` catches what the fuzzer would on its first seconds.
use pm_http::socks5;

fn run(data: &[u8]) {
    if let Ok(Some((g, used))) = socks5::parse_greeting(data) {
        assert!(used <= data.len() && used == 2 + g.methods.len());
        let m = socks5::choose_method(&g.methods, true);
        assert!(m == socks5::METHOD_PASSWORD || m == socks5::METHOD_NONE_ACCEPTABLE);
    }
    if let Ok(Some((c, used))) = socks5::parse_auth(data) {
        assert!(used <= data.len() && used == 3 + c.username.len() + c.password.len());
        assert!(!c.username.is_empty() && c.username.len() <= 255 && c.password.len() <= 255);
        let _ = socks5::credentials_match(&c, "u", "p");
    }
    if let Ok(Some((r, used))) = socks5::parse_request(data) {
        assert!(used <= data.len() && used <= socks5::MAX_MESSAGE);
        let host = r.address.host();
        assert!(!host.is_empty() && !host.chars().any(|c| c.is_control() || c.is_whitespace()));
        let _ = socks5::reply(socks5::REP_SUCCEEDED, None);
    }
    // Feeding any prefix of the input never panics either (the caller reads piecemeal).
    for cut in 0..data.len().min(40) {
        let _ = socks5::parse_greeting(&data[..cut]);
        let _ = socks5::parse_auth(&data[..cut]);
        let _ = socks5::parse_request(&data[..cut]);
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
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let seeds: Vec<Vec<u8>> = vec![
        vec![5, 2, 0, 2],
        vec![1, 3, b'b', b'o', b'b', 2, b'p', b'w'],
        vec![5, 1, 0, 1, 127, 0, 0, 1, 0x1f, 0x90],
        [vec![5, 1, 0, 3, 11], b"example.com".to_vec(), vec![1, 187]].concat(),
        [vec![5, 1, 0, 4], vec![0; 15], vec![1, 0, 80]].concat(),
    ];
    for seed in &seeds {
        run(seed);
        for _ in 0..3000 {
            let mut d = seed.clone();
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
        let len = (r.next() % 64) as usize;
        let d: Vec<u8> = (0..len).map(|_| r.next() as u8).collect();
        run(&d);
    }
}
