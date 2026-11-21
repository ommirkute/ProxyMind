//! The body of the `protobuf_decode` fuzz target (`fuzz/fuzz_targets/protobuf_decode.rs`) run over pseudo-random
//! and mutated inputs, so a plain `cargo test` catches what the fuzzer would on its first seconds.
use pm_http::protobuf::{self, BodyKind};

fn run(data: &[u8]) {
    let part = protobuf::decode_partial(data);
    assert!(part.consumed <= data.len());
    if let Ok(fields) = protobuf::decode(data) {
        // Text and bytes agree: the printed text reads back to fields that encode like the originals.
        let bytes = protobuf::encode(&fields);
        let text = protobuf::to_text(&fields, true);
        let back = protobuf::parse_text(&text).expect("printed text must parse");
        assert_eq!(protobuf::encode(&back), bytes);
        if let Ok(again) = protobuf::decode(&bytes) {
            assert_eq!(protobuf::encode(&again), bytes);
        }
    }
    let frames = protobuf::parse_frames(data);
    for f in &frames.frames {
        let _ = protobuf::decode_partial(&f.payload);
    }
    let no_gzip = |_: &[u8]| None;
    for kind in [BodyKind::Protobuf, BodyKind::Grpc, BodyKind::GrpcWeb, BodyKind::GrpcWebText] {
        let _ = protobuf::render_body(kind, data, &no_gzip, true);
        if let Ok(text) = std::str::from_utf8(data) {
            let _ = protobuf::encode_text(kind, text);
        }
    }
    let _ = protobuf::base64_decode(data);
    let _ = protobuf::parse_trailers(data);
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
    let seeds: Vec<Vec<u8>> = vec![
        vec![0x0a, 3, b'a', b'b', b'c', 0x12, 4, 0x08, 0x96, 0x01, 0x10, 0x02, 0x0b, 0x10, 0x05, 0x0c],
        protobuf::frame_message(0, &[0x08, 0x01, 0x15, 0, 0, 0xc0, 0x3f]),
        b"AAAAAAMIlgE=".to_vec(),
        b"@message\n1: 5\n2 {\n  3: \"x\"\n}\n@trailers\ngrpc-status: 0\n".to_vec(),
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
