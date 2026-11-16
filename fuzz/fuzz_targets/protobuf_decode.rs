#![no_main]
//! The Protobuf and gRPC decoder and its text format: never panic, stay within the limits, and what decodes
//! encodes to bytes that decode to the same thing.
use libfuzzer_sys::fuzz_target;
use pm_http::protobuf::{self, BodyKind};

fuzz_target!(|data: &[u8]| {
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
});
