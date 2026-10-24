#![no_main]
//! The WebSocket decoder, fed in two arbitrary pieces.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.first().map_or(0, |&b| b as usize % (data.len().max(1)));
    let mut d = pm_http::ws::Decoder::new(4096);
    let mut out = Vec::new();
    if d.feed(&data[..split], &mut out).is_ok() {
        let _ = d.feed(&data[split..], &mut out);
    }
    for m in out {
        assert!(m.payload.len() <= 4096);
    }
});
