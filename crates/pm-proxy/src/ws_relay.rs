//! Relays an upgraded WebSocket connection byte for byte while logging a
//! decoded copy of each message.

use flate2::{Decompress, FlushDecompress, Status};
use pm_core::now_ms;
use pm_http::ws::{Decoder, WsMessage};
use pm_store::NewWsMessage;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Recorder;

/// Payload bytes the decoder keeps per message (compressed data must be
/// whole to inflate it).
const DECODE_CAP: usize = 1 << 20;
/// Payload bytes stored per message.
const STORE_CAP: usize = 256 << 10;

/// What the handshake agreed on for permessage-deflate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Deflate {
    pub enabled: bool,
    pub client_no_context_takeover: bool,
    pub server_no_context_takeover: bool,
}

impl Deflate {
    /// Reads the server's `Sec-WebSocket-Extensions` answer.
    pub fn from_response(headers: &[pm_http::Header]) -> Self {
        let mut d = Self::default();
        for h in headers.iter().filter(|h| h.name.eq_ignore_ascii_case("sec-websocket-extensions")) {
            let v = String::from_utf8_lossy(&h.value).to_ascii_lowercase();
            for ext in v.split(',') {
                let mut params = ext.split(';').map(str::trim);
                if params.next() == Some("permessage-deflate") {
                    d.enabled = true;
                    for p in params {
                        d.client_no_context_takeover |= p == "client_no_context_takeover";
                        d.server_no_context_takeover |= p == "server_no_context_takeover";
                    }
                }
            }
        }
        d
    }
}

/// One direction's logger: decoder plus optional inflater.
struct Side {
    from_client: bool,
    decoder: Option<Decoder>,
    inflate: Option<Decompress>,
    reset_each_message: bool,
    msgs: Vec<WsMessage>,
}

impl Side {
    fn new(from_client: bool, deflate: Deflate) -> Self {
        let no_takeover =
            if from_client { deflate.client_no_context_takeover } else { deflate.server_no_context_takeover };
        Self {
            from_client,
            decoder: Some(Decoder::new(DECODE_CAP)),
            inflate: deflate.enabled.then(|| Decompress::new(false)),
            reset_each_message: no_takeover,
            msgs: Vec::new(),
        }
    }

    fn observe(&mut self, bytes: &[u8], recorder: &Recorder, key: u64) {
        let Some(d) = self.decoder.as_mut() else { return };
        if let Err(e) = d.feed(bytes, &mut self.msgs) {
            tracing::debug!("stopped logging WebSocket messages: {e}");
            self.decoder = None;
        }
        for m in std::mem::take(&mut self.msgs) {
            let msg = self.record_of(m);
            recorder.record_ws(key, msg);
        }
    }

    fn record_of(&mut self, m: WsMessage) -> NewWsMessage {
        let mut out = NewWsMessage {
            exchange_id: 0,
            ts_ms: now_ms(),
            from_client: self.from_client,
            opcode: m.opcode,
            len: m.len,
            payload: m.payload,
            truncated: m.truncated,
            compressed: m.compressed,
        };
        if m.compressed {
            match self.inflate_message(&out.payload, m.truncated) {
                Some((data, total)) => {
                    out.truncated = total > data.len() as u64;
                    out.len = total;
                    out.payload = data;
                    out.compressed = false;
                }
                None => out.compressed = true,
            }
        }
        if out.payload.len() > STORE_CAP {
            out.payload.truncate(STORE_CAP);
            out.truncated = true;
        }
        out
    }

    /// Inflates one message, keeping the context for the next one unless
    /// the handshake said not to. Returns (first bytes, full length).
    fn inflate_message(&mut self, data: &[u8], truncated: bool) -> Option<(Vec<u8>, u64)> {
        let z = self.inflate.as_mut()?;
        if truncated {
            // Part of the stream is missing: later messages can't be inflated either.
            if !self.reset_each_message {
                self.inflate = None;
            }
            return None;
        }
        let mut input = data.to_vec();
        input.extend_from_slice(&[0, 0, 0xFF, 0xFF]);
        let (mut kept, mut total, mut pos) = (Vec::new(), 0u64, 0usize);
        let mut buf = vec![0u8; 64 << 10];
        let ok = loop {
            let (in0, out0) = (z.total_in(), z.total_out());
            match z.decompress(&input[pos..], &mut buf, FlushDecompress::Sync) {
                Ok(status) => {
                    let used = (z.total_in() - in0) as usize;
                    let n = (z.total_out() - out0) as usize;
                    pos += used;
                    total += n as u64;
                    let room = STORE_CAP.saturating_sub(kept.len()).min(n);
                    kept.extend_from_slice(&buf[..room]);
                    if status == Status::StreamEnd || (pos >= input.len() && n < buf.len()) {
                        break true;
                    }
                    if used == 0 && n == 0 {
                        break false; // no progress: corrupt data
                    }
                }
                Err(_) => break false,
            }
        };
        if !ok {
            self.inflate = None;
            return None;
        }
        if self.reset_each_message {
            z.reset(false);
        }
        Some((kept, total))
    }
}

async fn pump<R, W>(mut from: R, mut to: W, first: Vec<u8>, mut side: Side, recorder: Recorder, key: u64)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if !first.is_empty() {
        if to.write_all(&first).await.is_err() {
            return;
        }
        side.observe(&first, &recorder, key);
    }
    let mut buf = vec![0u8; 16 << 10];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        // Forward first, then log: logging never delays or alters traffic.
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
        let _ = to.flush().await;
        side.observe(&buf[..n], &recorder, key);
    }
    let _ = to.shutdown().await;
}

/// Runs until both directions close. `client_buf`/`server_buf` are bytes
/// already read past the handshake.
pub(crate) async fn relay<C, S>(
    client: C,
    client_buf: Vec<u8>,
    server: S,
    server_buf: Vec<u8>,
    deflate: Deflate,
    recorder: Recorder,
    key: u64,
) where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (cr, cw) = tokio::io::split(client);
    let (sr, sw) = tokio::io::split(server);
    let up = pump(cr, sw, client_buf, Side::new(true, deflate), recorder.clone(), key);
    let down = pump(sr, cw, server_buf, Side::new(false, deflate), recorder.clone(), key);
    tokio::join!(up, down);
    recorder.ws_done(key);
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    fn deflate_msg(z: &mut Compress, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; data.len() + 64];
        let before = z.total_out();
        z.compress(data, &mut out, FlushCompress::Sync).unwrap();
        out.truncate((z.total_out() - before) as usize);
        assert!(out.ends_with(&[0, 0, 0xFF, 0xFF]));
        out.truncate(out.len() - 4);
        out
    }

    #[test]
    fn inflates_with_shared_context_and_parses_the_handshake() {
        let h = |v: &str| pm_http::Header { name: "Sec-WebSocket-Extensions".into(), value: v.as_bytes().to_vec() };
        let d = Deflate::from_response(&[h("permessage-deflate; client_no_context_takeover")]);
        assert!(d.enabled && d.client_no_context_takeover && !d.server_no_context_takeover);
        assert!(!Deflate::from_response(&[h("x-webkit-deflate-frame")]).enabled);

        let mut z = Compress::new(Compression::default(), false);
        let mut side = Side::new(false, d);
        for text in ["hello hello hello", "hello again, hello"] {
            let payload = deflate_msg(&mut z, text.as_bytes());
            let m = WsMessage { opcode: 1, compressed: true, len: payload.len() as u64, payload, truncated: false };
            let r = side.record_of(m);
            assert_eq!((r.payload.as_slice(), r.compressed), (text.as_bytes(), false));
        }
        // A truncated message breaks the shared context: later ones stay compressed.
        let m = WsMessage { opcode: 1, compressed: true, len: 99, payload: vec![1, 2], truncated: true };
        assert!(side.record_of(m).compressed);
        let payload = deflate_msg(&mut z, b"after");
        let m = WsMessage { opcode: 1, compressed: true, len: 5, payload, truncated: false };
        assert!(side.record_of(m).compressed);
    }
}
