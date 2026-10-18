//! Relays an upgraded WebSocket connection byte for byte while logging a
//! decoded copy of each message. Connections opened while WebSocket
//! interception is on are relayed message by message instead, so each
//! message can be held, edited or dropped.

use flate2::{Decompress, FlushDecompress, Status};
use pm_core::now_ms;
use std::sync::Arc;

use pm_http::ws::{self, Decoder, WsMessage};
use pm_store::NewWsMessage;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Recorder;
use crate::intercept::{Decision, InterceptQueue, Kind};

/// Payload bytes the decoder keeps per message (compressed data must be
/// whole to inflate it).
const DECODE_CAP: usize = 1 << 20;
/// Payload bytes stored per message.
const STORE_CAP: usize = 256 << 10;
/// Larger frames aren't split out; the rest of the connection is relayed raw.
const MAX_FRAME: u64 = 16 << 20;
/// Larger messages aren't held: they are forwarded as they arrive.
const MAX_HELD: usize = 1 << 20;

/// Where held WebSocket messages go, for a connection opened while
/// WebSocket interception was on.
#[derive(Clone)]
pub(crate) struct WsHold {
    pub queue: Arc<InterceptQueue>,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

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

fn stored(from_client: bool, opcode: u8, len: u64, payload: &[u8], truncated: bool) -> NewWsMessage {
    NewWsMessage {
        exchange_id: 0,
        ts_ms: now_ms(),
        from_client,
        opcode,
        len,
        payload: payload[..payload.len().min(STORE_CAP)].to_vec(),
        truncated: truncated || payload.len() > STORE_CAP,
        compressed: false,
    }
}

/// A data message being collected from its frames.
struct Pending {
    opcode: u8,
    /// The frames as received, forwarded unchanged if not edited.
    bytes: Vec<u8>,
    payload: Vec<u8>,
    len: u64,
    /// Too big to hold: its frames are forwarded as they arrive.
    passthrough: bool,
}

/// Relays one direction message by message, holding each data message in
/// the intercept queue. Control frames go straight through.
async fn pump_held<R, W>(
    mut from: R,
    mut to: W,
    first: Vec<u8>,
    from_client: bool,
    hold: WsHold,
    recorder: Recorder,
    key: u64,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let rng = SystemRandom::new();
    let kind = if from_client { Kind::WsToServer } else { Kind::WsToClient };
    let mut buf = first;
    let mut tmp = vec![0u8; 16 << 10];
    let mut msg: Option<Pending> = None;
    loop {
        loop {
            let head = match ws::parse_frame_head(&buf) {
                Ok(Some(h)) if h.total_len() <= MAX_FRAME => h,
                Ok(None) => break,
                // Not framing we can follow (or a huge frame): relay the rest raw.
                _ => {
                    if let Some(m) = msg.take() {
                        let _ = to.write_all(&m.bytes).await;
                    }
                    if to.write_all(&buf).await.is_ok() {
                        let _ = tokio::io::copy(&mut from, &mut to).await;
                    }
                    let _ = to.shutdown().await;
                    return;
                }
            };
            let total = head.total_len() as usize;
            if buf.len() < total {
                break;
            }
            let frame: Vec<u8> = buf.drain(..total).collect();
            let mut payload = frame[head.header_len..].to_vec();
            if let Some(mask) = head.mask {
                ws::apply_mask(&mut payload, mask);
            }
            if head.is_control() {
                if to.write_all(&frame).await.is_err() {
                    return;
                }
                recorder.record_ws(key, stored(from_client, head.opcode, payload.len() as u64, &payload, false));
                continue;
            }
            let m = msg.get_or_insert_with(|| Pending {
                opcode: head.opcode,
                bytes: Vec::new(),
                payload: Vec::new(),
                len: 0,
                passthrough: false,
            });
            m.len += head.payload_len;
            if m.passthrough {
                if to.write_all(&frame).await.is_err() {
                    return;
                }
                let room = STORE_CAP.saturating_sub(m.payload.len());
                m.payload.extend_from_slice(&payload[..payload.len().min(room)]);
            } else {
                m.bytes.extend_from_slice(&frame);
                m.payload.extend_from_slice(&payload);
                if m.payload.len() > MAX_HELD {
                    m.passthrough = true;
                    if to.write_all(&std::mem::take(&mut m.bytes)).await.is_err() {
                        return;
                    }
                    m.payload.truncate(STORE_CAP);
                }
            }
            if !head.fin {
                continue;
            }
            let Some(m) = msg.take() else { continue };
            if m.passthrough {
                recorder.record_ws(key, stored(from_client, m.opcode, m.len, &m.payload, true));
                continue;
            }
            let decision =
                hold.queue.hold(kind, &hold.scheme, &hold.host, hold.port, "WS", &hold.path, &m.payload).await;
            match decision {
                Decision::Forward(None) => {
                    if to.write_all(&m.bytes).await.is_err() {
                        return;
                    }
                    recorder.record_ws(key, stored(from_client, m.opcode, m.len, &m.payload, false));
                }
                Decision::Forward(Some(edited)) => {
                    // Browsers must mask what they send; servers must not.
                    let mask = if from_client {
                        let mut k = [0u8; 4];
                        if rng.fill(&mut k).is_err() {
                            return;
                        }
                        Some(k)
                    } else {
                        None
                    };
                    if to.write_all(&ws::encode_frame(m.opcode, &edited, mask)).await.is_err() {
                        return;
                    }
                    recorder.record_ws(key, stored(from_client, m.opcode, edited.len() as u64, &edited, false));
                }
                Decision::Drop => {} // never reaches the other side, so it isn't logged
            }
        }
        let _ = to.flush().await;
        let n = match from.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
    }
    if let Some(m) = msg.take() {
        let _ = to.write_all(&m.bytes).await;
    }
    let _ = to.shutdown().await;
}

/// Runs until both directions close. `client_buf`/`server_buf` are bytes
/// already read past the handshake.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay<C, S>(
    client: C,
    client_buf: Vec<u8>,
    server: S,
    server_buf: Vec<u8>,
    deflate: Deflate,
    hold: Option<WsHold>,
    recorder: Recorder,
    key: u64,
) where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (cr, cw) = tokio::io::split(client);
    let (sr, sw) = tokio::io::split(server);
    match hold {
        // Compressed messages can't be edited or dropped without breaking
        // the shared compression context, so those connections aren't held.
        Some(h) if !deflate.enabled => {
            let up = pump_held(cr, sw, client_buf, true, h.clone(), recorder.clone(), key);
            let down = pump_held(sr, cw, server_buf, false, h, recorder.clone(), key);
            tokio::join!(up, down);
        }
        _ => {
            let up = pump(cr, sw, client_buf, Side::new(true, deflate), recorder.clone(), key);
            let down = pump(sr, cw, server_buf, Side::new(false, deflate), recorder.clone(), key);
            tokio::join!(up, down);
        }
    }
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
