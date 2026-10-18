//! WebSocket frame decoding (RFC 6455) for logging. No I/O: feed it the
//! bytes seen on one direction of a connection and it returns whole
//! messages. The proxy forwards the original bytes itself; this decoder
//! only watches a copy.
//!
//! Large payloads are streamed: only the first `cap` bytes of a message
//! are kept, so a huge frame never has to sit in memory.

/// Opcodes.
pub const CONTINUATION: u8 = 0x0;
pub const TEXT: u8 = 0x1;
pub const BINARY: u8 = 0x2;
pub const CLOSE: u8 = 0x8;
pub const PING: u8 = 0x9;
pub const PONG: u8 = 0xA;

pub fn opcode_name(op: u8) -> &'static str {
    match op {
        TEXT => "text",
        BINARY => "binary",
        CLOSE => "close",
        PING => "ping",
        PONG => "pong",
        _ => "other",
    }
}

/// One complete message (fragments joined) or control frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsMessage {
    pub opcode: u8,
    /// RSV1 was set on the first frame: with permessage-deflate, the
    /// payload is compressed.
    pub compressed: bool,
    /// Unmasked payload, at most `cap` bytes.
    pub payload: Vec<u8>,
    /// Full payload length on the wire.
    pub len: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WsError {
    #[error("reserved opcode {0:#x}")]
    ReservedOpcode(u8),
    #[error("control frame is fragmented or longer than 125 bytes")]
    BadControlFrame,
    #[error("continuation frame without a message to continue")]
    UnexpectedContinuation,
    #[error("new data frame while a fragmented message is open")]
    UnfinishedMessage,
    #[error("payload length has the top bit set")]
    BadLength,
}

#[derive(Debug)]
struct Frame {
    fin: bool,
    opcode: u8,
    mask: Option<[u8; 4]>,
    remaining: u64,
    offset: u64,
}

#[derive(Debug)]
struct Partial {
    opcode: u8,
    compressed: bool,
    payload: Vec<u8>,
    len: u64,
}

/// Streaming decoder for one direction of a WebSocket connection.
#[derive(Debug)]
pub struct Decoder {
    cap: usize,
    head: Vec<u8>,
    frame: Option<Frame>,
    /// The data message being assembled (text/binary and its continuations).
    data: Option<Partial>,
    /// The control frame being read (they may arrive between fragments).
    control: Option<Partial>,
}

impl Decoder {
    /// `cap`: how many payload bytes to keep per message.
    pub fn new(cap: usize) -> Self {
        Self { cap, head: Vec::with_capacity(14), frame: None, data: None, control: None }
    }

    /// Consumes bytes and appends any finished messages to `out`. After an
    /// error the stream can't be followed; stop feeding this decoder.
    pub fn feed(&mut self, mut input: &[u8], out: &mut Vec<WsMessage>) -> Result<(), WsError> {
        while !input.is_empty() {
            if self.frame.is_none() {
                let take = input.len().min(self.head_needed().saturating_sub(self.head.len()).max(1));
                self.head.extend_from_slice(&input[..take]);
                input = &input[take..];
                if self.head.len() < self.head_needed() {
                    continue;
                }
                self.start_frame()?;
                if self.frame.as_ref().is_some_and(|f| f.remaining == 0) {
                    self.end_frame(out);
                    continue;
                }
            }
            // Payload bytes of the current frame.
            let Some(f) = self.frame.as_mut() else { continue };
            let n = usize::try_from(f.remaining).unwrap_or(usize::MAX).min(input.len());
            let chunk = &input[..n];
            input = &input[n..];
            let cap = self.cap;
            let target = if f.opcode >= 8 { self.control.as_mut() } else { self.data.as_mut() };
            if let Some(p) = target {
                let room = cap.saturating_sub(p.payload.len()).min(chunk.len());
                let start = p.payload.len();
                p.payload.extend_from_slice(&chunk[..room]);
                if let Some(mask) = f.mask {
                    for (i, b) in p.payload[start..].iter_mut().enumerate() {
                        *b ^= mask[((f.offset + i as u64) % 4) as usize];
                    }
                }
                p.len += n as u64;
            }
            f.offset += n as u64;
            f.remaining -= n as u64;
            if f.remaining == 0 {
                self.end_frame(out);
            }
        }
        Ok(())
    }

    /// Header length implied by the bytes seen so far.
    fn head_needed(&self) -> usize {
        if self.head.len() < 2 {
            return 2;
        }
        let masked = self.head[1] & 0x80 != 0;
        let ext = match self.head[1] & 0x7F {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        2 + ext + if masked { 4 } else { 0 }
    }

    fn start_frame(&mut self) -> Result<(), WsError> {
        let h = std::mem::take(&mut self.head);
        let fin = h[0] & 0x80 != 0;
        let rsv1 = h[0] & 0x40 != 0;
        let opcode = h[0] & 0x0F;
        let masked = h[1] & 0x80 != 0;
        let (len, mut i) = match h[1] & 0x7F {
            126 => (u64::from(u16::from_be_bytes([h[2], h[3]])), 4),
            127 => {
                let v = u64::from_be_bytes(h[2..10].try_into().unwrap_or([0; 8]));
                if v >> 63 != 0 {
                    return Err(WsError::BadLength);
                }
                (v, 10)
            }
            n => (u64::from(n), 2),
        };
        let mask = masked.then(|| {
            let m = [h[i], h[i + 1], h[i + 2], h[i + 3]];
            i += 4;
            m
        });
        debug_assert_eq!(i, h.len());
        match opcode {
            CONTINUATION => {
                if self.data.is_none() {
                    return Err(WsError::UnexpectedContinuation);
                }
            }
            TEXT | BINARY => {
                if self.data.is_some() {
                    return Err(WsError::UnfinishedMessage);
                }
                self.data = Some(Partial { opcode, compressed: rsv1, payload: Vec::new(), len: 0 });
            }
            CLOSE | PING | PONG => {
                if !fin || len > 125 {
                    return Err(WsError::BadControlFrame);
                }
                self.control = Some(Partial { opcode, compressed: false, payload: Vec::new(), len: 0 });
            }
            op => return Err(WsError::ReservedOpcode(op)),
        }
        self.frame = Some(Frame { fin, opcode, mask, remaining: len, offset: 0 });
        Ok(())
    }

    fn end_frame(&mut self, out: &mut Vec<WsMessage>) {
        let Some(f) = self.frame.take() else { return };
        let done = if f.opcode >= 8 {
            self.control.take()
        } else if f.fin {
            self.data.take()
        } else {
            None
        };
        if let Some(p) = done {
            out.push(WsMessage {
                opcode: p.opcode,
                compressed: p.compressed,
                truncated: p.len > p.payload.len() as u64,
                payload: p.payload,
                len: p.len,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(fin: bool, op: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![(if fin { 0x80 } else { 0 }) | op];
        let m = if mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => v.push(m | n as u8),
            n if n <= 0xFFFF => {
                v.push(m | 126);
                v.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                v.push(m | 127);
                v.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        match mask {
            Some(k) => {
                v.extend_from_slice(&k);
                v.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
            }
            None => v.extend_from_slice(payload),
        }
        v
    }

    fn decode_all(cap: usize, bytes: &[u8], step: usize) -> Vec<WsMessage> {
        let mut d = Decoder::new(cap);
        let mut out = vec![];
        for c in bytes.chunks(step) {
            d.feed(c, &mut out).unwrap();
        }
        out
    }

    #[test]
    fn masked_text_in_any_chunking() {
        let bytes = frame(true, TEXT, Some([1, 2, 3, 4]), b"hello websocket");
        for step in [1, 2, 3, 7, 100] {
            let m = decode_all(1024, &bytes, step);
            assert_eq!(m.len(), 1, "step {step}");
            assert_eq!(m[0].payload, b"hello websocket");
            assert_eq!((m[0].opcode, m[0].len, m[0].truncated), (TEXT, 15, false));
        }
    }

    #[test]
    fn fragments_join_and_control_frames_interleave() {
        let mut bytes = frame(false, TEXT, Some([9, 9, 9, 9]), b"hel");
        bytes.extend(frame(true, PING, Some([5, 6, 7, 8]), b"p"));
        bytes.extend(frame(true, CONTINUATION, Some([1, 1, 1, 1]), b"lo"));
        bytes.extend(frame(true, CLOSE, None, &[0x03, 0xE8]));
        let m = decode_all(1024, &bytes, 1);
        assert_eq!(m.iter().map(|m| m.opcode).collect::<Vec<_>>(), [PING, TEXT, CLOSE]);
        assert_eq!(m[1].payload, b"hello");
        assert_eq!(m[0].payload, b"p");
    }

    #[test]
    fn big_payloads_are_capped_and_lengths_kept() {
        let big = vec![b'x'; 70_000];
        let bytes = frame(true, BINARY, None, &big);
        let m = decode_all(1000, &bytes, 4096);
        assert_eq!((m[0].len, m[0].payload.len(), m[0].truncated), (70_000, 1000, true));
        let medium = vec![b'y'; 300];
        let m = decode_all(1000, &frame(true, TEXT, Some([1, 2, 3, 4]), &medium), 33);
        assert_eq!(m[0].payload, medium);
    }

    #[test]
    fn empty_frames_and_rsv1() {
        let mut bytes = frame(true, TEXT, None, b"");
        let mut compressed = frame(true, TEXT, None, b"\x02\x00");
        compressed[0] |= 0x40;
        bytes.extend(compressed);
        let m = decode_all(64, &bytes, 1);
        assert_eq!(m.len(), 2);
        assert!(m[0].payload.is_empty() && !m[0].compressed);
        assert!(m[1].compressed);
    }

    #[test]
    fn protocol_errors() {
        let mut d = Decoder::new(10);
        assert_eq!(d.feed(&frame(true, 0x3, None, b""), &mut vec![]), Err(WsError::ReservedOpcode(3)));
        let mut d = Decoder::new(10);
        assert_eq!(d.feed(&frame(true, CONTINUATION, None, b"x"), &mut vec![]), Err(WsError::UnexpectedContinuation));
        let mut d = Decoder::new(10);
        assert_eq!(d.feed(&frame(true, PING, None, &[0; 126]), &mut vec![]), Err(WsError::BadControlFrame));
        let mut d = Decoder::new(10);
        assert_eq!(d.feed(&[0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0], &mut vec![]), Err(WsError::BadLength));
    }
}
