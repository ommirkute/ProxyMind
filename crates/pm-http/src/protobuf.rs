//! Protobuf wire format and gRPC framing, without a schema. No I/O.
//!
//! Decoding is lenient about *meaning* and strict about *structure*: a length-delimited field becomes a nested
//! message, a string or bytes by a heuristic (below), and malformed input gives an error or a partial result, never
//! a panic. Hard limits bound the work on hostile input ([`MAX_DEPTH`], [`MAX_FIELDS`], [`MAX_INPUT`]).
//!
//! # Text format
//!
//! A message is shown as text people can edit, and the same text encodes back to bytes:
//!
//! ```text
//! 1: 150                 # varint, as unsigned decimal ("# zigzag 75" is a comment: comments are ignored)
//! 2: "text"              # string (escapes: \" \\ \n \r \t \u{1f600})
//! 3 {                    # nested message (length-delimited)
//!   1: 5
//! }
//! 4: 0x0a0b              # bytes, as hex (an empty value is "")
//! 5: 1.5f32              # fixed32 shown as a float (also: 9i32, -1i32, 0x7fc00001i32)
//! 6: 2.0f64              # fixed64 shown as a double (also: 9i64)
//! 7 group {              # deprecated group (start group ... end group)
//!   1: 1
//! }
//! ```
//!
//! gRPC bodies are a list of messages. Each starts with a line `@message`; gRPC-Web trailers are a `@trailers`
//! section of `name: value` lines. Text before the first `@` line is one message.
//!
//! # What round-trips
//!
//! `encode_text(decode(bytes))` gives the original bytes when the sender used the canonical encoding. It does not
//! when the original had an over-long varint, a compressed gRPC message (edited messages are sent uncompressed), a
//! trailers frame that is not `name: value\r\n` lines, base64 chunking that differs from one padded stream, or
//! bytes the decoder had to stop at. [`render_body`] reports this as `exact: false`; callers keep the original bytes
//! unless the person changed the text.
//!
//! # How a length-delimited field is shown
//!
//! In order: empty gives `""`; valid UTF-8 without control characters is a string; otherwise bytes that parse
//! completely as a message (at least one field, depth within the limit) are a nested message; otherwise valid UTF-8
//! with only tab, newline and carriage return as controls is a string; otherwise hex bytes. The first rule means a
//! message whose bytes are all printable text is shown as a string; the encoded bytes are the same either way.

use std::borrow::Cow;
use std::fmt::Write as _;

/// Deepest nesting of messages and groups.
pub const MAX_DEPTH: usize = 32;
/// Most fields decoded or parsed in one call (counts speculative nested attempts too).
pub const MAX_FIELDS: usize = 100_000;
/// Largest input accepted.
pub const MAX_INPUT: usize = 16 * 1024 * 1024;
/// Most gRPC frames read from one body.
pub const MAX_FRAMES: usize = 100_000;
/// Highest legal field number.
pub const MAX_FIELD_NUMBER: u64 = (1 << 29) - 1;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtoError {
    #[error("input ends in the middle of a value at byte {offset}")]
    Truncated { offset: usize },
    #[error("varint at byte {offset} is longer than 10 bytes or overflows 64 bits")]
    BadVarint { offset: usize },
    #[error("unknown wire type {wire_type} at byte {offset}")]
    BadWireType { offset: usize, wire_type: u8 },
    #[error("field number 0 or above 2^29-1 at byte {offset}")]
    BadFieldNumber { offset: usize },
    #[error("end-group tag at byte {offset} has no matching start-group")]
    UnmatchedEndGroup { offset: usize },
    #[error("group started before byte {offset} is never closed")]
    UnclosedGroup { offset: usize },
    #[error("messages nested deeper than {MAX_DEPTH}")]
    TooDeep,
    #[error("more than {MAX_FIELDS} fields")]
    TooManyFields,
    #[error("input larger than {MAX_INPUT} bytes")]
    TooLarge,
    #[error("gRPC frame at byte {offset} has unknown flag bits {flag:#04x}")]
    BadFrameFlag { offset: usize, flag: u8 },
    #[error("gRPC frame at byte {offset} is cut off")]
    TruncatedFrame { offset: usize },
    #[error("more than {MAX_FRAMES} gRPC frames")]
    TooManyFrames,
    #[error("body is not valid base64")]
    BadBase64,
    #[error("line {line}: {message}")]
    Text { line: usize, message: String },
}

/// One decoded value. `Message`, `Text` and `Bytes` are all length-delimited on the wire.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Varint(u64),
    Fixed64(u64),
    Fixed32(u32),
    Message(Vec<Field>),
    Text(String),
    Bytes(Vec<u8>),
    Group(Vec<Field>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub number: u32,
    pub value: Value,
}

/// A decode that may have stopped early: `fields` is what was read before `error`.
#[derive(Debug, Clone, PartialEq)]
pub struct Partial {
    pub fields: Vec<Field>,
    pub error: Option<ProtoError>,
    /// Bytes consumed before the error (all of the input when there is none).
    pub consumed: usize,
}

struct Ctx {
    fields_left: usize,
}

fn read_varint(buf: &[u8], pos: &mut usize, base: usize) -> Result<u64, ProtoError> {
    let start = *pos;
    let mut v = 0u64;
    for i in 0..10 {
        let Some(&b) = buf.get(start + i) else {
            return Err(ProtoError::Truncated { offset: base + start });
        };
        if i == 9 && b > 1 {
            return Err(ProtoError::BadVarint { offset: base + start });
        }
        v |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            *pos = start + i + 1;
            return Ok(v);
        }
    }
    Err(ProtoError::BadVarint { offset: base + start })
}

fn is_printable(c: char) -> bool {
    !c.is_control()
        && !matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

/// Valid UTF-8 where every character is printable (`allow_ws`: also tab, newline, carriage return).
fn as_text(bytes: &[u8], allow_ws: bool) -> Option<&str> {
    let s = std::str::from_utf8(bytes).ok()?;
    s.chars().all(|c| is_printable(c) || (allow_ws && matches!(c, '\t' | '\n' | '\r'))).then_some(s)
}

fn classify(slice: &[u8], depth: usize, ctx: &mut Ctx) -> Value {
    if slice.is_empty() {
        return Value::Bytes(Vec::new());
    }
    if let Some(s) = as_text(slice, false) {
        return Value::Text(s.to_string());
    }
    if depth < MAX_DEPTH {
        let mut kids = Vec::new();
        let mut p = 0;
        if parse_into(slice, &mut p, depth + 1, ctx, None, &mut kids, 0).is_ok() && !kids.is_empty() {
            return Value::Message(kids);
        }
    }
    if let Some(s) = as_text(slice, true) {
        return Value::Text(s.to_string());
    }
    Value::Bytes(slice.to_vec())
}

#[allow(clippy::too_many_arguments)]
fn parse_into(
    buf: &[u8],
    pos: &mut usize,
    depth: usize,
    ctx: &mut Ctx,
    group: Option<u32>,
    out: &mut Vec<Field>,
    base: usize,
) -> Result<(), ProtoError> {
    while *pos < buf.len() {
        let tag_at = *pos;
        let tag = read_varint(buf, pos, base)?;
        let wire = (tag & 7) as u8;
        let number = tag >> 3;
        if number == 0 || number > MAX_FIELD_NUMBER {
            return Err(ProtoError::BadFieldNumber { offset: base + tag_at });
        }
        let number = number as u32;
        if wire == 4 {
            if group == Some(number) {
                return Ok(());
            }
            return Err(ProtoError::UnmatchedEndGroup { offset: base + tag_at });
        }
        if ctx.fields_left == 0 {
            return Err(ProtoError::TooManyFields);
        }
        ctx.fields_left -= 1;
        let value = match wire {
            0 => Value::Varint(read_varint(buf, pos, base)?),
            1 => {
                let b = buf.get(*pos..*pos + 8).ok_or(ProtoError::Truncated { offset: base + *pos })?;
                *pos += 8;
                Value::Fixed64(u64::from_le_bytes(b.try_into().unwrap_or_default()))
            }
            2 => {
                let len = read_varint(buf, pos, base)?;
                let remaining = (buf.len() - *pos) as u64;
                if len > remaining {
                    return Err(ProtoError::Truncated { offset: base + *pos });
                }
                let end = *pos + len as usize;
                let value = classify(&buf[*pos..end], depth, ctx);
                *pos = end;
                value
            }
            3 => {
                if depth >= MAX_DEPTH {
                    return Err(ProtoError::TooDeep);
                }
                let mut kids = Vec::new();
                parse_into(buf, pos, depth + 1, ctx, Some(number), &mut kids, base)?;
                Value::Group(kids)
            }
            5 => {
                let b = buf.get(*pos..*pos + 4).ok_or(ProtoError::Truncated { offset: base + *pos })?;
                *pos += 4;
                Value::Fixed32(u32::from_le_bytes(b.try_into().unwrap_or_default()))
            }
            _ => return Err(ProtoError::BadWireType { offset: base + tag_at, wire_type: wire }),
        };
        out.push(Field { number, value });
    }
    if group.is_some() {
        return Err(ProtoError::UnclosedGroup { offset: base + *pos });
    }
    Ok(())
}

/// Decodes a whole message; any malformed byte is an error.
pub fn decode(bytes: &[u8]) -> Result<Vec<Field>, ProtoError> {
    let p = decode_partial(bytes);
    match p.error {
        Some(e) => Err(e),
        None => Ok(p.fields),
    }
}

/// Decodes as far as the input is well formed.
pub fn decode_partial(bytes: &[u8]) -> Partial {
    if bytes.len() > MAX_INPUT {
        return Partial { fields: Vec::new(), error: Some(ProtoError::TooLarge), consumed: 0 };
    }
    let mut ctx = Ctx { fields_left: MAX_FIELDS };
    let mut fields = Vec::new();
    let mut pos = 0;
    // A failed top-level field leaves `pos` at the failure; fields before it are kept.
    let error = parse_into(bytes, &mut pos, 0, &mut ctx, None, &mut fields, 0).err();
    Partial { fields, error, consumed: pos }
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn put_tag(out: &mut Vec<u8>, number: u32, wire: u8) {
    put_varint(out, (u64::from(number) << 3) | u64::from(wire));
}

fn encode_into(out: &mut Vec<u8>, fields: &[Field]) {
    for f in fields {
        match &f.value {
            Value::Varint(v) => {
                put_tag(out, f.number, 0);
                put_varint(out, *v);
            }
            Value::Fixed64(v) => {
                put_tag(out, f.number, 1);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Value::Fixed32(v) => {
                put_tag(out, f.number, 5);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Value::Message(k) => {
                let mut inner = Vec::new();
                encode_into(&mut inner, k);
                put_tag(out, f.number, 2);
                put_varint(out, inner.len() as u64);
                out.extend_from_slice(&inner);
            }
            Value::Text(s) => {
                put_tag(out, f.number, 2);
                put_varint(out, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Value::Bytes(b) => {
                put_tag(out, f.number, 2);
                put_varint(out, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Group(k) => {
                put_tag(out, f.number, 3);
                encode_into(out, k);
                put_tag(out, f.number, 4);
            }
        }
    }
}

/// Encodes fields in order, with the canonical (shortest) varints.
pub fn encode(fields: &[Field]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(&mut out, fields);
    out
}

// ---------------------------------------------------------------------------------------------------------------
// Text format: printing

fn zigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// Significant digits in the shortest decimal form of a float (`{:e}` has no padding zeros).
fn sig_digits(s: &str) -> usize {
    let mantissa = s.split(['e', 'E']).next().unwrap_or_default();
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    digits.trim_matches('0').len()
}

fn fixed32_text(v: u32, annotate: bool) -> String {
    let f = f32::from_bits(v);
    let shown = format!("{f:?}");
    let as_float = f.is_finite()
        && v != 0
        && (1e-4..=1e9).contains(&f.abs())
        && sig_digits(&format!("{f:e}")) <= 7
        && shown.parse::<f32>().is_ok_and(|p| p.to_bits() == v);
    let mut s = if as_float { format!("{shown}f32") } else { format!("{v}i32") };
    if annotate {
        let other = if as_float {
            format!("i32 {v}")
        } else if f.is_finite() {
            format!("f32 {shown}")
        } else {
            format!("f32 {f}")
        };
        let signed = if v >= 1 << 31 { format!("int32 {}, ", v as i32) } else { String::new() };
        let _ = write!(s, "  # {signed}{other}");
    }
    s
}

fn fixed64_text(v: u64, annotate: bool) -> String {
    let f = f64::from_bits(v);
    let shown = format!("{f:?}");
    let as_float = f.is_finite()
        && v != 0
        && (1e-9..=1e15).contains(&f.abs())
        && sig_digits(&format!("{f:e}")) <= 12
        && shown.parse::<f64>().is_ok_and(|p| p.to_bits() == v);
    let mut s = if as_float { format!("{shown}f64") } else { format!("{v}i64") };
    if annotate {
        let other = if as_float {
            format!("i64 {v}")
        } else if f.is_finite() {
            format!("f64 {shown}")
        } else {
            format!("f64 {f}")
        };
        let signed = if v >= 1 << 63 { format!("int64 {}, ", v as i64) } else { String::new() };
        let _ = write!(s, "  # {signed}{other}");
    }
    s
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if is_printable(c) => out.push(c),
            c => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
        }
    }
    out.push('"');
    out
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2 + 2);
    s.push_str("0x");
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn print_fields(out: &mut String, fields: &[Field], indent: usize, annotate: bool) {
    let pad = "  ".repeat(indent);
    for f in fields {
        let n = f.number;
        match &f.value {
            Value::Varint(v) => {
                let _ = write!(out, "{pad}{n}: {v}");
                if annotate && *v != 0 {
                    if *v >= 1 << 63 {
                        let _ = write!(out, "  # int64 {}, zigzag {}", *v as i64, zigzag(*v));
                    } else {
                        let _ = write!(out, "  # zigzag {}", zigzag(*v));
                    }
                }
                out.push('\n');
            }
            Value::Fixed32(v) => {
                let _ = writeln!(out, "{pad}{n}: {}", fixed32_text(*v, annotate));
            }
            Value::Fixed64(v) => {
                let _ = writeln!(out, "{pad}{n}: {}", fixed64_text(*v, annotate));
            }
            Value::Text(s) => {
                let _ = writeln!(out, "{pad}{n}: {}", quote(s));
            }
            Value::Bytes(b) if b.is_empty() => {
                let _ = writeln!(out, "{pad}{n}: \"\"");
            }
            Value::Bytes(b) => {
                let _ = writeln!(out, "{pad}{n}: {}", hex(b));
            }
            Value::Message(k) => {
                let _ = writeln!(out, "{pad}{n} {{");
                print_fields(out, k, indent + 1, annotate);
                let _ = writeln!(out, "{pad}}}");
            }
            Value::Group(k) => {
                let _ = writeln!(out, "{pad}{n} group {{");
                print_fields(out, k, indent + 1, annotate);
                let _ = writeln!(out, "{pad}}}");
            }
        }
    }
}

/// The editable text of fields. With `annotate`, comments show other readings of numbers (zigzag, signed, float).
pub fn to_text(fields: &[Field], annotate: bool) -> String {
    let mut out = String::new();
    print_fields(&mut out, fields, 0, annotate);
    out
}

// ---------------------------------------------------------------------------------------------------------------
// Text format: parsing

#[derive(Debug, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Colon,
    Open,
    Close,
}

fn text_err(line: usize, message: impl Into<String>) -> ProtoError {
    ProtoError::Text { line, message: message.into() }
}

fn tokenize(src: &str, line0: usize) -> Result<Vec<(usize, Tok)>, ProtoError> {
    let mut toks = Vec::new();
    let mut line = line0;
    let mut it = src.chars().peekable();
    while let Some(&c) = it.peek() {
        match c {
            '\n' => {
                line += 1;
                it.next();
            }
            c if c.is_whitespace() => {
                it.next();
            }
            '#' => while it.next_if(|&c| c != '\n').is_some() {},
            ':' => {
                it.next();
                toks.push((line, Tok::Colon));
            }
            '{' => {
                it.next();
                toks.push((line, Tok::Open));
            }
            '}' => {
                it.next();
                toks.push((line, Tok::Close));
            }
            '"' => {
                it.next();
                let mut s = String::new();
                loop {
                    match it.next() {
                        None | Some('\n') => return Err(text_err(line, "string is not closed")),
                        Some('"') => break,
                        Some('\\') => match it.next() {
                            Some('n') => s.push('\n'),
                            Some('r') => s.push('\r'),
                            Some('t') => s.push('\t'),
                            Some('"') => s.push('"'),
                            Some('\\') => s.push('\\'),
                            Some('u') => {
                                if it.next() != Some('{') {
                                    return Err(text_err(line, "expected \\u{...}"));
                                }
                                let mut h = String::new();
                                loop {
                                    match it.next() {
                                        Some('}') => break,
                                        Some(c) if c.is_ascii_hexdigit() && h.len() < 8 => h.push(c),
                                        _ => return Err(text_err(line, "bad \\u{...} escape")),
                                    }
                                }
                                let ch = u32::from_str_radix(&h, 16)
                                    .ok()
                                    .and_then(char::from_u32)
                                    .ok_or_else(|| text_err(line, "bad \\u{...} escape"))?;
                                s.push(ch);
                            }
                            _ => return Err(text_err(line, "unknown escape in string")),
                        },
                        Some(c) => s.push(c),
                    }
                }
                toks.push((line, Tok::Str(s)));
            }
            _ => {
                let mut w = String::new();
                while let Some(c) = it.next_if(|&c| !c.is_whitespace() && !matches!(c, '{' | '}' | ':' | '#' | '"')) {
                    w.push(c);
                }
                toks.push((line, Tok::Word(w)));
            }
        }
    }
    Ok(toks)
}

fn parse_u64(s: &str) -> Option<u64> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if let Some(neg) = s.strip_prefix('-') {
        neg.parse::<u64>().ok().filter(|&v| v <= 1 << 63).map(|v| (v as i64).wrapping_neg() as u64)
    } else {
        s.parse().ok()
    }
}

fn scalar(word: &str, line: usize) -> Result<Value, ProtoError> {
    let bad = || text_err(line, format!("cannot read the value {word:?}"));
    if let Some(n) = word.strip_suffix("i32") {
        let v = match n.strip_prefix('-') {
            Some(neg) => neg.parse::<u32>().ok().filter(|&v| v <= 1 << 31).map(|v| (v as i32).wrapping_neg() as u32),
            None => parse_u64(n).and_then(|v| u32::try_from(v).ok()),
        };
        return v.map(Value::Fixed32).ok_or_else(bad);
    }
    if let Some(n) = word.strip_suffix("i64") {
        return parse_u64(n).map(Value::Fixed64).ok_or_else(bad);
    }
    if let Some(h) = word.strip_prefix("0x").or_else(|| word.strip_prefix("0X")) {
        if h.len() % 2 != 0 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(text_err(line, "hex bytes need an even number of hex digits"));
        }
        let bytes = (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap_or(0)).collect();
        return Ok(Value::Bytes(bytes));
    }
    if let Some(n) = word.strip_suffix("f32") {
        return n.parse::<f32>().map(|f| Value::Fixed32(f.to_bits())).map_err(|_| bad());
    }
    if let Some(n) = word.strip_suffix("f64") {
        return n.parse::<f64>().map(|f| Value::Fixed64(f.to_bits())).map_err(|_| bad());
    }
    parse_u64(word).map(Value::Varint).ok_or_else(bad)
}

struct TextParser {
    toks: Vec<(usize, Tok)>,
    at: usize,
    fields_left: usize,
}

impl TextParser {
    fn line(&self) -> usize {
        self.toks.get(self.at).or(self.toks.last()).map_or(1, |t| t.0)
    }

    fn items(&mut self, depth: usize, nested: bool) -> Result<Vec<Field>, ProtoError> {
        let mut out = Vec::new();
        loop {
            let Some((line, tok)) = self.toks.get(self.at) else {
                return if nested { Err(text_err(self.line(), "missing }")) } else { Ok(out) };
            };
            let line = *line;
            match tok {
                Tok::Close if nested => {
                    self.at += 1;
                    return Ok(out);
                }
                Tok::Close => return Err(text_err(line, "unexpected }")),
                Tok::Word(w) => {
                    let number = w
                        .parse::<u64>()
                        .ok()
                        .filter(|n| (1..=MAX_FIELD_NUMBER).contains(n))
                        .ok_or_else(|| text_err(line, format!("expected a field number, found {w:?}")))?
                        as u32;
                    if self.fields_left == 0 {
                        return Err(text_err(line, "too many fields"));
                    }
                    self.fields_left -= 1;
                    self.at += 1;
                    out.push(Field { number, value: self.value(line, depth)? });
                }
                _ => return Err(text_err(line, "expected a field number")),
            }
        }
    }

    fn value(&mut self, line: usize, depth: usize) -> Result<Value, ProtoError> {
        let mut is_group = false;
        let mut colon = false;
        if matches!(self.toks.get(self.at), Some((_, Tok::Colon))) {
            colon = true;
            self.at += 1;
        }
        if !colon && matches!(self.toks.get(self.at), Some((_, Tok::Word(w))) if w == "group") {
            is_group = true;
            self.at += 1;
        }
        let Some((l, tok)) = self.toks.get(self.at) else {
            return Err(text_err(line, "field has no value"));
        };
        let l = *l;
        match tok {
            Tok::Open => {
                if depth >= MAX_DEPTH {
                    return Err(text_err(l, format!("nested deeper than {MAX_DEPTH}")));
                }
                self.at += 1;
                let kids = self.items(depth + 1, true)?;
                Ok(if is_group { Value::Group(kids) } else { Value::Message(kids) })
            }
            _ if is_group => Err(text_err(l, "expected { after group")),
            Tok::Str(s) => {
                let v = if s.is_empty() { Value::Bytes(Vec::new()) } else { Value::Text(s.clone()) };
                self.at += 1;
                Ok(v)
            }
            Tok::Word(w) if colon => {
                let v = scalar(w, l)?;
                self.at += 1;
                Ok(v)
            }
            _ => Err(text_err(l, "expected `:` and a value, or `{`")),
        }
    }
}

fn parse_text_at(src: &str, line0: usize) -> Result<Vec<Field>, ProtoError> {
    if src.len() > MAX_INPUT {
        return Err(ProtoError::TooLarge);
    }
    let toks = tokenize(src, line0)?;
    TextParser { toks, at: 0, fields_left: MAX_FIELDS }.items(0, false)
}

/// Reads the text format back into fields.
pub fn parse_text(src: &str) -> Result<Vec<Field>, ProtoError> {
    parse_text_at(src, 1)
}

// ---------------------------------------------------------------------------------------------------------------
// Base64 (for grpc-web-text)

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n =
            (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Decodes base64, ignoring whitespace. Several padded chunks joined together (what grpc-web-text clients send,
/// one per frame) decode as one stream; unpadded ends are accepted.
pub fn base64_decode(text: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut acc, mut n, mut padded) = (0u32, 0u32, 0u32);
    for &b in text {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'=' {
            padded += 1;
            n += 1;
        } else {
            if padded > 0 {
                return Err(ProtoError::BadBase64);
            }
            let v = B64.iter().position(|&x| x == b).ok_or(ProtoError::BadBase64)? as u32;
            acc = (acc << 6) | v;
            n += 1;
        }
        if n == 4 {
            match padded {
                0 => out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]),
                1 => out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]),
                2 => out.push((acc >> 4) as u8),
                _ => return Err(ProtoError::BadBase64),
            }
            (acc, n, padded) = (0, 0, 0);
        }
    }
    match (n, padded) {
        (0, _) => {}
        (2, 0) => out.push((acc >> 4) as u8),
        (3, 0) => out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]),
        _ => return Err(ProtoError::BadBase64),
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------------------------
// gRPC framing

/// How a body is framed, from its content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// `application/grpc[+proto]`: framed messages.
    Grpc,
    /// `application/grpc-web[+proto]`: framed messages, trailers in a frame with flag 0x80.
    GrpcWeb,
    /// `application/grpc-web-text[+proto]`: base64 of the gRPC-Web stream.
    GrpcWebText,
    /// A plain Protobuf message.
    Protobuf,
}

impl BodyKind {
    /// The kind a `Content-Type` value names, if it is gRPC or Protobuf.
    pub fn from_content_type(ct: &str) -> Option<Self> {
        let essence = ct.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
        match essence.as_str() {
            "application/grpc" | "application/grpc+proto" => Some(Self::Grpc),
            "application/grpc-web" | "application/grpc-web+proto" => Some(Self::GrpcWeb),
            "application/grpc-web-text" | "application/grpc-web-text+proto" => Some(Self::GrpcWebText),
            "application/x-protobuf" | "application/protobuf" | "application/vnd.google.protobuf" => {
                Some(Self::Protobuf)
            }
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Grpc => "grpc",
            Self::GrpcWeb => "grpc-web",
            Self::GrpcWebText => "grpc-web-text",
            Self::Protobuf => "protobuf",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "grpc" => Some(Self::Grpc),
            "grpc-web" => Some(Self::GrpcWeb),
            "grpc-web-text" => Some(Self::GrpcWebText),
            "protobuf" => Some(Self::Protobuf),
            _ => None,
        }
    }

    /// Bodies made of `[flag][length][payload]` frames.
    pub fn is_framed(self) -> bool {
        self != Self::Protobuf
    }
}

/// One gRPC frame: flag byte and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub flag: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn compressed(&self) -> bool {
        self.flag & 0x01 != 0
    }

    /// gRPC-Web trailers frame.
    pub fn is_trailers(&self) -> bool {
        self.flag & 0x80 != 0
    }
}

/// Frames read before `error` (if any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frames {
    pub frames: Vec<Frame>,
    pub error: Option<ProtoError>,
}

/// Splits a framed stream into frames, keeping what was read before a problem.
pub fn parse_frames(body: &[u8]) -> Frames {
    let mut frames = Vec::new();
    let mut at = 0;
    while at < body.len() {
        if frames.len() >= MAX_FRAMES {
            return Frames { frames, error: Some(ProtoError::TooManyFrames) };
        }
        let flag = body[at];
        if flag & 0x7e != 0 {
            return Frames { frames, error: Some(ProtoError::BadFrameFlag { offset: at, flag }) };
        }
        let Some(head) = body.get(at + 1..at + 5) else {
            return Frames { frames, error: Some(ProtoError::TruncatedFrame { offset: at }) };
        };
        let len = u32::from_be_bytes(head.try_into().unwrap_or_default()) as usize;
        let Some(payload) = body.get(at + 5..).and_then(|r| r.get(..len)) else {
            return Frames { frames, error: Some(ProtoError::TruncatedFrame { offset: at }) };
        };
        frames.push(Frame { flag, payload: payload.to_vec() });
        at += 5 + len;
    }
    Frames { frames, error: None }
}

/// One frame as bytes: flag, 4-byte big-endian length, payload.
pub fn frame_message(flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(flag);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// `name: value` lines of a trailers frame (CRLF or LF separated).
pub fn parse_trailers(payload: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(payload)
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Whole bodies

/// A body as editable text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub text: String,
    /// Encoding `text` again gives exactly the original bytes.
    pub exact: bool,
    /// Messages shown (trailers frames not counted).
    pub messages: usize,
    pub grpc_status: Option<String>,
    pub grpc_message: Option<String>,
    pub notes: Vec<String>,
}

/// Turns a body into text. `decompress` undoes the compression of a compressed gRPC message (`None` when it
/// cannot); pm-http does no decompression itself. Returns an error only when nothing could be decoded.
pub fn render_body(
    kind: BodyKind,
    body: &[u8],
    decompress: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
    annotate: bool,
) -> Result<Rendered, ProtoError> {
    if body.len() > MAX_INPUT {
        return Err(ProtoError::TooLarge);
    }
    let mut r = Rendered {
        text: String::new(),
        exact: false,
        messages: 0,
        grpc_status: None,
        grpc_message: None,
        notes: vec![],
    };
    let mut unreadable = false;
    if kind == BodyKind::Protobuf {
        let p = decode_partial(body);
        if let Some(e) = p.error {
            if p.fields.is_empty() {
                return Err(e);
            }
            let _ = writeln!(r.text, "# decoding stopped at byte {}: {e}", p.consumed);
            r.notes.push(format!("decoding stopped at byte {}: {e}; the rest is not shown", p.consumed));
            unreadable = true;
        }
        r.text = to_text(&p.fields, annotate) + &r.text;
        r.messages = 1;
    } else {
        let stream: Cow<[u8]> =
            if kind == BodyKind::GrpcWebText { Cow::Owned(base64_decode(body)?) } else { Cow::Borrowed(body) };
        let fr = parse_frames(&stream);
        if fr.frames.is_empty()
            && let Some(e) = fr.error
        {
            return Err(e);
        }
        for f in &fr.frames {
            if f.is_trailers() {
                r.text.push_str("@trailers\n");
                for (k, v) in parse_trailers(&f.payload) {
                    let _ = writeln!(r.text, "{k}: {v}");
                    match k.to_ascii_lowercase().as_str() {
                        "grpc-status" => r.grpc_status = Some(v),
                        "grpc-message" => r.grpc_message = Some(v),
                        _ => {}
                    }
                }
                continue;
            }
            r.messages += 1;
            let n = r.messages;
            r.text.push_str("@message\n");
            let payload: Cow<[u8]> = if f.compressed() {
                match decompress(&f.payload) {
                    Some(d) => {
                        r.notes.push(format!(
                            "message {n} is compressed; shown decompressed, and sent uncompressed if you edit the text"
                        ));
                        Cow::Owned(d)
                    }
                    None => {
                        let _ = writeln!(r.text, "# message {n} is compressed and could not be decompressed");
                        r.notes.push(format!("message {n} is compressed and could not be decompressed; not shown"));
                        unreadable = true;
                        continue;
                    }
                }
            } else {
                Cow::Borrowed(&f.payload)
            };
            let p = decode_partial(&payload);
            r.text.push_str(&to_text(&p.fields, annotate));
            if let Some(e) = p.error {
                let _ = writeln!(r.text, "# decoding stopped at byte {}: {e}", p.consumed);
                r.notes
                    .push(format!("message {n}: decoding stopped at byte {}: {e}; the rest is not shown", p.consumed));
                unreadable = true;
            }
        }
        if let Some(e) = fr.error {
            let _ = writeln!(r.text, "# framing stopped: {e}");
            r.notes.push(format!("framing stopped: {e}; the rest is not shown"));
            unreadable = true;
        }
    }
    r.exact = encode_text(kind, &r.text).is_ok_and(|b| b == body);
    if !r.exact && !unreadable && !r.notes.iter().any(|n| n.contains("compressed")) {
        r.notes.push(
            "the original bytes use an encoding the text cannot express (for example a longer-than-needed varint); \
             they are kept unless you edit the text"
                .into(),
        );
    }
    Ok(r)
}

enum Section {
    Message,
    Trailers,
}

fn directive(line: &str) -> Option<Section> {
    let t = line.trim();
    let (word, rest) = t.split_once(char::is_whitespace).unwrap_or((t, ""));
    let rest = rest.trim();
    if !(rest.is_empty() || rest.starts_with('#')) {
        return None;
    }
    match word {
        "@message" => Some(Section::Message),
        "@trailers" => Some(Section::Trailers),
        _ => None,
    }
}

/// Turns text back into a body of `kind`. Framed kinds write every message uncompressed (flag 0).
pub fn encode_text(kind: BodyKind, text: &str) -> Result<Vec<u8>, ProtoError> {
    if text.len() > MAX_INPUT {
        return Err(ProtoError::TooLarge);
    }
    if kind == BodyKind::Protobuf {
        return Ok(encode(&parse_text(text)?));
    }
    // Split into sections at `@message` / `@trailers` lines; text before the first one is a message.
    let mut sections: Vec<(Section, usize, String)> = vec![(Section::Message, 1, String::new())];
    for (i, line) in text.lines().enumerate() {
        match directive(line) {
            Some(s) => sections.push((s, i + 2, String::new())),
            None => {
                if let Some(last) = sections.last_mut() {
                    last.2.push_str(line);
                    last.2.push('\n');
                }
            }
        }
    }
    let mut out = Vec::new();
    let mut count = 0;
    for (i, (sec, line0, body)) in sections.iter().enumerate() {
        if i == 0 && tokenize(body, *line0)?.is_empty() {
            continue;
        }
        count += 1;
        if count > MAX_FRAMES {
            return Err(ProtoError::TooManyFrames);
        }
        match sec {
            Section::Message => out.extend(frame_message(0, &encode(&parse_text_at(body, *line0)?))),
            Section::Trailers => {
                if kind == BodyKind::Grpc {
                    return Err(text_err(
                        *line0 - 1,
                        "plain gRPC sends trailers as HTTP trailers, not in the body; use gRPC-Web for @trailers",
                    ));
                }
                let mut payload = String::new();
                for l in body.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                    payload.push_str(l);
                    payload.push_str("\r\n");
                }
                out.extend(frame_message(0x80, payload.as_bytes()));
            }
        }
    }
    if out.len() > MAX_INPUT {
        return Err(ProtoError::TooLarge);
    }
    if kind == BodyKind::GrpcWebText {
        return Ok(base64_encode(&out).into_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_gzip(_: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn varint(v: u64) -> Vec<u8> {
        let mut o = Vec::new();
        put_varint(&mut o, v);
        o
    }

    fn text_of(b: &[u8]) -> String {
        to_text(&decode(b).unwrap(), false)
    }

    fn round_trip(b: &[u8]) {
        let t = text_of(b);
        assert_eq!(encode(&parse_text(&t).unwrap()), b, "text was:\n{t}");
        let t = to_text(&decode(b).unwrap(), true);
        assert_eq!(encode(&parse_text(&t).unwrap()), b, "annotated text was:\n{t}");
    }

    #[test]
    fn varint_edge_cases() {
        assert_eq!(decode(&[0x08, 0x96, 0x01]).unwrap(), vec![Field { number: 1, value: Value::Varint(150) }]);
        // Max u64 is a 10-byte varint ending in 0x01.
        let mut b = vec![0x08];
        b.extend(varint(u64::MAX));
        assert_eq!(b.len(), 11);
        assert_eq!(decode(&b).unwrap()[0].value, Value::Varint(u64::MAX));
        round_trip(&b);
        assert_eq!(text_of(&b), "1: 18446744073709551615\n");
        // 10th byte above 1 overflows; an 11-byte varint never ends.
        let mut over = vec![0x08];
        over.extend([0xff; 9]);
        over.push(0x02);
        assert!(matches!(decode(&over), Err(ProtoError::BadVarint { .. })));
        let mut long = vec![0x08];
        long.extend([0x80; 10]);
        long.push(0);
        assert!(decode(&long).is_err());
        // Truncated varint.
        assert!(matches!(decode(&[0x08, 0x80]), Err(ProtoError::Truncated { .. })));
        // A negative int32 is a 10-byte varint; the comment shows it signed.
        let mut neg = vec![0x08];
        neg.extend(varint(-1i64 as u64));
        let t = to_text(&decode(&neg).unwrap(), true);
        assert!(t.contains("# int64 -1, zigzag -9223372036854775808"), "{t}");
        round_trip(&neg);
    }

    #[test]
    fn zigzag_comment() {
        let t = to_text(&decode(&[0x08, 0x96, 0x01]).unwrap(), true);
        assert_eq!(t, "1: 150  # zigzag 75\n");
        assert_eq!(zigzag(1), -1);
        assert_eq!(zigzag(2), 1);
        assert_eq!(zigzag(u64::MAX), i64::MIN);
        // Comments are ignored when reading the text back.
        assert_eq!(encode(&parse_text(&t).unwrap()), [0x08, 0x96, 0x01]);
    }

    #[test]
    fn non_canonical_varint_is_not_exact() {
        // 1: 1 written as 0x81 0x00.
        let body = [0x08, 0x81, 0x00];
        let r = render_body(BodyKind::Protobuf, &body, &no_gzip, false).unwrap();
        assert_eq!(r.text, "1: 1\n");
        assert!(!r.exact);
        assert!(r.notes.iter().any(|n| n.contains("longer-than-needed varint")), "{:?}", r.notes);
        let ok = render_body(BodyKind::Protobuf, &[0x08, 0x01], &no_gzip, false).unwrap();
        assert!(ok.exact && ok.notes.is_empty());
    }

    #[test]
    fn strings_bytes_and_nested() {
        // 1: "testing", 2 { 1: 150 }, 3: bytes with a NUL, 4: ""
        let mut b = vec![0x0a, 7];
        b.extend(b"testing");
        b.extend([0x12, 3, 0x08, 0x96, 0x01]);
        b.extend([0x1a, 3, 0xff, 0x00, 0xfe]);
        b.extend([0x22, 0]);
        let t = text_of(&b);
        assert_eq!(t, "1: \"testing\"\n2 {\n  1: 150\n}\n3: 0xff00fe\n4: \"\"\n");
        round_trip(&b);
        // Unicode text and escapes.
        let mut u = vec![0x0a];
        let s = "h\u{e9}llo \"q\" \\ \u{1f600}";
        u.push(s.len() as u8);
        u.extend(s.as_bytes());
        assert_eq!(text_of(&u), format!("1: {}\n", quote(s)));
        round_trip(&u);
        // Text with tab/newline: nested parse fails, so it is a string with escapes.
        let w = b"\x0a\x0bhi\nthere\tx!";
        assert_eq!(text_of(w), "1: \"hi\\nthere\\tx!\"\n");
        round_trip(w);
        // Bidirectional controls are not shown raw: the field is bytes.
        let mut bidi = vec![0x0a, 6];
        bidi.extend("a\u{202e}b".as_bytes());
        bidi[1] = (bidi.len() - 2) as u8;
        assert!(text_of(&bidi).starts_with("1: 0x"));
        round_trip(&bidi);
    }

    #[test]
    fn printable_text_that_parses_as_a_message_is_a_string() {
        // "(5" is also field 5 = 53, but plain text wins.
        assert_eq!(text_of(&[0x0a, 2, b'(', b'5']), "1: \"(5\"\n");
    }

    #[test]
    fn fixed_width_values() {
        let mut b = vec![0x0d];
        b.extend(1.5f32.to_le_bytes());
        b.push(0x11);
        b.extend(2.0f64.to_le_bytes());
        b.push(0x1d);
        b.extend(9u32.to_le_bytes());
        b.push(0x21);
        b.extend(u64::MAX.to_le_bytes());
        b.push(0x2d);
        b.extend(f32::NAN.to_bits().to_le_bytes());
        assert_eq!(text_of(&b), "1: 1.5f32\n2: 2.0f64\n3: 9i32\n4: 18446744073709551615i64\n5: 2143289344i32\n");
        round_trip(&b);
        let t = to_text(&decode(&b).unwrap(), true);
        assert!(t.contains("1: 1.5f32  # i32 1069547520"), "{t}");
        assert!(t.contains("3: 9i32  # f32 1.3e-44"), "{t}");
        assert!(t.contains("4: 18446744073709551615i64  # int64 -1, f64 NaN"), "{t}");
        // Reading floats, negatives and hex.
        let f = parse_text("1: -2.5f32\n2: 0x7ff8000000000001i64\n3: -1i32\n4: 3.25f64\n").unwrap();
        assert_eq!(f[0].value, Value::Fixed32((-2.5f32).to_bits()));
        assert_eq!(f[1].value, Value::Fixed64(0x7ff8_0000_0000_0001));
        assert_eq!(f[2].value, Value::Fixed32(u32::MAX));
        assert_eq!(f[3].value, Value::Fixed64(3.25f64.to_bits()));
        // Truncated fixed fields.
        assert!(matches!(decode(&[0x0d, 1, 2, 3]), Err(ProtoError::Truncated { .. })));
        assert!(matches!(decode(&[0x11, 1, 2, 3, 4, 5, 6, 7]), Err(ProtoError::Truncated { .. })));
    }

    #[test]
    fn groups() {
        // 1 group { 2: 5 }, then 3: 7
        let b = [0x0b, 0x10, 0x05, 0x0c, 0x18, 0x07];
        assert_eq!(text_of(&b), "1 group {\n  2: 5\n}\n3: 7\n");
        round_trip(&b);
        // Mismatched or missing end tags.
        assert!(matches!(decode(&[0x0b, 0x14]), Err(ProtoError::UnmatchedEndGroup { .. })));
        assert!(matches!(decode(&[0x0c]), Err(ProtoError::UnmatchedEndGroup { .. })));
        assert!(matches!(decode(&[0x0b, 0x10, 0x05]), Err(ProtoError::UnclosedGroup { .. })));
        // Nested groups.
        let n = [0x0b, 0x13, 0x08, 0x01, 0x14, 0x0c];
        assert_eq!(text_of(&n), "1 group {\n  2 group {\n    1: 1\n  }\n}\n");
        round_trip(&n);
    }

    #[test]
    fn malformed_input_is_an_error_or_partial() {
        assert!(matches!(decode(&[0x00, 0x01]), Err(ProtoError::BadFieldNumber { .. })));
        assert!(matches!(decode(&[0x0e]), Err(ProtoError::BadWireType { wire_type: 6, .. })));
        assert!(matches!(decode(&[0x0f]), Err(ProtoError::BadWireType { wire_type: 7, .. })));
        assert!(matches!(decode(&[0x0a, 5, b'a']), Err(ProtoError::Truncated { .. })));
        // A length that does not fit in the input.
        let mut huge = vec![0x0a];
        huge.extend(varint(u64::MAX));
        assert!(decode(&huge).is_err());
        // Field number above 2^29-1.
        let mut big = varint((1u64 << 32) << 3);
        big.push(0);
        assert!(matches!(decode(&big), Err(ProtoError::BadFieldNumber { .. })));
        // Partial: the first field survives, the error says where.
        let p = decode_partial(&[0x08, 0x01, 0x10]);
        assert_eq!(p.fields.len(), 1);
        assert_eq!(p.consumed, 3);
        assert!(p.error.is_some());
        let r = render_body(BodyKind::Protobuf, &[0x08, 0x01, 0x10], &no_gzip, false).unwrap();
        assert!(r.text.starts_with("1: 1\n# decoding stopped at byte 3"), "{}", r.text);
        assert!(!r.exact);
        // Nothing decoded at all is an error.
        assert!(render_body(BodyKind::Protobuf, &[0xff], &no_gzip, false).is_err());
        // Every prefix of a valid message decodes or errors without panicking.
        let good = [0x0a, 3, 1, 2, 3, 0x12, 4, 0x08, 1, 0x10, 2, 0x1d, 1, 2, 3, 4];
        for n in 0..good.len() {
            let _ = decode_partial(&good[..n]);
        }
    }

    #[test]
    fn depth_limit() {
        // MAX_DEPTH nested messages decode; more become bytes inside the innermost shown message.
        fn nest(levels: usize) -> Vec<u8> {
            let mut inner = vec![0x08, 0x01];
            for _ in 0..levels {
                let mut o = vec![0x0a];
                o.extend(varint(inner.len() as u64));
                o.extend(inner);
                inner = o;
            }
            inner
        }
        let ok = nest(20);
        assert!(decode(&ok).is_ok());
        round_trip(&ok);
        let deep = nest(200);
        let fields = decode(&deep).unwrap();
        assert_eq!(encode(&fields), deep);
        // Depth of the result is bounded.
        fn depth(f: &[Field]) -> usize {
            f.iter()
                .map(|f| match &f.value {
                    Value::Message(k) | Value::Group(k) => 1 + depth(k),
                    _ => 1,
                })
                .max()
                .unwrap_or(0)
        }
        assert!(depth(&fields) <= MAX_DEPTH + 1, "{}", depth(&fields));
        // Groups past the limit are an error, not a stack overflow.
        let g = vec![0x0b; 200];
        assert!(matches!(decode(&g), Err(ProtoError::TooDeep)));
        // The text parser is bounded too.
        let t = "1 {\n".repeat(200);
        assert!(parse_text(&t).is_err());
    }

    #[test]
    fn many_fields_are_bounded() {
        let b: Vec<u8> = std::iter::repeat_n([0x08u8, 0x01], MAX_FIELDS + 1).flatten().collect();
        let p = decode_partial(&b);
        assert_eq!(p.error, Some(ProtoError::TooManyFields));
        assert_eq!(p.fields.len(), MAX_FIELDS);
    }

    #[test]
    fn text_format_errors_name_the_line() {
        let e = parse_text("1: 5\n2: nope\n").unwrap_err();
        assert!(matches!(e, ProtoError::Text { line: 2, .. }), "{e}");
        assert!(parse_text("1 {\n").is_err());
        assert!(parse_text("}\n").is_err());
        assert!(parse_text("0: 1\n").is_err());
        assert!(parse_text("1: \"abc\n").is_err());
        assert!(parse_text("1: 0xabc\n").is_err());
        assert!(parse_text("1: 99999999999999999999\n").is_err());
        assert!(parse_text("x: 1\n").is_err());
        assert!(parse_text("1:\n").is_err());
        assert!(parse_text("1 group 5\n").is_err());
        // Optional colon before a brace, comments, blank lines.
        let f = parse_text("# note\n\n1: { 2: 3 } # tail\n").unwrap();
        assert_eq!(encode(&f), [0x0a, 2, 0x10, 3]);
        // `#` inside a string is not a comment.
        assert_eq!(parse_text("1: \"a#b\"").unwrap()[0].value, Value::Text("a#b".into()));
    }

    #[test]
    fn editing_text_changes_bytes() {
        let b = [0x0a, 2, b'h', b'i', 0x10, 0x05];
        let t = text_of(&b).replace("\"hi\"", "\"hello\"").replace("2: 5", "2: 300");
        assert_eq!(encode(&parse_text(&t).unwrap()), [0x0a, 5, b'h', b'e', b'l', b'l', b'o', 0x10, 0xac, 0x02]);
    }

    /// Small deterministic generator (xorshift) for the round-trip property.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    fn random_fields(r: &mut Rng, depth: usize) -> Vec<Field> {
        (0..r.next() % 6)
            .map(|_| {
                let number = (r.next() % 40 + 1) as u32;
                let value = match r.next() % 8 {
                    0 => Value::Varint(r.next() >> (r.next() % 64)),
                    1 => Value::Fixed32(r.next() as u32),
                    2 => Value::Fixed64(r.next()),
                    3 => Value::Text(["", "a", "hello world", "caf\u{e9}", "x\ny"][(r.next() % 5) as usize].into()),
                    4 => Value::Bytes((0..r.next() % 9).map(|_| r.next() as u8).collect()),
                    5 if depth < 5 => Value::Message(random_fields(r, depth + 1)),
                    6 if depth < 5 => Value::Group(random_fields(r, depth + 1)),
                    _ => Value::Varint(r.next() % 300),
                };
                Field { number, value }
            })
            .collect()
    }

    #[test]
    fn round_trip_property() {
        let mut r = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..2000 {
            let bytes = encode(&random_fields(&mut r, 0));
            // Whatever shape the heuristics pick, the bytes survive text and back.
            round_trip(&bytes);
            let rendered = render_body(BodyKind::Protobuf, &bytes, &no_gzip, true);
            if let Ok(rendered) = rendered {
                assert!(rendered.exact, "{}", rendered.text);
            }
        }
        // Random garbage never panics; when it decodes fully it re-encodes to the same bytes or a canonical form.
        for _ in 0..5000 {
            let len = (r.next() % 40) as usize;
            let junk: Vec<u8> = (0..len).map(|_| r.next() as u8).collect();
            if let Ok(f) = decode(&junk) {
                let again = decode(&encode(&f)).unwrap();
                assert_eq!(encode(&again), encode(&f));
            }
            let _ = parse_text(&String::from_utf8_lossy(&junk));
            let _ = parse_frames(&junk);
            let _ = base64_decode(&junk);
        }
    }

    #[test]
    fn content_types() {
        use BodyKind::*;
        for (ct, k) in [
            ("application/grpc", Some(Grpc)),
            ("Application/GRPC+proto; charset=x", Some(Grpc)),
            ("application/grpc-web", Some(GrpcWeb)),
            ("application/grpc-web+proto", Some(GrpcWeb)),
            ("application/grpc-web-text", Some(GrpcWebText)),
            ("application/grpc-web-text+proto", Some(GrpcWebText)),
            ("application/x-protobuf", Some(Protobuf)),
            ("application/protobuf", Some(Protobuf)),
            ("application/vnd.google.protobuf; proto=a.B", Some(Protobuf)),
            ("application/json", None),
            ("application/grpc+json", None),
        ] {
            assert_eq!(BodyKind::from_content_type(ct), k, "{ct}");
        }
        for k in [Grpc, GrpcWeb, GrpcWebText, Protobuf] {
            assert_eq!(BodyKind::from_name(k.name()), Some(k));
        }
    }

    #[test]
    fn grpc_frames_with_several_messages() {
        let m1 = [0x0a, 2, b'h', b'i'];
        let m2 = [0x08, 0x2a];
        let mut body = frame_message(0, &m1);
        body.extend(frame_message(0, &m2));
        body.extend(frame_message(0, &[]));
        let fr = parse_frames(&body);
        assert_eq!(fr.frames.len(), 3);
        assert!(fr.error.is_none());
        let r = render_body(BodyKind::Grpc, &body, &no_gzip, false).unwrap();
        assert_eq!(r.text, "@message\n1: \"hi\"\n@message\n1: 42\n@message\n");
        assert_eq!(r.messages, 3);
        assert!(r.exact);
        // Editing the text re-frames.
        let edited = r.text.replace("42", "43");
        let out = encode_text(BodyKind::Grpc, &edited).unwrap();
        let mut want = frame_message(0, &m1);
        want.extend(frame_message(0, &[0x08, 0x2b]));
        want.extend(frame_message(0, &[]));
        assert_eq!(out, want);
        // Without directives the text is one message.
        assert_eq!(encode_text(BodyKind::Grpc, "1: 42").unwrap(), frame_message(0, &m2));
        assert_eq!(encode_text(BodyKind::Grpc, "").unwrap(), Vec::<u8>::new());
        // A cut-off frame keeps the messages before it.
        let cut = &body[..body.len() - 3];
        let fr = parse_frames(&body[..m1.len() + 5 + 3]);
        assert_eq!(fr.frames.len(), 1);
        assert!(matches!(fr.error, Some(ProtoError::TruncatedFrame { .. })));
        let r = render_body(BodyKind::Grpc, cut, &no_gzip, false).unwrap();
        assert!(r.text.contains("# framing stopped"), "{}", r.text);
        assert!(!r.exact);
        // Bad flag bits mean this is not gRPC framing.
        assert!(render_body(BodyKind::Grpc, b"\x07\0\0\0\0", &no_gzip, false).is_err());
        assert!(render_body(BodyKind::Grpc, b"\0\0\0", &no_gzip, false).is_err());
    }

    #[test]
    fn compressed_messages() {
        let body = frame_message(1, b"packed");
        let un = |p: &[u8]| (p == b"packed").then(|| vec![0x08, 0x07]);
        let r = render_body(BodyKind::Grpc, &body, &un, false).unwrap();
        assert_eq!(r.text, "@message\n1: 7\n");
        assert!(!r.exact);
        assert!(r.notes[0].contains("compressed"));
        // Edited messages are sent with flag 0.
        assert_eq!(encode_text(BodyKind::Grpc, &r.text).unwrap(), frame_message(0, &[0x08, 0x07]));
        // No decompressor: the message is not shown, and says so.
        let r = render_body(BodyKind::Grpc, &body, &no_gzip, false).unwrap();
        assert!(r.text.contains("could not be decompressed"));
        assert!(!r.exact);
    }

    #[test]
    fn grpc_web_trailers_and_text() {
        let msg = frame_message(0, &[0x08, 0x01]);
        let trailers = frame_message(0x80, b"grpc-status: 3\r\ngrpc-message: bad thing\r\n");
        let mut web = msg.clone();
        web.extend(&trailers);
        let r = render_body(BodyKind::GrpcWeb, &web, &no_gzip, false).unwrap();
        assert_eq!(r.text, "@message\n1: 1\n@trailers\ngrpc-status: 3\ngrpc-message: bad thing\n");
        assert_eq!(r.grpc_status.as_deref(), Some("3"));
        assert_eq!(r.grpc_message.as_deref(), Some("bad thing"));
        assert_eq!(r.messages, 1);
        assert!(r.exact);
        assert_eq!(encode_text(BodyKind::GrpcWeb, &r.text).unwrap(), web);
        // grpc-web-text is the base64 of the same stream, also when chunks are padded separately.
        let text = base64_encode(&web);
        let rt = render_body(BodyKind::GrpcWebText, text.as_bytes(), &no_gzip, false).unwrap();
        assert_eq!(rt.text, r.text);
        assert!(rt.exact);
        assert_eq!(encode_text(BodyKind::GrpcWebText, &rt.text).unwrap(), text.as_bytes());
        let chunked = format!("{}{}", base64_encode(&msg), base64_encode(&trailers));
        let rc = render_body(BodyKind::GrpcWebText, chunked.as_bytes(), &no_gzip, false).unwrap();
        assert_eq!(rc.text, r.text);
        assert!(!rc.exact, "different chunking is not what the encoder writes");
        // Plain gRPC has no trailers frame to write.
        assert!(encode_text(BodyKind::Grpc, &r.text).is_err());
        // Bad base64.
        assert_eq!(render_body(BodyKind::GrpcWebText, b"@@@@", &no_gzip, false), Err(ProtoError::BadBase64));
    }

    #[test]
    fn base64_round_trip() {
        for n in 0..40 {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            let e = base64_encode(&data);
            assert_eq!(base64_decode(e.as_bytes()).unwrap(), data);
            assert_eq!(base64_decode(e.trim_end_matches('=').as_bytes()).unwrap(), data);
        }
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_decode(b"aGVs\nbG8=").unwrap(), b"hello");
        assert!(base64_decode(b"a").is_err());
        assert!(base64_decode(b"=aaa").is_err());
        assert!(base64_decode(b"aa=a").is_err());
    }

    #[test]
    fn grpc_text_errors_name_the_line() {
        let e = encode_text(BodyKind::Grpc, "@message\n1: 1\n@message\n2: oops\n").unwrap_err();
        assert!(matches!(e, ProtoError::Text { line: 4, .. }), "{e}");
    }
}
