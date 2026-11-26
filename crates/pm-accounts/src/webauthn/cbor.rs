//! A small, strict CBOR (RFC 8949) decoder for what WebAuthn sends: the attestation object, the COSE public key and
//! the authenticator extensions. It is a decoder only (we never encode CBOR outside the test authenticator).
//!
//! Strictness, on purpose:
//! * **Bounded:** nesting at most [`MAX_DEPTH`], at most [`MAX_ITEMS`] entries per array or map, and a declared length
//!   larger than the bytes left is refused before anything is allocated, so no input can ask for memory it does not
//!   carry.
//! * **Definite lengths only.** Indefinite-length strings, arrays and maps (additional information 31) are refused, as
//!   are reserved additional-information values.
//! * **No tags, no floats, no `undefined`.** WebAuthn uses none of them; refusing them keeps the surface small.
//! * **No duplicate map keys** (a duplicate could make two parsers disagree about a key).
//! * **No trailing bytes** for [`decode`]; [`decode_prefix`] reports how much it consumed (authenticator data has
//!   a COSE key followed by more CBOR).
//! * Text strings must be valid UTF-8. Integers that do not fit `i64` (a `u64` above `i64::MAX`, a negative below
//!   `i64::MIN`) are refused: no COSE value is that large.
//!
//! Non-minimal integer and length encodings are accepted (CTAP2's canonical form is minimal, but a verifier that
//! rejects the odd authenticator gains nothing).
//!
//! Nothing here panics on any input; a test feeds it random bytes and mutated valid items.

/// Deepest nesting of arrays and maps accepted.
pub const MAX_DEPTH: usize = 8;
/// Most entries in one array or map.
pub const MAX_ITEMS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Entries in the order they were sent; keys are unique.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborError {
    /// The input ended inside an item.
    Truncated,
    /// Bytes remain after the item.
    Trailing,
    TooDeep,
    TooLarge,
    /// Indefinite length, tag, float, `undefined`, a reserved value or an integer outside `i64`.
    Unsupported,
    BadUtf8,
    DuplicateKey,
}

impl Value {
    /// The value for an integer key of a map (COSE keys).
    pub fn get_int(&self, key: i64) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| matches!(k, Value::Int(i) if *i == key)).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value for a text key of a map (the attestation object).
    pub fn get_text(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| matches!(k, Value::Text(t) if t == key)).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }
}

/// Decodes exactly one item that must use the whole input.
pub fn decode(input: &[u8]) -> Result<Value, CborError> {
    let (v, used) = decode_prefix(input)?;
    if used == input.len() { Ok(v) } else { Err(CborError::Trailing) }
}

/// Decodes one item from the start of `input` and says how many bytes it took.
pub fn decode_prefix(input: &[u8]) -> Result<(Value, usize), CborError> {
    let mut r = Reader { buf: input, pos: 0 };
    let v = r.item(0)?;
    Ok((v, r.pos))
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn left(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        if n > self.left() {
            return Err(CborError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        Ok(self.take(1)?[0])
    }

    /// The argument of an item head: the additional information, or the 1, 2, 4 or 8 bytes after it.
    fn argument(&mut self, info: u8) -> Result<u64, CborError> {
        Ok(match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.byte()?),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| CborError::Truncated)?)),
            26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| CborError::Truncated)?)),
            27 => u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| CborError::Truncated)?),
            // 28 to 30 are reserved, 31 is the indefinite length.
            _ => return Err(CborError::Unsupported),
        })
    }

    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        let head = self.byte()?;
        let (major, info) = (head >> 5, head & 31);
        match major {
            0 => {
                let n = self.argument(info)?;
                i64::try_from(n).map(Value::Int).map_err(|_| CborError::Unsupported)
            }
            1 => {
                let n = self.argument(info)?;
                // -1 - n
                i64::try_from(n).map(|n| Value::Int(-1 - n)).map_err(|_| CborError::Unsupported)
            }
            2 | 3 => {
                let len = self.argument(info)?;
                let len = usize::try_from(len).map_err(|_| CborError::TooLarge)?;
                let bytes = self.take(len)?;
                if major == 2 {
                    Ok(Value::Bytes(bytes.to_vec()))
                } else {
                    String::from_utf8(bytes.to_vec()).map(Value::Text).map_err(|_| CborError::BadUtf8)
                }
            }
            4 | 5 => {
                if depth >= MAX_DEPTH {
                    return Err(CborError::TooDeep);
                }
                let n = self.argument(info)?;
                let n = usize::try_from(n).map_err(|_| CborError::TooLarge)?;
                if n > MAX_ITEMS {
                    return Err(CborError::TooLarge);
                }
                // Every entry takes at least one byte (a map entry two): a count the input cannot hold is refused
                // before anything is reserved.
                let per = if major == 5 { 2 } else { 1 };
                if n.saturating_mul(per) > self.left() {
                    return Err(CborError::Truncated);
                }
                if major == 4 {
                    let mut items = Vec::with_capacity(n);
                    for _ in 0..n {
                        items.push(self.item(depth + 1)?);
                    }
                    Ok(Value::Array(items))
                } else {
                    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(n);
                    for _ in 0..n {
                        let k = self.item(depth + 1)?;
                        if entries.iter().any(|(e, _)| *e == k) {
                            return Err(CborError::DuplicateKey);
                        }
                        let v = self.item(depth + 1)?;
                        entries.push((k, v));
                    }
                    Ok(Value::Map(entries))
                }
            }
            // Tags.
            6 => Err(CborError::Unsupported),
            _ => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(CborError::Unsupported),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn rfc_8949_appendix_a_examples() {
        // Integers, strings, arrays and maps from RFC 8949 Appendix A.
        assert_eq!(decode(&hex("00")).unwrap(), Value::Int(0));
        assert_eq!(decode(&hex("17")).unwrap(), Value::Int(23));
        assert_eq!(decode(&hex("1818")).unwrap(), Value::Int(24));
        assert_eq!(decode(&hex("1903e8")).unwrap(), Value::Int(1000));
        assert_eq!(decode(&hex("1a000f4240")).unwrap(), Value::Int(1_000_000));
        assert_eq!(decode(&hex("1b000000e8d4a51000")).unwrap(), Value::Int(1_000_000_000_000));
        assert_eq!(decode(&hex("20")).unwrap(), Value::Int(-1));
        assert_eq!(decode(&hex("29")).unwrap(), Value::Int(-10));
        assert_eq!(decode(&hex("3863")).unwrap(), Value::Int(-100));
        assert_eq!(decode(&hex("3903e7")).unwrap(), Value::Int(-1000));
        assert_eq!(decode(&hex("40")).unwrap(), Value::Bytes(vec![]));
        assert_eq!(decode(&hex("4401020304")).unwrap(), Value::Bytes(vec![1, 2, 3, 4]));
        assert_eq!(decode(&hex("60")).unwrap(), Value::Text(String::new()));
        assert_eq!(decode(&hex("6161")).unwrap(), Value::Text("a".into()));
        assert_eq!(decode(&hex("6449455446")).unwrap(), Value::Text("IETF".into()));
        assert_eq!(decode(&hex("62c3bc")).unwrap(), Value::Text("\u{fc}".into()));
        assert_eq!(decode(&hex("80")).unwrap(), Value::Array(vec![]));
        assert_eq!(decode(&hex("83010203")).unwrap(), Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]));
        assert_eq!(decode(&hex("f4")).unwrap(), Value::Bool(false));
        assert_eq!(decode(&hex("f5")).unwrap(), Value::Bool(true));
        assert_eq!(decode(&hex("f6")).unwrap(), Value::Null);
        let m = decode(&hex("a201020304")).unwrap();
        assert_eq!(m.get_int(1).and_then(Value::as_int), Some(2));
        assert_eq!(m.get_int(3).and_then(Value::as_int), Some(4));
        let m = decode(&hex("a56161614161626142616361436164614461656145")).unwrap();
        assert_eq!(m.get_text("e").and_then(Value::as_text), Some("E"));
        // [1, [2, 3], [4, 5]]
        assert!(matches!(decode(&hex("8301820203820405")).unwrap(), Value::Array(a) if a.len() == 3));
    }

    #[test]
    fn what_is_refused() {
        // Indefinite lengths (array, map, byte string, text string), tags, floats, undefined, reserved values.
        for h in [
            "9f01ff",
            "bf6161 01ff",
            "5f4101ff",
            "7f6161ff",
            "c074323031332d30332d32315432303a30343a30305a",
            "f90000",
            "fa47c35000",
            "fb3ff199999999999a",
            "f7",
            "f0",
            "1c",
            "1d",
            "1e",
            "1f",
            "3f",
            "ff",
        ] {
            let b = hex(&h.replace(' ', ""));
            assert!(decode(&b).is_err(), "{h}");
        }
        // Integers outside i64.
        assert_eq!(decode(&hex("1bffffffffffffffff")), Err(CborError::Unsupported));
        assert_eq!(decode(&hex("3bffffffffffffffff")), Err(CborError::Unsupported));
        assert_eq!(decode(&hex("3b7fffffffffffffff")).unwrap(), Value::Int(i64::MIN));
        // Trailing bytes, truncation, bad UTF-8, duplicate keys.
        assert_eq!(decode(&hex("0000")), Err(CborError::Trailing));
        assert_eq!(decode(&hex("19")), Err(CborError::Truncated));
        assert_eq!(decode(&hex("4401")), Err(CborError::Truncated));
        assert_eq!(decode(&hex("62c328")), Err(CborError::BadUtf8));
        assert_eq!(decode(&hex("a201020103")), Err(CborError::DuplicateKey));
        assert_eq!(decode(&[]), Err(CborError::Truncated));
    }

    #[test]
    fn declared_sizes_cannot_ask_for_memory() {
        // An array of 2^32 entries, a byte string of 2^60 bytes: refused at once, nothing allocated.
        assert!(decode(&hex("9affffffff")).is_err());
        assert!(decode(&hex("5b1000000000000000")).is_err());
        assert!(decode(&hex("bbffffffffffffffff")).is_err());
        // More entries than the limit, even with the bytes present.
        let mut big = vec![0x99, 0x01, 0x01]; // array of 257
        big.extend(std::iter::repeat_n(0u8, 257));
        assert_eq!(decode(&big), Err(CborError::TooLarge));
        let mut ok = vec![0x99, 0x01, 0x00]; // array of 256
        ok.extend(std::iter::repeat_n(0u8, 256));
        assert!(matches!(decode(&ok).unwrap(), Value::Array(a) if a.len() == 256));
    }

    #[test]
    fn nesting_is_bounded() {
        let ok: Vec<u8> = std::iter::repeat_n(0x81u8, MAX_DEPTH).chain([0x00]).collect();
        assert!(decode(&ok).is_ok());
        let deep: Vec<u8> = std::iter::repeat_n(0x81u8, MAX_DEPTH + 1).chain([0x00]).collect();
        assert_eq!(decode(&deep), Err(CborError::TooDeep));
        // A hostile megabyte of nesting stops at the limit instead of overflowing the stack.
        let hostile = vec![0x81u8; 1 << 20];
        assert_eq!(decode(&hostile), Err(CborError::TooDeep));
    }

    #[test]
    fn prefix_reports_how_much_it_used() {
        let (v, n) = decode_prefix(&hex("a10102f5")).unwrap();
        assert_eq!(n, 3);
        assert_eq!(v.get_int(1).and_then(Value::as_int), Some(2));
    }

    #[test]
    fn random_and_mutated_bytes_never_panic() {
        // A deterministic xorshift, so a failure reproduces.
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..20_000 {
            let len = (next() % 80) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            let _ = decode(&bytes);
            let _ = decode_prefix(&bytes);
        }
        // Single-byte mutations and truncations of a valid attestation-like item.
        let mut valid = vec![0xa3, 0x63];
        valid.extend(b"fmt");
        valid.push(0x64);
        valid.extend(b"none");
        valid.push(0x67);
        valid.extend(b"attStmt");
        valid.push(0xa0);
        valid.push(0x68);
        valid.extend(b"authData");
        valid.extend([0x58, 0x20]);
        valid.extend(0u8..32);
        assert!(decode(&valid).is_ok());
        for i in 0..valid.len() {
            let _ = decode(&valid[..i]);
            for b in [0x00, 0x1f, 0x5f, 0x7f, 0x9f, 0xbf, 0xff, 0xc0, 0x3b] {
                let mut m = valid.clone();
                m[i] = b;
                let _ = decode(&m);
            }
        }
    }
}
