//! A small DNS client without I/O: builds a query (with EDNS0, so larger
//! answers fit in UDP) and reads the records out of an answer. Answers come
//! from the network and are untrusted: every read is bounds-checked, name
//! compression pointers are followed a limited number of times, and nothing
//! panics.

use serde::Serialize;

/// Record types asked for by `recon_dns`.
pub const TYPES: &[(&str, u16)] =
    &[("A", 1), ("AAAA", 28), ("CNAME", 5), ("MX", 15), ("TXT", 16), ("NS", 2), ("SOA", 6), ("CAA", 257)];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Record {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub ttl: u32,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Answer {
    pub id: u16,
    /// RCODE: 0 no error, 2 server failure, 3 no such name…
    pub rcode: u8,
    /// The answer was cut to fit (TC bit).
    pub truncated: bool,
    pub records: Vec<Record>,
}

/// A query for `name` and type `qtype`, recursion desired, with an EDNS0
/// record advertising a 1232-byte buffer. `None` for a name that can't be
/// encoded (empty labels, labels over 63 bytes, names over 253).
pub fn query(id: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut p = Vec::with_capacity(64);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x01, 0x00]); // RD
    p.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]); // 1 question, 1 additional (OPT)
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.bytes().all(|b| b.is_ascii_graphic()) {
            return None;
        }
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&[0, 1]); // IN
    // OPT: root name, type 41, UDP size 1232, no extended flags, no data.
    p.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
    Some(p)
}

fn u16_at(p: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]))
}

fn u32_at(p: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([*p.get(i)?, *p.get(i + 1)?, *p.get(i + 2)?, *p.get(i + 3)?]))
}

/// Reads a (possibly compressed) name at `at`; returns it and the offset
/// just past it in the original position.
fn read_name(p: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *p.get(at)? as usize;
        match len {
            0 => {
                return Some((labels.join("."), end.unwrap_or(at + 1)));
            }
            l if l & 0xc0 == 0xc0 => {
                let ptr = usize::from(u16_at(p, at)?) & 0x3fff;
                end.get_or_insert(at + 2);
                if ptr >= p.len() {
                    return None;
                }
                at = ptr;
            }
            l if l <= 63 => {
                let label = p.get(at + 1..at + 1 + l)?;
                labels.push(String::from_utf8_lossy(label).into_owned());
                at += 1 + l;
            }
            _ => return None,
        }
    }
    None
}

fn rdata(p: &[u8], kind: u16, start: usize, len: usize) -> Option<String> {
    let d = p.get(start..start + len)?;
    Some(match kind {
        1 if len == 4 => std::net::Ipv4Addr::new(d[0], d[1], d[2], d[3]).to_string(),
        28 if len == 16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(d);
            std::net::Ipv6Addr::from(b).to_string()
        }
        2 | 5 => read_name(p, start)?.0,
        15 => format!("{} {}", u16_at(p, start)?, read_name(p, start + 2)?.0),
        16 => {
            // One or more character strings.
            let mut out = Vec::new();
            let mut i = 0;
            while i < d.len() {
                let l = d[i] as usize;
                out.push(String::from_utf8_lossy(d.get(i + 1..i + 1 + l)?).into_owned());
                i += 1 + l;
            }
            out.join("")
        }
        6 => {
            let (mname, i) = read_name(p, start)?;
            let (rname, i) = read_name(p, i)?;
            format!("{mname} {rname} serial {}", u32_at(p, i)?)
        }
        257 if len >= 2 => {
            let tag_len = d[1] as usize;
            let tag = String::from_utf8_lossy(d.get(2..2 + tag_len)?);
            let value = String::from_utf8_lossy(d.get(2 + tag_len..)?);
            format!("{} {tag} \"{value}\"", d[0])
        }
        _ => format!("({len} bytes)"),
    })
}

fn type_name(t: u16) -> String {
    TYPES.iter().find(|(_, n)| *n == t).map_or_else(|| format!("TYPE{t}"), |(s, _)| (*s).to_string())
}

/// Reads an answer. `None` when it isn't a DNS response at all.
pub fn parse(p: &[u8]) -> Option<Answer> {
    if p.len() < 12 || p[2] & 0x80 == 0 {
        return None;
    }
    let mut a = Answer { id: u16_at(p, 0)?, rcode: p[3] & 0x0f, truncated: p[2] & 0x02 != 0, records: Vec::new() };
    let (qd, an) = (u16_at(p, 4)?, u16_at(p, 6)?);
    let mut at = 12;
    for _ in 0..qd {
        at = read_name(p, at)?.1 + 4;
    }
    for _ in 0..an.min(200) {
        let (name, i) = read_name(p, at)?;
        let kind = u16_at(p, i)?;
        let ttl = u32_at(p, i + 4)?;
        let len = usize::from(u16_at(p, i + 8)?);
        let start = i + 10;
        if let Some(value) = rdata(p, kind, start, len) {
            a.records.push(Record { name, kind: type_name(kind), ttl, value });
        }
        at = start + len;
    }
    Some(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response to `q` with the given answers (name as a pointer to the question).
    fn respond(q: &[u8], answers: &[(u16, &[u8])]) -> Vec<u8> {
        let qend = q.len() - 11; // without the OPT record
        let mut r = q[..qend].to_vec();
        r[2] = 0x81;
        r[3] = 0x80;
        r[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        r[10..12].copy_from_slice(&[0, 0]);
        for (t, data) in answers {
            r.extend_from_slice(&[0xc0, 12]);
            r.extend_from_slice(&t.to_be_bytes());
            r.extend_from_slice(&[0, 1, 0, 0, 1, 44]);
            r.extend_from_slice(&(data.len() as u16).to_be_bytes());
            r.extend_from_slice(data);
        }
        r
    }

    #[test]
    fn builds_queries_and_reads_answers() {
        let q = query(7, "shop.test", 1).unwrap();
        assert_eq!(&q[..2], &[0, 7]);
        assert!(q.windows(10).any(|w| w == b"\x04shop\x04test"));
        let r = respond(&q, &[(1, &[10, 0, 0, 5]), (16, b"\x0bv=spf1 -all"), (15, b"\x00\x0a\x02mx\xc0\x0c")]);
        let a = parse(&r).unwrap();
        assert_eq!(a.id, 7);
        let v: Vec<(&str, &str)> = a.records.iter().map(|r| (r.kind.as_str(), r.value.as_str())).collect();
        assert_eq!(v, [("A", "10.0.0.5"), ("TXT", "v=spf1 -all"), ("MX", "10 mx.shop.test")]);
        assert_eq!(a.records[0].name, "shop.test");
        assert_eq!(a.records[0].ttl, 300);
    }

    #[test]
    fn bad_input_is_refused_not_panicked_on() {
        assert!(query(1, "", 1).is_none());
        assert!(query(1, &"a".repeat(64), 1).is_none());
        assert!(query(1, "a..b", 1).is_none());
        assert!(parse(&[0; 5]).is_none());
        // A pointer loop.
        let mut loopy = vec![0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 12];
        loopy.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert!(parse(&loopy).is_none());
        for n in 0..64usize {
            let junk: Vec<u8> = (0..n).map(|i| (i * 37 % 256) as u8 | 0x80).collect();
            let _ = parse(&junk);
        }
    }
}
