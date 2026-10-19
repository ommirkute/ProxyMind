//! A minimal authoritative DNS responder for OAST.
//!
//! Payloads name a host such as `<token>.oast.example.com`. When the target
//! resolves it (blind SSRF, XXE, command injection with `nslookup`), the
//! query reaches this responder through the domain's NS delegation, and the
//! token proves the lookup came from the payload. A lookup alone is proof:
//! many networks block outbound HTTP but still resolve names.
//!
//! The parser and answer builder are sans-I/O so they're easy to test and
//! fuzz; [`serve`] adds the UDP socket.

use std::net::{Ipv4Addr, SocketAddr};

use crate::Interaction;

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_ANY: u16 = 255;

const RCODE_REFUSED: u8 = 5;
const MAX_NAME: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    Truncated,
    NotAQuery,
    /// Only one question per query is supported (as every resolver sends).
    QuestionCount(u16),
    BadLabel,
    NameTooLong,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::Truncated => write!(f, "packet is truncated"),
            DnsError::NotAQuery => write!(f, "not a standard query"),
            DnsError::QuestionCount(n) => write!(f, "expected one question, got {n}"),
            DnsError::BadLabel => write!(f, "bad label (compression pointers aren't allowed in a question)"),
            DnsError::NameTooLong => write!(f, "name longer than 255 bytes"),
        }
    }
}

impl std::error::Error for DnsError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    pub recursion_desired: bool,
    /// Lowercased, without the trailing dot. Resolvers may randomise case
    /// (DNS 0x20), so names are compared in lowercase.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// End of the question section in the packet.
    question_end: usize,
}

pub fn type_name(t: u16) -> String {
    match t {
        TYPE_A => "A".into(),
        TYPE_AAAA => "AAAA".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        TYPE_ANY => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

/// Parses a DNS query packet (header + one question).
pub fn parse_query(p: &[u8]) -> Result<Query, DnsError> {
    if p.len() < 12 {
        return Err(DnsError::Truncated);
    }
    let id = u16::from_be_bytes([p[0], p[1]]);
    let flags = u16::from_be_bytes([p[2], p[3]]);
    // QR must be 0 (query) and the opcode 0 (standard query).
    if flags & 0x8000 != 0 || (flags >> 11) & 0xf != 0 {
        return Err(DnsError::NotAQuery);
    }
    let qd = u16::from_be_bytes([p[4], p[5]]);
    if qd != 1 {
        return Err(DnsError::QuestionCount(qd));
    }
    let mut i = 12;
    let mut labels: Vec<String> = Vec::new();
    let mut wire_len = 0usize;
    loop {
        let len = *p.get(i).ok_or(DnsError::Truncated)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return Err(DnsError::BadLabel);
        }
        wire_len += len + 1;
        if wire_len > MAX_NAME {
            return Err(DnsError::NameTooLong);
        }
        let label = p.get(i..i + len).ok_or(DnsError::Truncated)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        i += len;
    }
    let rest = p.get(i..i + 4).ok_or(DnsError::Truncated)?;
    Ok(Query {
        id,
        recursion_desired: flags & 0x0100 != 0,
        name: labels.join("."),
        qtype: u16::from_be_bytes([rest[0], rest[1]]),
        qclass: u16::from_be_bytes([rest[2], rest[3]]),
        question_end: i + 4,
    })
}

/// Whether `name` is `domain` or a name under it.
pub fn in_zone(name: &str, domain: &str) -> bool {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    !d.is_empty() && (name == d || name.ends_with(&format!(".{d}")))
}

/// The token in a name under `domain` (any label left of the domain).
pub fn token_in(name: &str, domain: &str) -> Option<String> {
    if !in_zone(name, domain) {
        return None;
    }
    let sub = name.strip_suffix(domain.trim_end_matches('.').to_ascii_lowercase().as_str())?;
    sub.split('.').find(|l| crate::is_token(l)).map(str::to_string)
}

/// Builds the answer for `q` (parsed from `packet`). Names in the zone get
/// an authoritative answer: an A record pointing at `answer_ip` for A/ANY
/// queries, an empty NOERROR otherwise. Names outside it are refused.
pub fn answer(packet: &[u8], q: &Query, domain: &str, answer_ip: Ipv4Addr) -> Vec<u8> {
    let ours = in_zone(&q.name, domain);
    let give_a = ours && q.qclass == 1 && matches!(q.qtype, TYPE_A | TYPE_ANY);
    let mut out = Vec::with_capacity(q.question_end + 16);
    out.extend_from_slice(&q.id.to_be_bytes());
    // QR=1, opcode 0, AA when ours, RD copied; RA=0; rcode 0 or REFUSED.
    let mut flags: u16 = 0x8000;
    if ours {
        flags |= 0x0400;
    } else {
        flags |= u16::from(RCODE_REFUSED);
    }
    if q.recursion_desired {
        flags |= 0x0100;
    }
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&u16::from(give_a).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT
    out.extend_from_slice(&packet[12..q.question_end]);
    if give_a {
        out.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out.extend_from_slice(&0u32.to_be_bytes()); // TTL 0: every lookup reaches us
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&answer_ip.octets());
    }
    out
}

/// What to record for a query, if it carries a token.
pub fn interaction(q: &Query, domain: &str, remote: SocketAddr) -> Option<Interaction> {
    let token = token_in(&q.name, domain)?;
    Some(Interaction {
        token,
        protocol: "dns".into(),
        remote: remote.to_string(),
        method: type_name(q.qtype),
        path: q.name.clone(),
        ts_ms: pm_core::now_ms(),
        raw: format!("DNS {} query for {} from {remote}", type_name(q.qtype), q.name),
    })
}

/// Answers queries on `socket` until it fails, calling `sink` for every
/// query that carries a token.
pub async fn serve<F>(socket: tokio::net::UdpSocket, domain: String, answer_ip: Ipv4Addr, sink: F)
where
    F: Fn(Interaction) + Send + Sync + 'static,
{
    let mut buf = vec![0u8; 1500];
    loop {
        let Ok((n, remote)) = socket.recv_from(&mut buf).await else { return };
        let packet = &buf[..n];
        let Ok(q) = parse_query(packet) else { continue };
        if let Some(i) = interaction(&q, &domain, remote) {
            sink(i);
        }
        let _ = socket.send_to(&answer(packet, &q, &domain, answer_ip), remote).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A query packet built by hand, as `dig` would send it.
    fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut p = id.to_be_bytes().to_vec();
        p.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, 1 question
        for l in name.split('.') {
            p.push(l.len() as u8);
            p.extend_from_slice(l.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p
    }

    #[test]
    fn parses_queries_case_insensitively() {
        let q = parse_query(&query(0xbeef, "AbCdEf0123456789abcd.OAST.Example.com", TYPE_A)).unwrap();
        assert_eq!(q.id, 0xbeef);
        assert!(q.recursion_desired);
        assert_eq!(q.name, "abcdef0123456789abcd.oast.example.com");
        assert_eq!((q.qtype, q.qclass), (TYPE_A, 1));
        assert_eq!(token_in(&q.name, "oast.example.com").as_deref(), Some("abcdef0123456789abcd"));
        // Token deeper in the name (e.g. data exfiltrated in front of it).
        assert_eq!(
            token_in("secret.abcdef0123456789abcd.oast.example.com", "oast.example.com.").as_deref(),
            Some("abcdef0123456789abcd")
        );
        assert_eq!(token_in("abcdef0123456789abcd.evil-oast.example.com", "oast.example.com"), None);
        assert_eq!(token_in("www.oast.example.com", "oast.example.com"), None);
    }

    #[test]
    fn golden_answer_for_an_a_query() {
        let p = query(0x1234, "abcdef0123456789abcd.oast.test", TYPE_A);
        let q = parse_query(&p).unwrap();
        let a = answer(&p, &q, "oast.test", Ipv4Addr::new(203, 0, 113, 7));
        let mut want = vec![0x12, 0x34, 0x85, 0x00, 0, 1, 0, 1, 0, 0, 0, 0];
        want.extend_from_slice(&p[12..]);
        want.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 203, 0, 113, 7]);
        assert_eq!(a, want);
    }

    #[test]
    fn other_types_get_empty_answers_and_other_zones_are_refused() {
        let p = query(7, "x.oast.test", TYPE_AAAA);
        let a = answer(&p, &parse_query(&p).unwrap(), "oast.test", Ipv4Addr::LOCALHOST);
        assert_eq!((a[3] & 0x0f, a[7]), (0, 0), "NOERROR, no answers");
        let p = query(7, "example.org", TYPE_A);
        let a = answer(&p, &parse_query(&p).unwrap(), "oast.test", Ipv4Addr::LOCALHOST);
        assert_eq!((a[3] & 0x0f, a[7]), (RCODE_REFUSED, 0), "not an open resolver");
    }

    #[test]
    fn rejects_malformed_packets() {
        assert_eq!(parse_query(&[0; 5]), Err(DnsError::Truncated));
        let mut resp = query(1, "a.b", TYPE_A);
        resp[2] |= 0x80;
        assert_eq!(parse_query(&resp), Err(DnsError::NotAQuery));
        let mut two = query(1, "a.b", TYPE_A);
        two[5] = 2;
        assert_eq!(parse_query(&two), Err(DnsError::QuestionCount(2)));
        let mut ptr = query(1, "a.b", TYPE_A);
        ptr[12] = 0xc0;
        assert_eq!(parse_query(&ptr), Err(DnsError::BadLabel));
        let long = query(1, &vec!["a".repeat(63); 5].join("."), TYPE_A);
        assert_eq!(parse_query(&long), Err(DnsError::NameTooLong));
        let mut cut = query(1, "abc.def", TYPE_A);
        cut.truncate(cut.len() - 3);
        assert_eq!(parse_query(&cut), Err(DnsError::Truncated));
        // Any bytes: never panic.
        for n in 0..64u8 {
            let junk: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37).wrapping_add(n)).collect();
            let _ = parse_query(&junk);
        }
    }

    #[tokio::test]
    async fn serves_over_udp_and_records_tokens() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let s2 = seen.clone();
        tokio::spawn(serve(sock, "oast.test".into(), Ipv4Addr::new(10, 0, 0, 1), move |i| s2.lock().unwrap().push(i)));
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let token = crate::new_token();
        client.send_to(&query(42, &format!("{token}.oast.test"), TYPE_A), addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(5), client.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[n - 4..n], &[10, 0, 0, 1]);
        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(
            (got[0].token.as_str(), got[0].protocol.as_str(), got[0].method.as_str()),
            (token.as_str(), "dns", "A")
        );
    }
}
