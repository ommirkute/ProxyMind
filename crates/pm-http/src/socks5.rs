//! SOCKS5 server-side handshake parsing (RFC 1928, username/password per RFC 1929). Sans-I/O: callers feed the bytes
//! they have read and get back what was parsed and how many bytes it used, or `None` when more bytes are needed.
//! Nothing here reads or writes a socket, and no input makes it panic.
//!
//! The handshake has three messages from the client, each parsed by one function:
//!
//! 1. the greeting (`05 nmethods methods...`), then [`choose_method`] picks the login method;
//! 2. with username/password: `01 ulen user plen pass` ([`parse_auth`]), answered with [`auth_reply`];
//! 3. the request (`05 cmd 00 atyp addr port`, [`parse_request`]), answered with [`reply`].
//!
//! Domain names are checked (UTF-8, no control characters, no spaces) because callers put them into Host headers
//! and certificates.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The protocol version byte.
pub const VERSION: u8 = 5;
/// Version byte of the username/password sub-negotiation (RFC 1929).
pub const AUTH_VERSION: u8 = 1;

/// Login method: none.
pub const METHOD_NO_AUTH: u8 = 0x00;
/// Login method: username and password.
pub const METHOD_PASSWORD: u8 = 0x02;
/// "No acceptable method": the server's answer when it likes none of the client's.
pub const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

/// Request command CONNECT.
pub const CMD_CONNECT: u8 = 1;
/// Request command BIND.
pub const CMD_BIND: u8 = 2;
/// Request command UDP ASSOCIATE.
pub const CMD_UDP_ASSOCIATE: u8 = 3;

/// Reply code: succeeded.
pub const REP_SUCCEEDED: u8 = 0;
/// Reply code: general SOCKS server failure.
pub const REP_GENERAL_FAILURE: u8 = 1;
/// Reply code: connection not allowed by ruleset.
pub const REP_NOT_ALLOWED: u8 = 2;
/// Reply code: network unreachable.
pub const REP_NETWORK_UNREACHABLE: u8 = 3;
/// Reply code: host unreachable.
pub const REP_HOST_UNREACHABLE: u8 = 4;
/// Reply code: connection refused.
pub const REP_CONNECTION_REFUSED: u8 = 5;
/// Reply code: command not supported.
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 7;
/// Reply code: address type not supported.
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 8;

/// Most bytes a complete handshake message can have (the greeting and request are shorter; a login is at most 513).
pub const MAX_MESSAGE: usize = 3 + 255 + 255 + 3;

/// Why a handshake message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The first byte is not 5 (SOCKS4, HTTP, or something else).
    BadVersion(u8),
    /// The greeting offers no login methods.
    NoMethods,
    /// The login sub-negotiation does not start with 1.
    BadAuthVersion(u8),
    /// An empty user name (RFC 1929 needs 1 to 255 bytes).
    EmptyUsername,
    /// The reserved byte of a request is not 0.
    BadReserved(u8),
    /// An address type other than 1, 3 or 4.
    BadAddressType(u8),
    /// A domain name that is empty, not UTF-8, or holds control characters or spaces.
    BadDomain,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadVersion(v) => write!(f, "not a SOCKS5 client (first byte {v})"),
            Error::NoMethods => write!(f, "the SOCKS5 greeting offers no login method"),
            Error::BadAuthVersion(v) => write!(f, "bad SOCKS5 login version {v}"),
            Error::EmptyUsername => write!(f, "the SOCKS5 login has an empty username"),
            Error::BadReserved(v) => write!(f, "bad reserved byte {v} in the SOCKS5 request"),
            Error::BadAddressType(t) => write!(f, "unsupported SOCKS5 address type {t}"),
            Error::BadDomain => write!(f, "the SOCKS5 request names an invalid host"),
        }
    }
}

impl std::error::Error for Error {}

/// The greeting: the login methods the client offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    pub methods: Vec<u8>,
}

/// A username and password (RFC 1929). Bytes, as sent; not necessarily UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

/// Where the client wants to connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Domain(String),
}

impl Address {
    /// The host as text: an IP address or the domain name (no brackets).
    pub fn host(&self) -> String {
        match self {
            Address::V4(ip) => ip.to_string(),
            Address::V6(ip) => ip.to_string(),
            Address::Domain(d) => d.clone(),
        }
    }
}

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// [`CMD_CONNECT`], [`CMD_BIND`], [`CMD_UDP_ASSOCIATE`] or any other byte the client sent.
    pub command: u8,
    pub address: Address,
    pub port: u16,
}

/// Parses the greeting. `Ok(None)`: not complete yet. On success, the greeting and the bytes it used.
pub fn parse_greeting(buf: &[u8]) -> Result<Option<(Greeting, usize)>, Error> {
    let Some(&ver) = buf.first() else { return Ok(None) };
    if ver != VERSION {
        return Err(Error::BadVersion(ver));
    }
    let Some(&n) = buf.get(1) else { return Ok(None) };
    if n == 0 {
        return Err(Error::NoMethods);
    }
    let end = 2 + usize::from(n);
    if buf.len() < end {
        return Ok(None);
    }
    Ok(Some((Greeting { methods: buf[2..end].to_vec() }, end)))
}

/// The login method to answer with: password login when `auth_required` and the client offers it, no login when
/// none is required and the client offers it, else [`METHOD_NONE_ACCEPTABLE`]. A server that requires a login
/// never picks "no login", even if the client offers nothing else.
pub fn choose_method(offered: &[u8], auth_required: bool) -> u8 {
    if auth_required {
        if offered.contains(&METHOD_PASSWORD) { METHOD_PASSWORD } else { METHOD_NONE_ACCEPTABLE }
    } else if offered.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        METHOD_NONE_ACCEPTABLE
    }
}

/// The server's answer to the greeting.
pub fn method_reply(method: u8) -> [u8; 2] {
    [VERSION, method]
}

/// Parses the username/password message. `Ok(None)`: not complete yet.
pub fn parse_auth(buf: &[u8]) -> Result<Option<(Credentials, usize)>, Error> {
    let Some(&ver) = buf.first() else { return Ok(None) };
    if ver != AUTH_VERSION {
        return Err(Error::BadAuthVersion(ver));
    }
    let Some(&ulen) = buf.get(1) else { return Ok(None) };
    if ulen == 0 {
        return Err(Error::EmptyUsername);
    }
    let pstart = 2 + usize::from(ulen);
    let Some(&plen) = buf.get(pstart) else { return Ok(None) };
    let end = pstart + 1 + usize::from(plen);
    if buf.len() < end {
        return Ok(None);
    }
    Ok(Some((Credentials { username: buf[2..pstart].to_vec(), password: buf[pstart + 1..end].to_vec() }, end)))
}

/// The server's answer to a login: success or failure (the client must then close).
pub fn auth_reply(ok: bool) -> [u8; 2] {
    [AUTH_VERSION, u8::from(!ok)]
}

/// Compares a received login with the configured one without stopping at the first difference.
pub fn credentials_match(got: &Credentials, username: &str, password: &str) -> bool {
    let a = ct_eq(&got.username, username.as_bytes());
    let b = ct_eq(&got.password, password.as_bytes());
    a & b
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// Parses a request. `Ok(None)`: not complete yet.
pub fn parse_request(buf: &[u8]) -> Result<Option<(Request, usize)>, Error> {
    let Some(&ver) = buf.first() else { return Ok(None) };
    if ver != VERSION {
        return Err(Error::BadVersion(ver));
    }
    if buf.len() < 4 {
        return Ok(None);
    }
    let (command, rsv, atyp) = (buf[1], buf[2], buf[3]);
    if rsv != 0 {
        return Err(Error::BadReserved(rsv));
    }
    let (address, after) = match atyp {
        1 => {
            if buf.len() < 4 + 4 {
                return Ok(None);
            }
            (Address::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7])), 8)
        }
        4 => {
            if buf.len() < 4 + 16 {
                return Ok(None);
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[4..20]);
            (Address::V6(Ipv6Addr::from(o)), 20)
        }
        3 => {
            let Some(&n) = buf.get(4) else { return Ok(None) };
            let end = 5 + usize::from(n);
            if buf.len() < end {
                return Ok(None);
            }
            (Address::Domain(valid_domain(&buf[5..end])?), end)
        }
        t => return Err(Error::BadAddressType(t)),
    };
    let end = after + 2;
    if buf.len() < end {
        return Ok(None);
    }
    let port = u16::from_be_bytes([buf[after], buf[after + 1]]);
    Ok(Some((Request { command, address, port }, end)))
}

fn valid_domain(raw: &[u8]) -> Result<String, Error> {
    let s = std::str::from_utf8(raw).map_err(|_| Error::BadDomain)?;
    if s.is_empty() || s.chars().any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '\\' | '@')) {
        return Err(Error::BadDomain);
    }
    Ok(s.to_string())
}

/// A reply to a request: `code` and the address the server connected from (`None` sends 0.0.0.0:0, which clients
/// of a CONNECT ignore).
pub fn reply(code: u8, bound: Option<SocketAddr>) -> Vec<u8> {
    let mut out = vec![VERSION, code, 0];
    match bound.map(|a| (a.ip(), a.port())) {
        Some((IpAddr::V4(ip), port)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Some((IpAddr::V6(ip), port)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        None => out.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0]),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(atyp: &[u8], port: u16) -> Vec<u8> {
        let mut v = vec![5, 1, 0];
        v.extend_from_slice(atyp);
        v.extend_from_slice(&port.to_be_bytes());
        v
    }

    #[test]
    fn greeting_parses_and_waits_for_more() {
        let (g, n) = parse_greeting(&[5, 2, 0, 2, 9, 9]).unwrap().unwrap();
        assert_eq!((g.methods, n), (vec![0, 2], 4));
        assert_eq!(parse_greeting(&[]).unwrap(), None);
        assert_eq!(parse_greeting(&[5]).unwrap(), None);
        assert_eq!(parse_greeting(&[5, 3, 0, 1]).unwrap(), None);
        assert_eq!(parse_greeting(&[4, 1, 0]), Err(Error::BadVersion(4)));
        assert_eq!(parse_greeting(b"GET / HTTP/1.1"), Err(Error::BadVersion(b'G')));
        assert_eq!(parse_greeting(&[5, 0]), Err(Error::NoMethods));
    }

    #[test]
    fn method_choice() {
        assert_eq!(choose_method(&[0, 2], false), METHOD_NO_AUTH);
        assert_eq!(choose_method(&[2], false), METHOD_NONE_ACCEPTABLE);
        assert_eq!(choose_method(&[0, 2], true), METHOD_PASSWORD);
        assert_eq!(choose_method(&[0], true), METHOD_NONE_ACCEPTABLE);
        assert_eq!(choose_method(&[], true), METHOD_NONE_ACCEPTABLE);
        assert_eq!(method_reply(2), [5, 2]);
    }

    #[test]
    fn auth_success_failure_and_truncation() {
        let mut m = vec![1, 3];
        m.extend_from_slice(b"bob");
        m.push(2);
        m.extend_from_slice(b"pw");
        let (c, n) = parse_auth(&m).unwrap().unwrap();
        assert_eq!(n, m.len());
        assert!(credentials_match(&c, "bob", "pw"));
        assert!(!credentials_match(&c, "bob", "pW"));
        assert!(!credentials_match(&c, "bo", "pw"));
        assert!(!credentials_match(&c, "bob", "pw2"));
        for cut in 0..m.len() {
            assert_eq!(parse_auth(&m[..cut]).unwrap(), None, "cut at {cut}");
        }
        // An empty password is allowed; an empty username and a wrong version are not.
        assert!(parse_auth(&[1, 1, b'a', 0]).unwrap().is_some());
        assert_eq!(parse_auth(&[1, 0, 0]), Err(Error::EmptyUsername));
        assert_eq!(parse_auth(&[5, 1, b'a', 0]), Err(Error::BadAuthVersion(5)));
        assert_eq!(auth_reply(true), [1, 0]);
        assert_eq!(auth_reply(false), [1, 1]);
        // The longest login is 255 + 255 bytes.
        let mut long = vec![1, 255];
        long.extend(std::iter::repeat_n(b'u', 255));
        long.push(255);
        long.extend(std::iter::repeat_n(b'p', 255));
        assert_eq!(parse_auth(&long).unwrap().unwrap().1, 513);
        assert!(long.len() <= MAX_MESSAGE);
    }

    #[test]
    fn requests_with_every_address_type() {
        let r = parse_request(&req(&[1, 192, 168, 1, 9], 8080)).unwrap().unwrap();
        assert_eq!(
            r.0,
            Request { command: CMD_CONNECT, address: Address::V4(Ipv4Addr::new(192, 168, 1, 9)), port: 8080 }
        );
        assert_eq!(r.1, 10);

        let mut v6 = vec![4];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        let r = parse_request(&req(&v6, 443)).unwrap().unwrap();
        assert_eq!(r.0.address, Address::V6(Ipv6Addr::LOCALHOST));
        assert_eq!((r.0.port, r.1), (443, 22));
        assert_eq!(r.0.address.host(), "::1");

        let mut dom = vec![3, 11];
        dom.extend_from_slice(b"example.com");
        let r = parse_request(&req(&dom, 80)).unwrap().unwrap();
        assert_eq!(r.0.address, Address::Domain("example.com".into()));
        assert_eq!((r.0.port, r.1), (80, 5 + 11 + 2));

        // Other commands parse; the caller refuses them.
        let mut bind = req(&[1, 1, 2, 3, 4], 9);
        bind[1] = CMD_BIND;
        assert_eq!(parse_request(&bind).unwrap().unwrap().0.command, CMD_BIND);
    }

    #[test]
    fn requests_that_are_bad_or_cut_short() {
        let mut dom = vec![3, 11];
        dom.extend_from_slice(b"example.com");
        for full in [
            req(&[1, 1, 2, 3, 4], 80),
            req(
                &{
                    let mut v = vec![4];
                    v.extend([7u8; 16]);
                    v
                },
                80,
            ),
            req(&dom, 80),
        ] {
            for cut in 0..full.len() {
                assert_eq!(parse_request(&full[..cut]).unwrap(), None, "cut at {cut}");
            }
            assert!(parse_request(&full).unwrap().is_some());
        }
        assert_eq!(parse_request(&[4, 1, 0, 1, 1, 2, 3, 4, 0, 80]), Err(Error::BadVersion(4)));
        assert_eq!(parse_request(&[5, 1, 7, 1, 1, 2, 3, 4, 0, 80]), Err(Error::BadReserved(7)));
        assert_eq!(parse_request(&[5, 1, 0, 9, 1, 2]), Err(Error::BadAddressType(9)));
        assert_eq!(parse_request(&req(&[3, 0], 80)), Err(Error::BadDomain));
        assert_eq!(parse_request(&req(&[3, 2, 0xff, 0xfe], 80)), Err(Error::BadDomain));
        assert_eq!(parse_request(&req(&[3, 3, b'a', b' ', b'b'], 80)), Err(Error::BadDomain));
        assert_eq!(parse_request(&req(&[3, 3, b'a', b'\r', b'\n'], 80)), Err(Error::BadDomain));
        assert_eq!(parse_request(&req(&[3, 3, b'a', b'@', b'b'], 80)), Err(Error::BadDomain));
        // Bytes after the request belong to the tunnel and are not consumed.
        let mut extra = req(&[1, 1, 2, 3, 4], 80);
        extra.extend_from_slice(b"GET / HTTP/1.1");
        assert_eq!(parse_request(&extra).unwrap().unwrap().1, 10);
    }

    #[test]
    fn replies() {
        assert_eq!(reply(REP_SUCCEEDED, None), [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reply(REP_COMMAND_NOT_SUPPORTED, None)[1], 7);
        let a: SocketAddr = "10.1.2.3:4567".parse().unwrap();
        assert_eq!(reply(0, Some(a)), [5, 0, 0, 1, 10, 1, 2, 3, 0x11, 0xd7]);
        let a6: SocketAddr = "[::1]:80".parse().unwrap();
        let r = reply(0, Some(a6));
        assert_eq!((r[3], r.len()), (4, 22));
    }
}
