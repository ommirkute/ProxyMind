//! Connections kept open for the proxy to reuse. Browsers expect it: a new
//! TCP and TLS handshake per request makes browsing slow. Replay, scans and
//! fuzzing don't use the pool; they want one connection per request.
//!
//! HTTP/1.1 connections are handed back after a complete response and
//! reused only for requests that are safe to retry (GET, HEAD, OPTIONS), in
//! case the server closed the connection meanwhile. HTTP/2 connections are
//! shared by every request to the host.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::io::AsyncReadExt;

use crate::{Conn, Io};

/// How long an idle HTTP/1.1 connection is kept.
const H1_IDLE: Duration = Duration::from_secs(30);
/// How long an unused HTTP/2 connection is kept.
const H2_IDLE: Duration = Duration::from_secs(90);
/// Idle HTTP/1.1 connections per host, and in all.
const PER_HOST: usize = 6;
const TOTAL: usize = 256;

type Idle = (Conn<Box<dyn Io>>, Instant);

#[derive(Default)]
pub(crate) struct Pool {
    h1: Mutex<HashMap<String, Vec<Idle>>>,
    h2: Mutex<HashMap<String, (h2::client::SendRequest<Bytes>, Instant)>>,
}

impl Pool {
    /// The most recently used idle connection to `key`, if one is recent.
    pub(crate) fn take_h1(&self, key: &str) -> Option<Conn<Box<dyn Io>>> {
        let mut m = self.h1.lock();
        let list = m.get_mut(key)?;
        while let Some((conn, at)) = list.pop() {
            if at.elapsed() < H1_IDLE {
                return Some(conn);
            }
        }
        None
    }

    pub(crate) fn put_h1(&self, key: String, conn: Conn<Box<dyn Io>>) {
        let mut m = self.h1.lock();
        if m.values().map(Vec::len).sum::<usize>() >= TOTAL {
            m.retain(|_, v| {
                v.retain(|(_, at)| at.elapsed() < H1_IDLE);
                !v.is_empty()
            });
            if m.values().map(Vec::len).sum::<usize>() >= TOTAL {
                return;
            }
        }
        let list = m.entry(key).or_default();
        if list.len() >= PER_HOST {
            list.remove(0);
        }
        list.push((conn, Instant::now()));
    }

    pub(crate) fn h1_has(&self, key: &str) -> bool {
        self.h1.lock().get(key).is_some_and(|v| v.iter().any(|(_, at)| at.elapsed() < H1_IDLE))
    }

    /// A shared HTTP/2 connection to `key`, if one was used recently.
    pub(crate) fn h2(&self, key: &str) -> Option<h2::client::SendRequest<Bytes>> {
        let mut m = self.h2.lock();
        match m.get_mut(key) {
            Some((c, at)) if at.elapsed() < H2_IDLE => {
                *at = Instant::now();
                Some(c.clone())
            }
            Some(_) => {
                m.remove(key);
                None
            }
            None => None,
        }
    }

    pub(crate) fn put_h2(&self, key: String, c: h2::client::SendRequest<Bytes>) {
        let mut m = self.h2.lock();
        m.retain(|_, (_, at)| at.elapsed() < H2_IDLE);
        m.insert(key, (c, Instant::now()));
    }

    pub(crate) fn drop_h2(&self, key: &str) {
        self.h2.lock().remove(key);
    }
}

/// Whether a pooled connection is still usable: the server hasn't closed it
/// and sent nothing unasked.
pub(crate) async fn alive(conn: &mut Conn<Box<dyn Io>>) -> bool {
    if !conn.buf.is_empty() {
        return false;
    }
    let mut b = [0u8; 1];
    // Polls the read once: still pending means open and quiet.
    tokio::time::timeout(Duration::ZERO, conn.io.read(&mut b)).await.is_err()
}
