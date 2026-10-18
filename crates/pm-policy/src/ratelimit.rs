//! Per-host request rate and concurrency limits.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Token bucket per host: allows short bursts up to one second's worth of
/// requests, then `rate` requests per second.
pub struct RateLimiter {
    rate: f64,
    max_concurrency: u32,
    hosts: Mutex<HashMap<String, HostState>>,
}

struct HostState {
    tokens: f64,
    updated: Instant,
    in_flight: Arc<Mutex<u32>>,
}

/// Held while a request is in flight; releases the concurrency slot on drop.
#[derive(Debug)]
pub struct Permit {
    in_flight: Arc<Mutex<u32>>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut n = self.in_flight.lock();
        *n = n.saturating_sub(1);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    /// No token available yet; retry after this long.
    Rate(Duration),
    /// Too many requests already in flight to this host.
    Concurrency,
}

impl RateLimiter {
    pub fn new(rate_per_sec: f64, max_concurrency: u32) -> Self {
        Self { rate: rate_per_sec, max_concurrency, hosts: Mutex::new(HashMap::new()) }
    }

    /// Takes a permit for one request to `host`, or says how long to wait.
    pub fn try_acquire(&self, host: &str, now: Instant) -> Result<Permit, Wait> {
        let burst = self.rate.max(1.0);
        let mut hosts = self.hosts.lock();
        let st = hosts.entry(host.to_ascii_lowercase()).or_insert_with(|| HostState {
            tokens: burst,
            updated: now,
            in_flight: Arc::new(Mutex::new(0)),
        });
        let elapsed = now.saturating_duration_since(st.updated).as_secs_f64();
        st.tokens = (st.tokens + elapsed * self.rate).min(burst);
        st.updated = now;

        let mut in_flight = st.in_flight.lock();
        if *in_flight >= self.max_concurrency {
            return Err(Wait::Concurrency);
        }
        if st.tokens < 1.0 {
            return Err(Wait::Rate(Duration::from_secs_f64((1.0 - st.tokens) / self.rate)));
        }
        st.tokens -= 1.0;
        *in_flight += 1;
        Ok(Permit { in_flight: st.in_flight.clone() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_rate_and_refills() {
        let rl = RateLimiter::new(2.0, 100);
        let t0 = Instant::now();
        let _a = rl.try_acquire("a.com", t0).unwrap();
        let _b = rl.try_acquire("A.com", t0).unwrap();
        assert!(matches!(rl.try_acquire("a.com", t0), Err(Wait::Rate(_))));
        // Other hosts have their own bucket.
        assert!(rl.try_acquire("b.com", t0).is_ok());
        assert!(rl.try_acquire("a.com", t0 + Duration::from_millis(500)).is_ok());
    }

    #[test]
    fn enforces_concurrency_and_releases_on_drop() {
        let rl = RateLimiter::new(1000.0, 1);
        let t0 = Instant::now();
        let p = rl.try_acquire("a.com", t0).unwrap();
        assert_eq!(rl.try_acquire("a.com", t0).unwrap_err(), Wait::Concurrency);
        drop(p);
        assert!(rl.try_acquire("a.com", t0).is_ok());
    }
}
