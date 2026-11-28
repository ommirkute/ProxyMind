//! Time as a dependency, so tests of expiry and back-off never sleep.

use std::sync::atomic::{AtomicI64, Ordering};

/// Seconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}

/// A clock that only moves when told to.
#[derive(Debug)]
pub struct ManualClock(AtomicI64);

impl ManualClock {
    pub fn new(start: i64) -> Self {
        Self(AtomicI64::new(start))
    }

    pub fn set(&self, t: i64) {
        self.0.store(t, Ordering::SeqCst);
    }

    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
