use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct Clock {
    inner: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl Clock {
    pub fn system() -> Self {
        Self {
            inner: Arc::new(system_unix),
        }
    }

    pub fn manual(tick: Arc<AtomicI64>) -> Self {
        Self {
            inner: Arc::new(move || tick.load(Ordering::SeqCst)),
        }
    }

    pub fn unix(&self) -> i64 {
        (self.inner)()
    }
}

pub fn system_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
