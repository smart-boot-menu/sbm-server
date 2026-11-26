use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Limiter {
    inner: std::sync::Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl Limiter {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn allow(&self, key: &str, limit: usize, window: Duration) -> bool {
        let mut guard = self.inner.lock().expect("rate limiter lock");
        let now = Instant::now();
        let hits = guard.entry(key.to_string()).or_default();
        hits.retain(|t| now.duration_since(*t) < window);
        if hits.len() >= limit {
            return false;
        }
        hits.push(now);
        true
    }
}

impl Default for Limiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_blocks_the_burst() {
        let limiter = Limiter::new();
        assert!(limiter.allow("k", 2, Duration::from_secs(60)));
        assert!(limiter.allow("k", 2, Duration::from_secs(60)));
        assert!(!limiter.allow("k", 2, Duration::from_secs(60)));
    }
}
