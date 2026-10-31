//! Per-principal sliding-window rate limit.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub struct Limiter {
    per_minute: usize,
    hits: HashMap<String, VecDeque<Instant>>,
}

impl Limiter {
    pub fn new(per_minute: u32) -> Self {
        Self { per_minute: per_minute.max(1) as usize, hits: HashMap::new() }
    }

    pub fn allow(&mut self, who: &str, now: Instant) -> bool {
        let q = self.hits.entry(who.to_string()).or_default();
        while q.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60)) {
            q.pop_front();
        }
        if q.len() >= self.per_minute {
            return false;
        }
        q.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_limits_each_principal() {
        let mut l = Limiter::new(3);
        let t = Instant::now();
        assert!((0..3).all(|_| l.allow("a", t)));
        assert!(!l.allow("a", t));
        assert!(l.allow("b", t));
        assert!(l.allow("a", t + Duration::from_secs(61)));
    }
}
