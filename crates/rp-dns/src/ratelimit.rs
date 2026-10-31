//! Per-client token bucket.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

pub struct RateLimiter {
    rate: f64,
    burst: f64,
    buckets: HashMap<IpAddr, (f64, Instant)>,
}

impl RateLimiter {
    /// `qps` sustained queries per second, bursts up to twice that.
    pub fn new(qps: u32) -> Self {
        let rate = f64::from(qps.max(1));
        Self { rate, burst: rate * 2.0, buckets: HashMap::new() }
    }

    pub fn allow(&mut self, client: IpAddr, now: Instant) -> bool {
        if self.buckets.len() > 10_000 {
            // Forget idle clients so the table can't grow without bound.
            let rate = self.rate;
            let burst = self.burst;
            self.buckets.retain(|_, (tokens, last)| {
                *tokens + now.duration_since(*last).as_secs_f64() * rate < burst
            });
        }
        let (tokens, last) = self.buckets.entry(client).or_insert((self.burst, now));
        *tokens = (*tokens + now.duration_since(*last).as_secs_f64() * self.rate).min(self.burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn allows_burst_then_limits_then_refills() {
        let mut r = RateLimiter::new(5);
        let t0 = Instant::now();
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let allowed = (0..20).filter(|_| r.allow(ip, t0)).count();
        assert_eq!(allowed, 10, "burst is 2x qps");
        assert!(!r.allow(ip, t0));
        assert!(r.allow(ip, t0 + Duration::from_millis(250)), "refills at qps");
        let other: IpAddr = "192.0.2.8".parse().unwrap();
        assert!(r.allow(other, t0), "clients are independent");
    }
}
