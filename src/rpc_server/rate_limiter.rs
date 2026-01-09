use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::warn;

/// Rate limiter using a sliding window approach
pub struct RateLimiter {
    /// Map of IP address to request timestamps
    requests: Arc<DashMap<String, Arc<Mutex<Vec<Instant>>>>>,
    /// Maximum number of requests allowed per window
    max_requests: u32,
    /// Time window duration
    window_duration: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    /// * `max_requests` - Maximum number of requests allowed per window
    /// * `window_duration` - Time window duration
    pub fn new(max_requests: u32, window_duration: Duration) -> Self {
        Self {
            requests: Arc::new(DashMap::new()),
            max_requests,
            window_duration,
        }
    }

    /// Check if a request from the given IP should be allowed
    /// Returns true if allowed, false if rate limited
    pub async fn check(&self, ip: &str) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window_duration;

        // Get or create the entry for this IP
        let entry = self
            .requests
            .entry(ip.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(Vec::new())));

        let mut timestamps = entry.value().lock().await;

        // Remove timestamps outside the window
        timestamps.retain(|&ts| ts > cutoff);

        // Check if we're over the limit
        if timestamps.len() >= self.max_requests as usize {
            warn!(
                "🚫 [RATE_LIMIT] Rate limit exceeded for IP: {} ({} requests in window)",
                ip,
                timestamps.len()
            );
            return false;
        }

        // Add current request timestamp
        timestamps.push(now);
        true
    }

    /// Clean up old entries periodically (call this in a background task)
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let cutoff = now - self.window_duration;

        // Collect keys to remove (to avoid holding locks during iteration)
        let keys_to_remove: Vec<String> = {
            let mut to_remove = Vec::new();
            for entry in self.requests.iter() {
                let mut ts = entry.value().lock().await;
                ts.retain(|&t| t > cutoff);
                if ts.is_empty() {
                    to_remove.push(entry.key().clone());
                }
            }
            to_remove
        };

        // Remove empty entries
        for key in keys_to_remove {
            self.requests.remove(&key);
        }
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        Self {
            requests: self.requests.clone(),
            max_requests: self.max_requests,
            window_duration: self.window_duration,
        }
    }
}
