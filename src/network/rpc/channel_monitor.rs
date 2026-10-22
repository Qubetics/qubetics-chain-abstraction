/// Channel health monitoring for production systems
/// 
/// This module provides utilities to monitor channel health and detect
/// potential issues before they cause failures.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Tracks channel health metrics
#[derive(Clone)]
pub struct ChannelHealthMonitor {
    /// Total messages sent successfully
    pub messages_sent: Arc<AtomicU64>,
    /// Total messages that failed due to full channel
    pub messages_dropped_full: Arc<AtomicU64>,
    /// Total messages that failed due to closed channel
    pub messages_dropped_closed: Arc<AtomicU64>,
    /// Last health check timestamp
    pub last_health_check: Arc<AtomicU64>,
}

impl ChannelHealthMonitor {
    pub fn new() -> Self {
        Self {
            messages_sent: Arc::new(AtomicU64::new(0)),
            messages_dropped_full: Arc::new(AtomicU64::new(0)),
            messages_dropped_closed: Arc::new(AtomicU64::new(0)),
            last_health_check: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Record a successful send
    pub fn record_send_success(&self) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed send due to full channel
    pub fn record_send_full(&self) {
        let count = self.messages_dropped_full.fetch_add(1, Ordering::Relaxed) + 1;
        
        // Alert if we're dropping messages frequently
        if count % 10 == 0 {
            warn!(
                "⚠️ [CHANNEL_HEALTH] Channel full - dropped {} messages total",
                count
            );
            warn!("⚠️ [CHANNEL_HEALTH] Consider increasing channel capacity");
        }
        
        // Critical alert if drop rate is very high
        let sent = self.messages_sent.load(Ordering::Relaxed);
        if sent > 100 && count > sent / 10 {
            error!(
                "❌ [CHANNEL_HEALTH] CRITICAL: High drop rate - {}/{} messages dropped ({}%)",
                count, sent, (count * 100) / sent
            );
            error!("❌ [CHANNEL_HEALTH] System is overloaded - increase channel capacity immediately");
        }
    }

    /// Record a failed send due to closed channel
    pub fn record_send_closed(&self) {
        let count = self.messages_dropped_closed.fetch_add(1, Ordering::Relaxed) + 1;
        error!(
            "❌ [CHANNEL_HEALTH] Channel closed - {} messages dropped",
            count
        );
        error!("❌ [CHANNEL_HEALTH] System is shutting down or channel was dropped");
    }

    /// Get current health statistics
    pub fn get_stats(&self) -> ChannelStats {
        ChannelStats {
            sent: self.messages_sent.load(Ordering::Relaxed),
            dropped_full: self.messages_dropped_full.load(Ordering::Relaxed),
            dropped_closed: self.messages_dropped_closed.load(Ordering::Relaxed),
        }
    }

    /// Perform health check and log if needed
    pub fn health_check(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let last_check = self.last_health_check.load(Ordering::Relaxed);
        
        // Perform health check every 60 seconds
        if now - last_check > 60 {
            self.last_health_check.store(now, Ordering::Relaxed);
            
            let stats = self.get_stats();
            let total = stats.sent + stats.dropped_full + stats.dropped_closed;
            
            if total > 0 {
                let success_rate = (stats.sent * 100) / total;
                
                if success_rate < 95 {
                    error!(
                        "❌ [CHANNEL_HEALTH] Poor health: {}% success rate ({} sent, {} dropped)",
                        success_rate, stats.sent, stats.dropped_full + stats.dropped_closed
                    );
                } else if success_rate < 99 {
                    warn!(
                        "⚠️ [CHANNEL_HEALTH] Degraded health: {}% success rate ({} sent, {} dropped)",
                        success_rate, stats.sent, stats.dropped_full + stats.dropped_closed
                    );
                } else {
                    info!(
                        "✅ [CHANNEL_HEALTH] Good health: {}% success rate ({} sent, {} dropped)",
                        success_rate, stats.sent, stats.dropped_full + stats.dropped_closed
                    );
                }
            }
        }
    }
}

impl Default for ChannelHealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ChannelStats {
    pub sent: u64,
    pub dropped_full: u64,
    pub dropped_closed: u64,
}

impl ChannelStats {
    pub fn success_rate(&self) -> f64 {
        let total = self.sent + self.dropped_full + self.dropped_closed;
        if total == 0 {
            100.0
        } else {
            (self.sent as f64 / total as f64) * 100.0
        }
    }

    pub fn total_dropped(&self) -> u64 {
        self.dropped_full + self.dropped_closed
    }
}

