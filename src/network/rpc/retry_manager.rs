/// Retry manager for critical messages with exponential backoff
///
/// This module handles automatic retries for critical consensus messages that must
/// reach all nodes in the network. It uses exponential backoff to avoid overwhelming
/// the network and tracks acknowledgments from all nodes.
use anyhow::{anyhow, Result};
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::types::{ChannelMessage, GossipsubMessage};

// For production jitter in retry delays
use rand::Rng;

/// Message identifier for tracking retries
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageId {
    pub message_type: CriticalMessageType,
    pub unique_id: String, // Unique identifier for this specific message instance
}

/// Types of critical messages that need retry
/// Reduced from 7 to 5 types - removed SELECT messages that have ACK/MISSING fallback
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CriticalMessageType {
    TransactionIdBroadcast,
    VrfSelectedNodes,
}

/// State of a message retry
#[derive(Debug, Clone)]
struct RetryState {
    #[allow(dead_code)] // Used in logging and debugging
    message_id: MessageId,
    topic: String,
    data: Vec<u8>,
    expected_nodes: HashSet<PeerId>,
    acknowledged_nodes: HashSet<PeerId>,
    retry_count: u8,
    first_sent_at: Instant,
    last_retry_at: Option<Instant>,
}

/// Retry manager for critical messages
pub struct RetryManager {
    /// Active retry states keyed by message ID
    active_retries: Arc<RwLock<HashMap<MessageId, RetryState>>>,
    /// Channel to send retry messages
    message_tx: tokio::sync::mpsc::Sender<ChannelMessage>,
}

impl RetryManager {
    pub fn new(message_tx: tokio::sync::mpsc::Sender<ChannelMessage>) -> Self {
        Self {
            active_retries: Arc::new(RwLock::new(HashMap::new())),
            message_tx,
        }
    }

    /// Check if a message type is critical and needs retry
    /// Reduced from 7 to 5 types - SELECT messages have ACK/MISSING fallback
    pub fn is_critical_message(msg: &GossipsubMessage) -> Option<CriticalMessageType> {
        match msg {
            GossipsubMessage::TransactionIdBroadcast { .. } => {
                Some(CriticalMessageType::TransactionIdBroadcast)
            }
            GossipsubMessage::VrfSelectedNodes(_) => Some(CriticalMessageType::VrfSelectedNodes),
            _ => None,
        }
    }

    /// Generate a unique ID for a message based on its content
    pub fn generate_message_id(
        msg_type: CriticalMessageType,
        msg: &GossipsubMessage,
    ) -> Result<MessageId> {
        let unique_id = match msg {
            GossipsubMessage::TransactionIdBroadcast { transaction_id, .. } => {
                transaction_id.clone()
            }
            GossipsubMessage::VrfSelectedNodes(broadcast) => {
                format!("vrf_{}_{}", broadcast.round, broadcast.selector_node_id.0)
            }
            _ => return Err(anyhow!("Not a critical message type")),
        };

        Ok(MessageId {
            message_type: msg_type,
            unique_id,
        })
    }

    /// Register a critical message for retry tracking
    pub async fn register_message(
        &self,
        message_id: MessageId,
        topic: String,
        data: Vec<u8>,
        expected_nodes: HashSet<PeerId>,
    ) -> Result<()> {
        // Validate inputs
        if topic.is_empty() {
            return Err(anyhow!("Topic cannot be empty"));
        }
        if data.is_empty() {
            return Err(anyhow!("Message data cannot be empty"));
        }
        if expected_nodes.is_empty() {
            // No nodes to wait for, consider it successful immediately
            debug!(
                "ℹ️ [RETRY] No expected nodes for {:?}, skipping retry registration",
                message_id
            );
            return Ok(());
        }

        let state = RetryState {
            message_id: message_id.clone(),
            topic,
            data,
            expected_nodes: expected_nodes.clone(),
            acknowledged_nodes: HashSet::new(),
            retry_count: 0,
            first_sent_at: Instant::now(),
            last_retry_at: None,
        };

        let mut retries = self.active_retries.write().await;

        // Check if message is already being tracked (shouldn't happen, but be safe)
        if retries.contains_key(&message_id) {
            debug!(
                "⚠️ [RETRY] Message {:?} already registered, updating state",
                message_id
            );
        }

        retries.insert(message_id.clone(), state);

        debug!(
            "🔄 [RETRY] Registered critical message for retry: {:?} (expecting {} nodes)",
            message_id,
            expected_nodes.len()
        );

        // Log which nodes we're expecting ACKs from
        let expected_list: Vec<String> = expected_nodes.iter().map(|p| p.to_string()).collect();
        debug!(
            "📋 [RETRY] Expected nodes for {:?}: {:?}",
            message_id, expected_list
        );

        // Start the retry monitoring task
        let retries_clone = self.active_retries.clone();
        let message_tx_clone = self.message_tx.clone();
        let msg_id_clone = message_id.clone();

        tokio::spawn(async move {
            Self::monitor_and_retry(retries_clone, message_tx_clone, msg_id_clone).await;
        });

        Ok(())
    }

    /// Record an acknowledgment from a node
    /// Returns: Ok(true) if all nodes acknowledged, Ok(false) if still waiting, Err if failed
    /// Production: This is a critical path - must be fast and reliable
    pub async fn record_acknowledgment(
        &self,
        message_id: &MessageId,
        node_id: PeerId,
    ) -> Result<bool> {
        // Production: Add timeout to prevent hanging on lock acquisition
        let lock_timeout = Duration::from_secs(5);
        let mut retries = match tokio::time::timeout(lock_timeout, self.active_retries.write())
            .await
        {
            Ok(guard) => guard,
            Err(_) => {
                debug!(
                    "❌ [RETRY] CRITICAL: Timeout acquiring write lock for ACK recording (>{}s)",
                    lock_timeout.as_secs()
                );
                debug!("❌ [RETRY] This indicates lock contention or deadlock - investigate immediately");
                return Err(anyhow!("Timeout acquiring retry state lock"));
            }
        };

        if let Some(state) = retries.get_mut(message_id) {
            // Verify the node is actually expected (security check)
            if !state.expected_nodes.contains(&node_id) {
                debug!(
                    "⚠️ [RETRY] Received ACK from unexpected node {} for {:?}",
                    node_id, message_id
                );
                return Ok(false);
            }

            if state.acknowledged_nodes.insert(node_id) {
                let acked_count = state.acknowledged_nodes.len();
                let expected_count = state.expected_nodes.len();
                let missing_count = expected_count - acked_count;

                debug!(
                    "✅ [RETRY] Received ACK for {:?} from {} ({}/{})",
                    message_id, node_id, acked_count, expected_count
                );

                // Log which nodes are still missing
                if missing_count > 0 {
                    let missing_nodes: Vec<String> = state
                        .expected_nodes
                        .difference(&state.acknowledged_nodes)
                        .map(|p| p.to_string())
                        .collect();
                    debug!(
                        "⏳ [RETRY] Still waiting for ACKs from {} nodes: {:?}",
                        missing_count, missing_nodes
                    );
                }

                // Check if all nodes have acknowledged
                if acked_count >= expected_count {
                    debug!(
                        "🎉 [RETRY] All nodes acknowledged {:?}, removing from retry queue",
                        message_id
                    );
                    retries.remove(message_id);
                    return Ok(true); // All acknowledged
                }
                return Ok(false); // Still waiting
            } else {
                // Duplicate ACK - this is fine, just log at debug level
                debug!(
                    "🔄 [RETRY] Duplicate ACK from {} for {:?}",
                    node_id, message_id
                );
                return Ok(false);
            }
        }

        // Message not in retry queue (already completed or never registered)
        // This is normal - message might have been completed or sender didn't register it
        Ok(false)
    }

    /// Mark a peer as unreachable for all active retries
    pub async fn mark_peer_unreachable(&self, peer_id: PeerId) {
        let removed_count = Self::remove_peer_from_retries(&self.active_retries, &peer_id).await;
        if removed_count > 0 {
            debug!(
                "⚠️ [RETRY] Marked peer {} unreachable for {} active retries",
                peer_id, removed_count
            );
        }
    }

    /// Helper: Check if message type is VRF-related (needs aggressive retry)
    fn is_vrf_message(msg_type: &CriticalMessageType) -> bool {
        matches!(
            msg_type,
            CriticalMessageType::VrfSelectedNodes
        )
    }

    async fn remove_peer_from_retries(
        retries: &Arc<RwLock<HashMap<MessageId, RetryState>>>,
        peer_id: &PeerId,
    ) -> usize {
        let mut retries_guard = retries.write().await;
        let mut completed_messages = Vec::new();
        let mut removed_count = 0;

        for (message_id, state) in retries_guard.iter_mut() {
            if state.expected_nodes.remove(peer_id) {
                removed_count += 1;
                warn!(
                    "⚠️ [RETRY] Removing unreachable peer {} from expected set for {:?}",
                    peer_id, message_id
                );

                if state.acknowledged_nodes.len() >= state.expected_nodes.len() {
                    completed_messages.push(message_id.clone());
                }
            }
        }

        for message_id in completed_messages {
            retries_guard.remove(&message_id);
        }

        removed_count
    }

    /// Monitor a message and retry if needed
    /// Production configuration: Separate parameters for VRF (aggressive) vs others (standard)
    async fn monitor_and_retry(
        retries: Arc<RwLock<HashMap<MessageId, RetryState>>>,
        message_tx: tokio::sync::mpsc::Sender<ChannelMessage>,
        message_id: MessageId,
    ) {
        // VRF-SPECIFIC CONFIG: Extremely aggressive to ensure consensus
        // VRF messages MUST be delivered fast or consensus splits occur
        const VRF_INITIAL_WAIT: Duration = Duration::from_millis(500); // Only 500ms wait for VRF
        const VRF_MAX_RETRIES: u8 = 10; // More retries for critical VRF
        const VRF_BACKOFF_DELAYS: [Duration; 10] = [
            Duration::from_millis(100), // 1st retry: 100ms (ultra-fast)
            Duration::from_millis(200), // 2nd retry: 200ms
            Duration::from_millis(300), // 3rd retry: 300ms
            Duration::from_millis(500), // 4th retry: 500ms
            Duration::from_millis(500), // 5th retry: 500ms
            Duration::from_secs(1),     // 6th retry: 1s
            Duration::from_secs(1),     // 7th retry: 1s
            Duration::from_secs(2),     // 8th retry: 2s
            Duration::from_secs(2),     // 9th retry: 2s
            Duration::from_secs(3),     // 10th retry: 3s
        ];
        // VRF Total time: 500ms initial + 11.1s retries = ~12s (5x faster than standard!)

        // STANDARD CONFIG: For non-VRF critical messages
        const STANDARD_INITIAL_WAIT: Duration = Duration::from_secs(3);
        const STANDARD_MAX_RETRIES: u8 = 7;
        const STANDARD_BACKOFF_DELAYS: [Duration; 7] = [
            Duration::from_secs(1),  // 1st retry: 1 second
            Duration::from_secs(2),  // 2nd retry: 2 seconds
            Duration::from_secs(3),  // 3rd retry: 3 seconds
            Duration::from_secs(5),  // 4th retry: 5 seconds
            Duration::from_secs(8),  // 5th retry: 8 seconds
            Duration::from_secs(13), // 6th retry: 13 seconds
            Duration::from_secs(21), // 7th retry: 21 seconds
        ];
        // Standard Total time: 3s initial + 53s retries = 56s max

        // Select parameters based on message type
        let is_vrf = Self::is_vrf_message(&message_id.message_type);
        let initial_wait = if is_vrf {
            VRF_INITIAL_WAIT
        } else {
            STANDARD_INITIAL_WAIT
        };
        let max_retries = if is_vrf {
            VRF_MAX_RETRIES
        } else {
            STANDARD_MAX_RETRIES
        };

        let msg_type_str = if is_vrf {
            "VRF (aggressive)"
        } else {
            "standard"
        };

        // Wait for initial ACKs
        info!(
            "⏰ [RETRY] Starting {} monitoring for {:?} - waiting {:?} for initial ACKs",
            msg_type_str, message_id, initial_wait
        );
        tokio::time::sleep(initial_wait).await;

        // Retry loop with exponential backoff + jitter for production robustness
        for retry_attempt in 0..max_retries {
            let (needs_retry, state_opt) = {
                let retries_guard = retries.read().await;
                if let Some(state) = retries_guard.get(&message_id) {
                    let all_acked = state.acknowledged_nodes.len() >= state.expected_nodes.len();
                    if all_acked {
                        // All nodes acknowledged, we're done
                        return;
                    }

                    let missing_count = state.expected_nodes.len() - state.acknowledged_nodes.len();
                    (true, Some((state.clone(), missing_count)))
                } else {
                    // Message was removed (all acknowledged or manually removed)
                    return;
                }
            };

            if !needs_retry {
                return;
            }

            if let Some((state, missing_count)) = state_opt {
                warn!(
                    "⚠️ [RETRY] Retry attempt {} for {:?}: {} nodes still missing ACKs",
                    retry_attempt + 1,
                    message_id,
                    missing_count
                );

                // Update retry state
                let retry_count = {
                    let mut retries_guard = retries.write().await;
                    if let Some(state_mut) = retries_guard.get_mut(&message_id) {
                        state_mut.retry_count += 1;
                        state_mut.last_retry_at = Some(Instant::now());
                        state_mut.retry_count
                    } else {
                        // Message was removed
                        return;
                    }
                };

                let missing_peers: Vec<PeerId> = state
                    .expected_nodes
                    .difference(&state.acknowledged_nodes)
                    .cloned()
                    .collect();

                info!(
                    "🔄 [RETRY] Sending {} retry unicast for {:?} (attempt {}/{}) to {} peers",
                    msg_type_str,
                    message_id,
                    retry_attempt + 1,
                    max_retries,
                    missing_peers.len()
                );

                let message_type = format!("{:?}", state.message_id.message_type);
                let message_id_str = state.message_id.unique_id.clone();

                for peer_id in missing_peers {
                    let retry_msg = ChannelMessage::UnicastCritical {
                        target_peer_id: peer_id.to_string(),
                        topic: state.topic.clone(),
                        data: state.data.clone(),
                        message_type: message_type.clone(),
                        message_id: message_id_str.clone(),
                        retry_count,
                    };

                    match message_tx.try_send(retry_msg) {
                        Ok(_) => {
                            info!(
                                "✅ [RETRY] Unicast retry sent to {} for {:?} (attempt {}/{})",
                                peer_id,
                                message_id,
                                retry_attempt + 1,
                                max_retries
                            );
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            warn!("⚠️ [RETRY] Channel full - retry queued for next cycle");
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            error!("❌ [RETRY] CRITICAL: Channel closed - cannot send retries!");
                            error!("❌ [RETRY] System is shutting down or channel was dropped");
                            return;
                        }
                    }
                }

                // Wait for backoff period before next retry (with jitter for production)
                let retry_idx = retry_attempt as usize;

                // Select appropriate backoff delays based on message type
                let base_delay = if is_vrf {
                    if retry_idx < VRF_BACKOFF_DELAYS.len() {
                        VRF_BACKOFF_DELAYS[retry_idx]
                    } else {
                        VRF_BACKOFF_DELAYS[VRF_BACKOFF_DELAYS.len() - 1]
                    }
                } else {
                    if retry_idx < STANDARD_BACKOFF_DELAYS.len() {
                        STANDARD_BACKOFF_DELAYS[retry_idx]
                    } else {
                        STANDARD_BACKOFF_DELAYS[STANDARD_BACKOFF_DELAYS.len() - 1]
                    }
                };

                // Add jitter (0-20% of base delay) to prevent thundering herd problem
                // For VRF messages, use less jitter (0-10%) for more predictable timing
                let jitter_ms = {
                    let mut rng = rand::thread_rng();
                    let jitter_factor: f64 = if is_vrf {
                        rng.gen_range(0.0..0.1) // 0-10% jitter for VRF
                    } else {
                        rng.gen_range(0.0..0.2) // 0-20% jitter for others
                    };
                    (base_delay.as_millis() as f64 * jitter_factor) as u64
                };
                let delay_with_jitter = base_delay + Duration::from_millis(jitter_ms);

                info!(
                        "⏳ [RETRY] {} waiting {:?} (base: {:?} + jitter: {}ms) before retry {} for {:?}",
                        msg_type_str, delay_with_jitter, base_delay, jitter_ms, retry_attempt + 2, message_id
                    );
                tokio::time::sleep(delay_with_jitter).await;
            }
        }

        // After all retries, check final state and log comprehensive failure information
        let final_state = {
            let retries_guard = retries.read().await;
            retries_guard.get(&message_id).cloned()
        };

        if let Some(state) = final_state {
            let missing_count = state.expected_nodes.len() - state.acknowledged_nodes.len();
            if missing_count > 0 {
                let total_time = state.first_sent_at.elapsed();
                let ack_rate = (state.acknowledged_nodes.len() as f64
                    / state.expected_nodes.len() as f64)
                    * 100.0;

                error!("❌ [RETRY] DELIVERY FAILURE for {:?}", message_id);
                error!(
                    "❌ [RETRY] Failed to deliver to {} of {} nodes ({:.1}% success rate)",
                    missing_count,
                    state.expected_nodes.len(),
                    ack_rate
                );
                error!(
                    "❌ [RETRY] Total attempts: {} retries over {:?}",
                    max_retries, total_time
                );

                // Log which nodes are missing with detailed information
                let missing_nodes: Vec<PeerId> = state
                    .expected_nodes
                    .difference(&state.acknowledged_nodes)
                    .cloned()
                    .collect();
                error!(
                    "❌ [RETRY] Missing ACKs from {} nodes: {:?}",
                    missing_nodes.len(),
                    missing_nodes
                );

                // Production: Log actionable information for operators
                warn!("⚠️ [RETRY] ACTION REQUIRED: Investigate connectivity to missing nodes");
                warn!("⚠️ [RETRY] This may indicate network partitioning or node failures");

                // Log acknowledged nodes for comparison
                let acked_nodes: Vec<_> = state.acknowledged_nodes.iter().collect();
                info!(
                    "✅ [RETRY] Successfully received ACKs from {} nodes: {:?}",
                    acked_nodes.len(),
                    acked_nodes
                );
            } else {
                // All nodes acknowledged - success!
                info!(
                    "🎉 [RETRY] Successfully delivered {:?} to all {} nodes in {:?}",
                    message_id,
                    state.expected_nodes.len(),
                    state.first_sent_at.elapsed()
                );
            }

            // Remove from retry queue
            let mut retries_guard = retries.write().await;
            retries_guard.remove(&message_id);
        }
    }

    /// Check if a message is already being tracked (to avoid duplicate registration on retries)
    pub async fn is_message_tracked(&self, message_id: &MessageId) -> bool {
        let retries = self.active_retries.read().await;
        retries.contains_key(message_id)
    }

    /// Get the current retry state for a message (for debugging)
    pub async fn get_retry_state(&self, message_id: &MessageId) -> Option<(usize, usize, u8)> {
        let retries = self.active_retries.read().await;
        retries.get(message_id).map(|state| {
            (
                state.acknowledged_nodes.len(),
                state.expected_nodes.len(),
                state.retry_count,
            )
        })
    }
}
