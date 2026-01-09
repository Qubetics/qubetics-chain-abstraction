use crate::database::upgrade::CompatibilityMatrix;
/// Track network-wide version information
use anyhow::Result;
use chrono::Utc;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerVersionInfo {
    pub peer_id: PeerId,
    pub version: String,
    pub last_seen: i64,
    pub features: Vec<String>,
}

pub struct NetworkVersionTracker {
    peer_versions: Arc<RwLock<HashMap<PeerId, PeerVersionInfo>>>,
    compatibility_matrix: CompatibilityMatrix,
}

impl NetworkVersionTracker {
    pub fn new() -> Self {
        Self {
            peer_versions: Arc::new(RwLock::new(HashMap::new())),
            compatibility_matrix: CompatibilityMatrix::new(),
        }
    }

    /// Track a peer's version
    pub async fn track_peer_version(
        &self,
        peer_id: PeerId,
        version: String,
        features: Vec<String>,
    ) {
        let mut versions = self.peer_versions.write().await;

        let info = PeerVersionInfo {
            peer_id,
            version: version.clone(),
            last_seen: Utc::now().timestamp(),
            features,
        };

        versions.insert(peer_id, info);
        info!(
            "📍 [VERSION_TRACKER] Tracked peer {} version: {}",
            peer_id, version
        );
    }

    /// Remove peer from tracking
    pub async fn remove_peer(&self, peer_id: &PeerId) {
        let mut versions = self.peer_versions.write().await;
        versions.remove(peer_id);
        info!("🗑️  [VERSION_TRACKER] Removed peer: {}", peer_id);
    }

    /// Get version distribution across network
    pub async fn get_version_distribution(&self) -> HashMap<String, usize> {
        let versions = self.peer_versions.read().await;
        let version_list: Vec<String> =
            versions.values().map(|info| info.version.clone()).collect();

        self.compatibility_matrix
            .get_version_distribution(&version_list)
    }

    /// Get all peer versions
    pub async fn get_all_versions(&self) -> Vec<String> {
        let versions = self.peer_versions.read().await;
        versions.values().map(|info| info.version.clone()).collect()
    }

    /// Check if a specific version can join the network
    pub async fn can_version_join(&self, version: &str) -> Result<bool> {
        let network_versions = self.get_all_versions().await;
        self.compatibility_matrix
            .can_join_network(version, &network_versions)
    }

    /// Get minimum version in network
    pub async fn get_minimum_version(&self) -> Option<String> {
        let versions = self.get_all_versions().await;
        self.compatibility_matrix
            .get_minimum_network_version(&versions)
    }

    /// Get maximum version in network
    pub async fn get_maximum_version(&self) -> Option<String> {
        let versions = self.get_all_versions().await;
        self.compatibility_matrix
            .get_maximum_network_version(&versions)
    }

    /// Check if network has reached minimum threshold for a feature
    pub async fn is_feature_available(
        &self,
        required_version: &str,
        required_ratio: f64,
    ) -> Result<bool> {
        let versions = self.get_all_versions().await;
        self.compatibility_matrix
            .is_feature_available(&versions, required_version, required_ratio)
    }

    /// Get total peer count
    pub async fn get_peer_count(&self) -> usize {
        let versions = self.peer_versions.read().await;
        versions.len()
    }

    /// Get peers with specific version
    pub async fn get_peers_with_version(&self, version: &str) -> Vec<PeerId> {
        let versions = self.peer_versions.read().await;
        versions
            .values()
            .filter(|info| info.version == version)
            .map(|info| info.peer_id)
            .collect()
    }

    /// Check if all peers are on same version
    pub async fn is_network_uniform(&self) -> bool {
        let distribution = self.get_version_distribution().await;
        distribution.len() <= 1
    }

    /// Get detailed network version info
    pub async fn get_network_info(&self) -> NetworkVersionInfo {
        let versions = self.peer_versions.read().await;
        let distribution = self.compatibility_matrix.get_version_distribution(
            &versions
                .values()
                .map(|info| info.version.clone())
                .collect::<Vec<_>>(),
        );

        let all_versions: Vec<String> =
            versions.values().map(|info| info.version.clone()).collect();
        let min_version = self
            .compatibility_matrix
            .get_minimum_network_version(&all_versions);
        let max_version = self
            .compatibility_matrix
            .get_maximum_network_version(&all_versions);

        NetworkVersionInfo {
            total_peers: versions.len(),
            version_distribution: distribution,
            min_version,
            max_version,
            is_uniform: all_versions.windows(2).all(|w| w[0] == w[1]) && !all_versions.is_empty(),
        }
    }

    /// Clean up stale peer entries (not seen for 5 minutes)
    pub async fn cleanup_stale_peers(&self) {
        let mut versions = self.peer_versions.write().await;
        let now = Utc::now().timestamp();
        let stale_threshold = 300; // 5 minutes

        let stale_peers: Vec<PeerId> = versions
            .iter()
            .filter(|(_, info)| now - info.last_seen > stale_threshold)
            .map(|(peer_id, _)| *peer_id)
            .collect();

        for peer_id in &stale_peers {
            versions.remove(peer_id);
            warn!("🧹 [VERSION_TRACKER] Removed stale peer: {}", peer_id);
        }

        if !stale_peers.is_empty() {
            info!(
                "🧹 [VERSION_TRACKER] Cleaned up {} stale peers",
                stale_peers.len()
            );
        }
    }
}

impl Default for NetworkVersionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize)]
pub struct NetworkVersionInfo {
    pub total_peers: usize,
    pub version_distribution: HashMap<String, usize>,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub is_uniform: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_version_tracking() {
        let tracker = NetworkVersionTracker::new();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        // Track peers
        tracker
            .track_peer_version(peer1, "0.1.0".to_string(), vec![])
            .await;
        tracker
            .track_peer_version(peer2, "0.2.0".to_string(), vec![])
            .await;

        // Check distribution
        let distribution = tracker.get_version_distribution().await;
        assert_eq!(distribution.get("0.1.0"), Some(&1));
        assert_eq!(distribution.get("0.2.0"), Some(&1));

        // Check peer count
        assert_eq!(tracker.get_peer_count().await, 2);

        // Remove peer
        tracker.remove_peer(&peer1).await;
        assert_eq!(tracker.get_peer_count().await, 1);
    }
}
