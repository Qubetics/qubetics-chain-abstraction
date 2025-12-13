use anyhow::Result;
use libp2p::PeerId;
use tracing::info;

use crate::types::p2p::SerializablePeerId;
use crate::types::rpc::RPCRequest;
use crate::types::vrf::VrfRoundSyncRequest;

use crate::network::transport::types::{MpcNetworkBehaviour, MpcNetworkLayer};

impl MpcNetworkLayer {
    /// Sync database from an existing peer when joining the network
    /// This method should be called by new nodes after connecting to the network
    pub async fn sync_database_from_peer(
        &self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        peer_id: PeerId,
    ) -> Result<()> {
        info!("📦 [DB_SYNC] Starting database sync from peer {}", peer_id);

        // Step 1: Request database metadata
        let request = RPCRequest::RequestDatabaseSync {
            requester_id: SerializablePeerId(self.local_peer_id),
        };

        let request_id = swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, request);

        info!(
            "📦 [DB_SYNC] Sent sync metadata request (ID: {:?})",
            request_id
        );

        // Note: The actual response handling happens in the swarm event loop
        // We need to handle DatabaseSyncMetadata and DatabaseBatch responses there
        Ok(())
    }

    /// Handle database sync metadata response and start batch requests
    pub async fn handle_database_sync_metadata(
        &mut self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        peer_id: PeerId,
        total_entries: usize,
        batch_size: usize,
    ) -> Result<()> {
        if total_entries == 0 {
            info!("📦 [DB_SYNC] Peer has no data to sync");
            return Ok(());
        }

        // Initialize sync state
        self.db_sync_state
            .start_sync(peer_id, total_entries, batch_size);

        let total_batches = total_entries.div_ceil(batch_size);
        info!(
            "📦 [DB_SYNC] Starting batch sync: {} entries in {} batches from peer {}",
            total_entries, total_batches, peer_id
        );
        info!("📊 [DB_SYNC] Progress: 0/{} entries (0.00%)", total_entries);

        // Request first batch - subsequent batches will be requested after receiving responses
        let request = RPCRequest::RequestDatabaseBatch {
            batch_index: 0,
            batch_size,
        };

        swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, request);

        info!("📦 [DB_SYNC] Requested batch 0/{}", total_batches - 1);
        Ok(())
    }

    /// Handle a batch of database entries
    pub async fn handle_database_batch(
        &mut self,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
        peer_id: PeerId,
        batch_index: usize,
        entries: Vec<crate::types::rpc::DatabaseEntry>,
        is_last_batch: bool,
        batch_size: usize,
    ) -> Result<()> {
        let entries_count = entries.len();

        info!(
            "📦 [DB_SYNC] Received batch {} with {} entries (last: {})",
            batch_index, entries_count, is_last_batch
        );

        // Convert entries to tuple format
        let db_entries: Vec<(Vec<u8>, Vec<u8>)> =
            entries.into_iter().map(|e| (e.key, e.value)).collect();

        // Import batch into database
        self.db.import_batch_async(db_entries).await?;

        // Update sync state
        self.db_sync_state.complete_batch(entries_count);

        let progress = self.db_sync_state.progress_percentage();
        info!(
            "✅ [DB_SYNC] Successfully imported batch {} - Progress: {}/{} entries ({:.2}%)",
            batch_index,
            self.db_sync_state.entries_synced,
            self.db_sync_state.total_entries,
            progress
        );

        // Request next batch if not last
        if !is_last_batch {
            let request = RPCRequest::RequestDatabaseBatch {
                batch_index: batch_index + 1,
                batch_size,
            };

            swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, request);

            info!(
                "📦 [DB_SYNC] Requested batch {}/{} from peer {}",
                batch_index + 1,
                self.db_sync_state.total_batches - 1,
                peer_id
            );
        } else {
            // Finish sync
            self.db_sync_state.finish_sync();
            info!("🎉 [DB_SYNC] Database synchronization completed!");
            info!(
                "📊 [DB_SYNC] Total synced: {} entries from peer {}",
                self.db_sync_state.entries_synced, peer_id
            );

            // Request VRF round sync after database sync completes
            if !self.vrf_round_requested {
                info!(
                    "🔄 [VRF_SYNC] Requesting current VRF round from peer {}",
                    peer_id
                );
                let current_round = self.get_local_vrf_round().await;
                swarm.behaviour_mut().request_response.send_request(
                    &peer_id,
                    RPCRequest::VrfRoundSync(VrfRoundSyncRequest {
                        from: SerializablePeerId(self.local_peer_id),
                        current_round,
                    }),
                );
                self.vrf_round_requested = true;
                info!("✅ [VRF_SYNC] VRF round request sent to peer {}", peer_id);
            }
        }

        Ok(())
    }
}
