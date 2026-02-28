pub mod dkg_gossip;
pub mod signature_gossip;
pub mod intent_gossip;
pub mod system_gossip;

use crate::network::transport::types::MpcNetworkLayer;
use libp2p::gossipsub::Message;
use anyhow::Result;
use tracing::{debug, warn};
use crate::types::GossipsubMessage;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use crate::types::ChannelMessage;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PendingAddLiquidityRecord {
    pub(crate) request_id: String,
    pub(crate) solver_id: String,
    pub(crate) solver_address: String,
    pub(crate) amount: String,
    pub(crate) chain_id: u64,
    pub(crate) signature: String,
    pub(crate) signed_payload: String,
    pub(crate) timestamp_ms: i64,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) tx_id: Option<String>,
}

pub(crate) const ADD_LIQUIDITY_DB_PREFIX: &str = "solver_add_liquidity:";
pub(crate) const MIN_CLAIM_TICS_WEI: u64 = 1_000_000_000_000_000_000;

impl MpcNetworkLayer {
    pub(crate) async fn handle_gossipsub_message(&mut self, message: &Message) -> Result<()> {
        let msg = match serde_json::from_slice::<GossipsubMessage>(&message.data) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Failed to deserialize gossipsub message: {:?}", e);
                return Ok(());
            }
        };
        match msg {
            GossipsubMessage::DKG(inner) => {
                self.handle_dkg(message, GossipsubMessage::DKG(inner)).await?
            }
            GossipsubMessage::UserRegistration { .. } => {
                self.handle_userregistration(message, msg).await?
            }
            GossipsubMessage::AdminRegistration { .. } => {
                self.handle_adminregistration(message, msg).await?
            }
            GossipsubMessage::DepositIntent { .. } => {
                self.handle_depositintent(message, msg).await?
            }
            GossipsubMessage::SolverAddLiquidity { .. } => {
                self.handle_solveraddliquidity(message, msg).await?
            }
            GossipsubMessage::TicsUserToVaultIntentBatch { .. } => {
                self.handle_ticsusertovaultintentbatch(message, msg).await?
            }
            GossipsubMessage::BtcUserToVaultIntentBatch { .. } => {
                self.handle_btcusertovaultintentbatch(message, msg).await?
            }
            GossipsubMessage::BtcWithdrawBatch { .. } => {
                self.handle_btcwithdrawbatch(message, msg).await?
            }
            GossipsubMessage::TicsWithdrawBatch { .. } => {
                self.handle_ticswithdrawbatch(message, msg).await?
            }
            GossipsubMessage::BtcClaimRewardBatch { .. } => {
                self.handle_btcclaimrewardbatch(message, msg).await?
            }
            GossipsubMessage::TicsClaimRewardBatch { .. } => {
                self.handle_ticsclaimrewardbatch(message, msg).await?
            }
            GossipsubMessage::BtcClaimPlatformFeeBatch { .. } => {
                self.handle_btcclaimplatformfeebatch(message, msg).await?
            }
            GossipsubMessage::TicsClaimPlatformFeeBatch { .. } => {
                self.handle_ticsclaimplatformfeebatch(message, msg).await?
            }
            GossipsubMessage::IntentBatchBroadcast { .. } => {
                self.handle_intentbatchbroadcast(message, msg).await?
            }
            GossipsubMessage::SolverAddLiquidityBatch { .. } => {
                self.handle_solveraddliquiditybatch(message, msg).await?
            }
            GossipsubMessage::WithdrawLiquidity { .. } => {
                self.handle_withdrawliquidity(message, msg).await?
            }
            GossipsubMessage::PendingWithdrawRequestBroadcast { .. } => {
                self.handle_pendingwithdrawrequestbroadcast(message, msg).await?
            }
            GossipsubMessage::PendingClaimPlatformFeeRequestBroadcast { .. } => {
                self.handle_pendingclaimplatformfeerequestbroadcast(message, msg).await?
            }
            GossipsubMessage::PendingClaimRewardRequestBroadcast { .. } => {
                self.handle_pendingclaimrewardrequestbroadcast(message, msg).await?
            }
            GossipsubMessage::WithdrawTxIdBroadcast { .. } => {
                self.handle_withdrawtxidbroadcast(message, msg).await?
            }
            GossipsubMessage::ClaimRewardTxIdBroadcast { .. } => {
                self.handle_claimrewardtxidbroadcast(message, msg).await?
            }
            GossipsubMessage::ClaimPlatformFeeTxIdBroadcast { .. } => {
                self.handle_claimplatformfeetxidbroadcast(message, msg).await?
            }
            GossipsubMessage::BtcIntentManagerTxUpdate { .. } => {
                self.handle_btcintentmanagertxupdate(message, msg).await?
            }
            GossipsubMessage::Command(inner) => {
                self.handle_command(message, GossipsubMessage::Command(inner)).await?
            }
            GossipsubMessage::TransactionIdBroadcast { .. } => {
                self.handle_transactionidbroadcast(message, msg).await?
            }
            GossipsubMessage::FinalNodeIdBroadcast { .. } => {
                self.handle_finalnodeidbroadcast(message, msg).await?
            }
            GossipsubMessage::TransactionErrorBroadcast { .. } => {
                self.handle_transactionerrorbroadcast(message, msg).await?
            }
            GossipsubMessage::PeerInvalidationDeleted { .. } => {
                self.handle_peerinvalidationdeleted(message, msg).await?
            }
            GossipsubMessage::PeerDiscovered { .. } => {
                self.handle_peerdiscovered(message, msg).await?
            }
            GossipsubMessage::CriticalMessageAck { .. } => {
                self.handle_criticalmessageack(message, msg).await?
            }
            GossipsubMessage::TransactionBroadcast { .. } => {
                self.handle_transactionbroadcast(message, msg).await?
            }
            GossipsubMessage::PeerDisconnection { .. } => {
                self.handle_peerdisconnection(message, msg).await?
            }
            GossipsubMessage::PeerInvalidationBatch { .. } => {
                self.handle_peerinvalidationbatch(message, msg).await?
            }
            GossipsubMessage::TransactionFailure { .. } => {
                self.handle_transactionfailure(message, msg).await?
            }
            GossipsubMessage::ActivePeerList { .. } => {
                self.handle_activepeerlist(message, msg).await?
            }
            GossipsubMessage::Signing(inner) => {
                self.handle_signing(message, GossipsubMessage::Signing(inner)).await?
            }
            GossipsubMessage::Consensus(inner) => {
                self.handle_consensus(message, GossipsubMessage::Consensus(inner)).await?
            }
            GossipsubMessage::VrfSelection(inner) => {
                self.handle_vrfselection(message, GossipsubMessage::VrfSelection(inner)).await?
            }
            GossipsubMessage::VrfSelectedNodes(inner) => {
                self.handle_vrfselectednodes(message, GossipsubMessage::VrfSelectedNodes(inner)).await?
            }
            GossipsubMessage::VrfRoundSyncRequest(inner) => {
                self.handle_vrfroundsyncrequest(message, GossipsubMessage::VrfRoundSyncRequest(inner)).await?
            }
            GossipsubMessage::VrfRoundSyncResponse(inner) => {
                self.handle_vrfroundsyncresponse(message, GossipsubMessage::VrfRoundSyncResponse(inner)).await?
            }
            GossipsubMessage::NonceTupleBroadcast { .. } => {
                self.handle_noncetuplebroadcast(message, msg).await?
            }
            GossipsubMessage::NonceInvalidation { .. } => {
                self.handle_nonceinvalidation(message, msg).await?
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) async fn send_critical_message_ack(
        &self,
        msg_type: crate::network::rpc::retry_manager::CriticalMessageType,
        msg: &GossipsubMessage,
    ) {
        debug!("🔍 [RETRY] Starting ACK generation for message type: {:?}", msg_type);
        let gen_timeout = Duration::from_secs(2);
        let message_id = match tokio::time::timeout(gen_timeout, async {
            crate::network::rpc::retry_manager::RetryManager::generate_message_id(
                msg_type.clone(),
                msg,
            )
        })
        .await
        {
            Ok(Ok(id)) => id,
            Ok(Err(e)) => {
                debug!("❌ [RETRY] Failed to generate message ID for ACK: {}", e);
                return;
            }
            Err(_) => {
                debug!("❌ [RETRY] Timeout generating message ID");
                return;
            }
        };

        let unique_id = message_id.unique_id.clone();
        let ack_msg = GossipsubMessage::CriticalMessageAck {
            message_type: format!("{:?}", msg_type),
            message_id: unique_id.clone(),
            node_id: self.local_peer_id,
        };

        let topic = match msg_type {
            crate::network::rpc::retry_manager::CriticalMessageType::TransactionIdBroadcast => {
                crate::network::transport::types::TOPIC_TRANSACTION_SYNC
            }
            crate::network::rpc::retry_manager::CriticalMessageType::FinalNodeIdBroadcast => {
                crate::network::transport::types::TOPIC_TRANSACTION_SYNC
            }
        };

        let data = match serde_json::to_vec(&ack_msg) {
            Ok(d) => d,
            Err(e) => {
                debug!("❌ [RETRY] Failed to serialize ACK message: {}", e);
                return;
            }
        };

        match self.message_tx.try_send(ChannelMessage::Broadcast {
            topic: topic.to_string(),
            data,
        }) {
            Ok(_) => {
                self.channel_health.record_send_success();
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.channel_health.record_send_full();
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.channel_health.record_send_closed();
            }
        }
        self.channel_health.health_check();
    }
}
