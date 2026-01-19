use anyhow::Result;
use libp2p::identity::Keypair;
use libp2p::PeerId;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::database::{keys, KeyStore};

use crate::network::transport::types::MpcNetworkLayer;

impl MpcNetworkLayer {
    /// Load existing keypair from keystore or create a new one
    ///
    /// Accepts a KeyStore implementation (e.g., Database, remote KMS) to allow
    /// the MPC stack to control the identity lifecycle and swap storage backends
    /// without changing keypair management logic.
    pub async fn load_or_create_keypair(keystore: Arc<dyn KeyStore>) -> Result<(Keypair, PeerId)> {
        // Try to load existing keypair
        if let Some(keypair_bytes) = keystore.get_keypair(keys::PEER_KEYPAIR)? {
            match Keypair::from_protobuf_encoding(&keypair_bytes) {
                Ok(keypair) => {
                    let peer_id = PeerId::from(keypair.public());
                    info!("🔄 Loaded existing keypair - Peer ID: {}", peer_id);
                    return Ok((keypair, peer_id));
                }
                Err(e) => {
                    warn!(
                        "⚠️ Failed to decode existing keypair: {}. Generating new one.",
                        e
                    );
                }
            }
        } else {
            info!("🆕 No existing keypair found. Generating new one.");
        }

        // Generate new keypair
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        // Save keypair to keystore
        let keypair_bytes = keypair
            .to_protobuf_encoding()
            .map_err(|e| anyhow::anyhow!("Failed to encode keypair: {}", e))?;
        keystore.put_keypair(keys::PEER_KEYPAIR, &keypair_bytes)?;

        info!("✅ Generated and saved new keypair - Peer ID: {}", peer_id);
        Ok((keypair, peer_id))
    }

    /// Broadcast a user registration to all other nodes in the P2P network
    pub async fn broadcast_user_registration(
        &self,
        ethereum_address: &str,
        node_id: &str,
    ) -> Result<()> {
        use crate::types::{ChannelMessage, GossipsubMessage};

        let registration_msg = GossipsubMessage::UserRegistration {
            ethereum_address: ethereum_address.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            node_id: node_id.to_string(),
        };

        let msg_bytes = serde_json::to_vec(&registration_msg)
            .map_err(|e| anyhow::anyhow!("Failed to serialize user registration: {}", e))?;

        // Send via the message channel to be broadcast by the swarm
        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: "user-registrations".to_string(),
                data: msg_bytes,
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send user registration broadcast: {}", e))?;

        info!(
            "📡 Broadcasted user registration for {} from node {} to P2P network",
            ethereum_address, node_id
        );
        Ok(())
    }

    /// Broadcast a message to a specific topic
    pub async fn broadcast(&self, topic: &str, data: &[u8]) -> Result<()> {
        use crate::types::ChannelMessage;

        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: topic.to_string(),
                data: data.to_vec(),
            })
            .await?;
        Ok(())
    }

    /// Get the appropriate signing key based on the user eth address
    pub(crate) async fn get_signing_key_for_user(
        &self,
        user_eth_address: Option<&String>,
    ) -> Option<k256::Scalar> {
        if let Some(eth_address) = user_eth_address {
            // Use user-specific tweaked share
            info!(
                "🔑 [NETWORK] Using user-specific tweaked share for signing - User: {}",
                eth_address
            );

            if let Some(user_intent_manager) = &self.user_intent_manager {
                match user_intent_manager.get_user_by_address(eth_address).await {
                    Some(user) => {
                        if let Some(tweaked_share) = &user.tweaked_secret_share {
                            let share_scalar = tweaked_share.0;
                            // Derive pubkey from this scalar for debug
                            let secp = secp256k1::Secp256k1::new();
                            let sk = secp256k1::SecretKey::from_slice(&share_scalar.to_bytes())
                                .unwrap_or_else(|_| {
                                    secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap()
                                });
                            let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

                            info!(
                                "✅ [NETWORK] Found user's tweaked share for: {}\n\
                                 \tTweaked Share PubKey (Self-Calc): 0x{}",
                                eth_address,
                                hex::encode(pk.serialize())
                            );

                            Some(share_scalar)
                        } else {
                            warn!(
                                "❌ [NETWORK] User {} has no tweaked share available",
                                eth_address
                            );
                            None
                        }
                    }
                    None => {
                        warn!("❌ [NETWORK] User {} not found in registry", eth_address);
                        None
                    }
                }
            } else {
                warn!("❌ [NETWORK] User registry not available");
                None
            }
        } else {
            // Use network's original DKG share
            info!("🔑 [NETWORK] Using network's original DKG share for signing");

            if let Some(dkg_node) = &self.dkg_node {
                if let Some(secret_share) = dkg_node.get_final_secret_share().await {
                    info!("✅ [NETWORK] Found network's DKG share");
                    Some(secret_share)
                } else {
                    warn!("❌ [NETWORK] DKG not completed yet, no secret share available");
                    None
                }
            } else {
                warn!("❌ [NETWORK] DKG node not available");
                None
            }
        }
    }

    /// Execute contract call for a given transaction type and intent
    ///
    /// This method delegates to MpcChainExecutor to keep contract execution
    /// logic separate from networking concerns.
    pub(crate) async fn execute_contract_call_for_transaction(
        &mut self,
        intent: &crate::types::DepositIntent,
        intent_hash: &str,
        transaction_type: crate::types::TransactionType,
        tx_hash: &str,
        vault_group_key: Option<k256::ProjectivePoint>,
        amount: u128,
    ) -> Result<()> {
        // Use sequencer to ensure sequential execution and prevent nonce collisions
        self.submit_contract_transaction_to_sequencer(
            intent,
            intent_hash,
            transaction_type,
            tx_hash,
            vault_group_key,
            amount,
        )
        .await
    }

    /// Execute refund intent contract call for a completed refund transaction
    /// This follows the same flow as execute_contract_call_for_transaction but for refunds
    /// Uses the sequencer to ensure sequential execution and prevent nonce collisions
    pub(crate) async fn execute_refund_contract_call_for_transaction(
        &mut self,
        intent: &crate::types::DepositIntent,
        intent_hash: &str,
        transaction_hash: &str,
        reason: &str,
        vault_group_key: Option<k256::ProjectivePoint>,
    ) -> Result<()> {
        // Use sequencer to ensure sequential execution and prevent nonce collisions
        self.submit_refund_intent_to_sequencer(
            intent_hash,
            transaction_hash,
            &intent.timestamp.to_string(),
            reason,
            vault_group_key,
        )
        .await
    }

    /// Execute solver add-liquidity operation directly (sequencer removed)
    pub(crate) async fn submit_solver_add_liquidity_to_sequencer(
        &mut self,
        solver_address: &str,
        solver_id: &str,
        asset_chain_name: &str,
        amount: u128,
        request_id: &str,
    ) -> Result<()> {
        // Execute directly - sequencer removed
        self.submit_solver_add_liquidity_contract_update(
            solver_address,
            solver_id,
            asset_chain_name,
            amount,
            None, // No request_id
            None, // No original_request
        )
        .await
    }

    // ----------------------------------------------------------------------------
    // Network transaction sequencer (NetworkToTarget and future flows)
    // ----------------------------------------------------------------------------

    /// Initialize the network transaction sequencer if not already present
    async fn initialize_network_transaction_sequencer(&mut self) {
        if self.network_transaction_sequencer.is_none() {
            let mut sequencer = crate::network::sequencer::NetworkTransactionSequencer::new();
            let total_nodes = self.node_manager.get_total_nodes();
            let node_id = self.local_peer_id.to_string();
            let message_tx = self.message_tx.clone();
            sequencer.initialize(message_tx, node_id, total_nodes).await;

            // Configure VRF + Consensus for final node selection
            sequencer.set_local_peer_id(self.local_peer_id);

            // Create SEPARATE VRF service for main sequencer with "main_seq:" storage prefix
            // This ensures main sequencer VRF data doesn't collide with signing or vault sequencer
            let main_vrf_storage =
                crate::database::storage::VrfStorage::new_with_prefix(self.db.clone(), "main_seq:");
            let main_vrf_service = crate::protocols::VrfService::new_with_storage_and_context(
                self.local_peer_id,
                self.message_tx.clone(),
                main_vrf_storage,
                "network",
            );
            sequencer.set_vrf_service(Arc::new(main_vrf_service));
            info!("✅ [MAIN_SEQUENCER] Separate VRF service configured with storage prefix 'main_seq:'");

            // Create a new consensus node for main sequencer (independent from signing)
            sequencer.set_consensus_node(Arc::new(tokio::sync::RwLock::new(
                crate::consensus::ConsensusNode::new(),
            )));
            info!("✅ [MAIN_SEQUENCER] Consensus node configured");

            // Get available nodes from node manager
            let available_nodes: Vec<libp2p::PeerId> =
                self.node_manager.get_active_nodes().into_iter().collect();
            sequencer
                .update_available_nodes(available_nodes.clone())
                .await;
            info!(
                "✅ [MAIN_SEQUENCER] Available nodes configured: count={}",
                available_nodes.len()
            );

            self.network_transaction_sequencer = Some(sequencer);
            info!(
                "✅ [NETWORK] Network transaction sequencer fully initialized with {} total nodes",
                total_nodes
            );
        }
    }

    /// Submit a NetworkToTarget transaction to the network transaction sequencer
    pub(crate) async fn submit_network_to_target_to_sequencer(
        &mut self,
        intent: &crate::types::DepositIntent,
        intent_hash: &str,
        amount: u128,
        tx_bytes: Vec<u8>,
        eth_tx: crate::chain_abstraction::EthereumTransaction,
        user_tweaked_share: Option<k256::Scalar>,
        user_eth_address: Option<String>,
    ) -> Result<()> {
        use crate::network::sequencer::{NetworkTransactionFlow, NetworkTransactionRequest};

        if self.network_transaction_sequencer.is_none() {
            self.initialize_network_transaction_sequencer().await;
        }

        if let Some(sequencer) = &self.network_transaction_sequencer {
            let transaction_id = crate::network::sequencer::NetworkTransactionSequencer::generate_transaction_id_for_network_to_target(intent_hash);

            let request = NetworkTransactionRequest {
                flow: NetworkTransactionFlow::NetworkToTarget {
                    intent: intent.clone(),
                    intent_hash: intent_hash.to_string(),
                    transaction_type: crate::types::TransactionType::NetworkToTarget,
                    amount,
                    tx_bytes,
                    eth_tx,
                    user_tweaked_share,
                    user_eth_address,
                },
                transaction_id: transaction_id.clone(),
                sequence: 0, // set by sequencer.submit
            };

            sequencer.submit(request).await?;
            info!(
                "📋 [NETWORK] Submitted NetworkToTarget to network transaction sequencer: intent_hash={}, amount={}, tx_id={}",
                intent_hash, amount, transaction_id
            );
            Ok(())
        } else {
            warn!("❌ [NETWORK] Network transaction sequencer not available for NetworkToTarget transaction");
            Ok(())
        }
    }

    /// Submit a withdraw liquidity transaction to the network sequencer
    pub(crate) async fn submit_withdraw_liquidity_to_sequencer(
        &mut self,
        solver_address: &str,
        eth_address: &str,
        amount: u128,
        tx_bytes: Vec<u8>,
        eth_tx: crate::chain_abstraction::EthereumTransaction,
    ) -> Result<()> {
        use crate::network::sequencer::{NetworkTransactionFlow, NetworkTransactionRequest};

        if self.network_transaction_sequencer.is_none() {
            self.initialize_network_transaction_sequencer().await;
        }

        if let Some(sequencer) = &self.network_transaction_sequencer {
            let transaction_id = crate::network::sequencer::NetworkTransactionSequencer::generate_transaction_id_for_withdraw_liquidity(&tx_bytes);

            let request = NetworkTransactionRequest {
                flow: NetworkTransactionFlow::WithdrawLiquidity {
                    solver_address: solver_address.to_string(),
                    eth_address: eth_address.to_string(),
                    amount,
                    tx_bytes,
                    eth_tx,
                },
                transaction_id: transaction_id.clone(),
                sequence: 0, // set by sequencer.submit
            };

            sequencer.submit(request).await?;
            info!(
                "📋 [NETWORK] Submitted WithdrawLiquidity to network transaction sequencer: solver={}, eth_address={}, amount={}, tx_id={}",
                solver_address, eth_address, amount, transaction_id
            );
            Ok(())
        } else {
            warn!("❌ [NETWORK] Network transaction sequencer not available for WithdrawLiquidity transaction");
            Ok(())
        }
    }

    /// Submit a reward payout transaction to the network sequencer
    pub(crate) async fn submit_reward_payout_to_sequencer(
        &mut self,
        solver_address: &str,
        eth_address: &str,
        amount: u128,
        tx_bytes: Vec<u8>,
        eth_tx: crate::chain_abstraction::EthereumTransaction,
    ) -> Result<()> {
        use crate::network::sequencer::{NetworkTransactionFlow, NetworkTransactionRequest};

        if self.network_transaction_sequencer.is_none() {
            self.initialize_network_transaction_sequencer().await;
        }

        if let Some(sequencer) = &self.network_transaction_sequencer {
            let transaction_id = crate::network::sequencer::NetworkTransactionSequencer::generate_transaction_id_for_reward_payout(&tx_bytes);

            let request = NetworkTransactionRequest {
                flow: NetworkTransactionFlow::RewardPayout {
                    solver_address: solver_address.to_string(),
                    eth_address: eth_address.to_string(),
                    amount,
                    tx_bytes,
                    eth_tx,
                },
                transaction_id: transaction_id.clone(),
                sequence: 0, // set by sequencer.submit
            };

            sequencer.submit(request).await?;
            info!(
                "📋 [NETWORK] Submitted RewardPayout to network transaction sequencer: solver={}, eth_address={}, amount={}, tx_id={}",
                solver_address, eth_address, amount, transaction_id
            );
            Ok(())
        } else {
            warn!("❌ [NETWORK] Network transaction sequencer not available for RewardPayout transaction");
            Ok(())
        }
    }

    /// Process a network transaction from the sequencer (currently only NetworkToTarget)
    pub(crate) async fn process_network_transaction(
        &mut self,
        request: crate::network::sequencer::NetworkTransactionRequest,
    ) -> Result<()> {
        use crate::network::sequencer::NetworkTransactionFlow;
        use crate::signing::EthereumSigner;

        match &request.flow {
            NetworkTransactionFlow::NetworkToTarget {
                intent_hash,
                tx_bytes,
                eth_tx,
                user_tweaked_share,
                user_eth_address: _user_eth_address,
                transaction_type,
                ..
            } => {
                info!(
                    "📋 [NETWORK_SEQUENCER] Processing NetworkToTarget transaction: intent_hash={}, tx_id={}",
                    intent_hash, request.transaction_id
                );

                if let Some(signing_node) = &mut self.signing_node {
                    let chain_handler: Arc<dyn crate::chain_abstraction::ChainHandler> =
                        crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                            eth_tx.chain_id,
                        )
                        .into();
                    let mut eth_signer = EthereumSigner::new(signing_node);
                    // IMPORTANT:
                    // For NetworkToTarget, we must sign with the NETWORK's DKG share so the
                    // recovered "from" address is the network main address (derived from group key),
                    // not a user-derived address.
                    //
                    // `EthereumSigner` treats `user_tweaked_share: Some(_)` as "user signing", so we
                    // pass the share via `signing_key_override` and force `user_eth_address=None`.
                    let network_signing_share = *user_tweaked_share;
                    match eth_signer
                        .sign_transaction(
                            tx_bytes.clone(),
                            &chain_handler,
                            eth_tx,
                            None,
                            None,
                            Some(intent_hash.clone()),
                            Some(transaction_type.clone()),
                            None,
                            network_signing_share,
                        )
                        .await
                    {
                        Ok(()) => {
                            info!(
                                "✅ [NETWORK_SEQUENCER] Successfully signed NetworkToTarget transaction: intent_hash={}, tx_id={}",
                                intent_hash, request.transaction_id
                            );
                            Ok(())
                        }
                        Err(e) => {
                            let error_message = format!(
                                "Failed to sign NetworkToTarget transaction (insufficient TICS or other error): {}",
                                e
                            );
                            error!("❌ [NETWORK_SEQUENCER] {}", error_message);

                            // Store transaction error and trigger refund
                            if let Some(user_intent_manager) = &self.user_intent_manager {
                                // Store the error
                                if let Err(store_err) = user_intent_manager
                                    .store_transaction_error(intent_hash, &error_message, None)
                                    .await
                                {
                                    warn!(
                                        "❌ [NETWORK_SEQUENCER] Failed to store transaction error for intent {}: {}",
                                        intent_hash, store_err
                                    );
                                } else {
                                    info!(
                                        "💥 [NETWORK_SEQUENCER] Stored transaction error for intent {}: {}",
                                        intent_hash, error_message
                                    );
                                }

                                // Broadcast the error
                                if let Some(signing_node) = &self.signing_node {
                                    signing_node
                                        .broadcast_transaction_error(
                                            Some(intent_hash),
                                            &error_message,
                                            "network_to_target",
                                            None,
                                        )
                                        .await;
                                }

                                // Trigger refund for NetworkToTarget transactions
                                info!(
                                    "💸 [NETWORK_SEQUENCER] Network-to-target transaction failed, initiating refund for intent: {}",
                                    intent_hash
                                );

                                // Get the intent for refund calculation
                                if let Some(intent) =
                                    user_intent_manager.get_intent(intent_hash).await
                                {
                                    // Calculate refund amount
                                    let intent_amount = intent.amount.parse::<u128>().unwrap_or(0);
                                    let refund_amount = if let Some(tx_ids) = user_intent_manager
                                        .get_intent_transaction_ids(intent_hash)
                                        .await
                                    {
                                        if tx_ids.user_to_network_tx_id.is_some() {
                                            // UserToVault transaction exists, refund original amount + 5% extra
                                            intent_amount + (intent_amount / 20)
                                        } else {
                                            // No UserToVault transaction, refund original amount
                                            intent_amount
                                        }
                                    } else {
                                        intent_amount
                                    };

                                    // Broadcast refund initiation through signing node
                                    if let Some(signing_node) = &self.signing_node {
                                        if let Err(refund_err) = signing_node
                                            .initiate_refund_transaction(intent_hash)
                                            .await
                                        {
                                            error!(
                                                "❌ [NETWORK_SEQUENCER] Failed to initiate refund transaction: {}",
                                                refund_err
                                            );
                                        } else {
                                            info!(
                                                "✅ [NETWORK_SEQUENCER] Successfully initiated refund for intent: {}",
                                                intent_hash
                                            );
                                        }
                                    }
                                } else {
                                    warn!(
                                        "❌ [NETWORK_SEQUENCER] Could not retrieve intent {} for refund initiation",
                                        intent_hash
                                    );
                                }
                            }

                            // Return the error so it can be logged by the caller
                            Err(anyhow::anyhow!("{}", error_message))
                        }
                    }
                } else {
                    Err(anyhow::anyhow!("Signing node not available"))
                }
            }
            NetworkTransactionFlow::WithdrawLiquidity {
                solver_address,
                eth_address,
                amount,
                tx_bytes,
                eth_tx,
            } => {
                info!(
                    "📋 [NETWORK_SEQUENCER] Processing WithdrawLiquidity transaction: solver={}, eth_address={}, amount={}, tx_id={}",
                    solver_address, eth_address, amount, request.transaction_id
                );

                if let Some(signing_node) = &mut self.signing_node {
                    let chain_handler: Arc<dyn crate::chain_abstraction::ChainHandler> =
                        crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                            eth_tx.chain_id,
                        )
                        .into();
                    // IMPORTANT:
                    // RewardTxn and WithdrawLiquidity must be handled identically:
                    // 1. Both use network's DKG secret share for signing (network group key)
                    // 2. Both verify signatures against individual partial public keys (network share pubkeys)
                    // 3. Both go through the same multi-node signature collection and verification process
                    // Do not rely on `SigningNode.key_store.private_key` being pre-populated.
                    // Instead, explicitly pass the network's DKG secret share as an override.
                    let network_signing_share = match &self.dkg_node {
                        Some(dkg_node) => dkg_node.get_final_secret_share().await,
                        None => None,
                    };
                    let mut eth_signer = EthereumSigner::new(signing_node);
                    eth_signer
                        .sign_transaction(
                            tx_bytes.clone(),
                            &chain_handler,
                            eth_tx,
                            None, // never treat this as "user signing"
                            None, // No user address for network transactions
                            None, // No intent_hash for withdraw liquidity
                            Some(crate::types::TransactionType::WithdrawLiquidity),
                            Some(solver_address.clone()),
                            network_signing_share,
                        )
                        .await?;

                    info!(
                        "✅ [NETWORK_SEQUENCER] Successfully signed WithdrawLiquidity transaction: solver={}, tx_id={}",
                        solver_address, request.transaction_id
                    );
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Signing node not available"))
                }
            }
            NetworkTransactionFlow::RewardPayout {
                solver_address,
                eth_address,
                amount,
                tx_bytes,
                eth_tx,
            } => {
                info!(
                    "📋 [NETWORK_SEQUENCER] Processing RewardPayout transaction: solver={}, eth_address={}, amount={}, tx_id={}",
                    solver_address, eth_address, amount, request.transaction_id
                );

                if let Some(signing_node) = &mut self.signing_node {
                    let chain_handler: Arc<dyn crate::chain_abstraction::ChainHandler> =
                        crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                            eth_tx.chain_id,
                        )
                        .into();
                    // IMPORTANT:
                    // RewardTxn and WithdrawLiquidity must be handled identically:
                    // 1. Both use network's DKG secret share for signing (network group key)
                    // 2. Both verify signatures against individual partial public keys (network share pubkeys)
                    // 3. Both go through the same multi-node signature collection and verification process
                    // Do not rely on `SigningNode.key_store.private_key` being pre-populated.
                    // Instead, explicitly pass the network's DKG secret share as an override.
                    let network_signing_share = match &self.dkg_node {
                        Some(dkg_node) => dkg_node.get_final_secret_share().await,
                        None => None,
                    };
                    let mut eth_signer = EthereumSigner::new(signing_node);
                    eth_signer
                        .sign_transaction(
                            tx_bytes.clone(),
                            &chain_handler,
                            eth_tx,
                            None, // never treat this as "user signing"
                            None, // No user address for network transactions
                            None, // No intent_hash for reward payout
                            Some(crate::types::TransactionType::RewardTxn),
                            Some(solver_address.clone()),
                            network_signing_share,
                        )
                        .await?;

                    info!(
                        "✅ [NETWORK_SEQUENCER] Successfully signed RewardPayout transaction: solver={}, tx_id={}",
                        solver_address, request.transaction_id
                    );
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Signing node not available"))
                }
            }
        }
    }

    /// Submit a solver withdraw-liquidity contract update to the sequencer
    pub(crate) async fn submit_solver_withdraw_liquidity_to_sequencer(
        &mut self,
        solver_address: &str,
        asset_chain_name: &str,
        amount: u128,
        payout_tx_hash: &str,
    ) -> Result<()> {
        use crate::network::sequencer::{ContractTransactionFlow, ContractTransactionRequest};

        if amount == 0 {
            info!(
                "⏭️ [NETWORK] Skipping withdraw-liquidity sequencing for solver {} (amount=0)",
                solver_address
            );
            return Ok(());
        }

        // Execute directly - sequencer removed
        self.submit_solver_liquidity_contract_update(
            solver_address,
            asset_chain_name,
            amount,
            payout_tx_hash,
            None, // No request_id
            None, // No original_request
        )
        .await
    }

    /// Submit a solver claim-reward contract update to the sequencer
    pub(crate) async fn submit_solver_claim_reward_to_sequencer(
        &mut self,
        solver_address: &str,
        reward_btc: Option<u128>,
        reward_tics: Option<u128>,
        payout_tx_hash: &str,
    ) -> Result<()> {
        use crate::network::sequencer::{ContractTransactionFlow, ContractTransactionRequest};

        if reward_btc.is_none() && reward_tics.is_none() {
            info!(
                "⏭️ [NETWORK] Skipping claim-reward sequencing for solver {} (both rewards are None)",
                solver_address
            );
            return Ok(());
        }

        if reward_btc.unwrap_or(0) == 0 && reward_tics.unwrap_or(0) == 0 {
            info!(
                "⏭️ [NETWORK] Skipping claim-reward sequencing for solver {} (both rewards are zero)",
                solver_address
            );
            return Ok(());
        }

        // Execute directly - sequencer removed
        self.submit_solver_reward_contract_update(
            solver_address,
            reward_btc,
            reward_tics,
            payout_tx_hash,
            None, // No request_id
            None, // No original_request
        )
        .await
    }

    /// Execute contract transaction directly (sequencer removed)
    async fn submit_contract_transaction_to_sequencer(
        &mut self,
        intent: &crate::types::DepositIntent,
        intent_hash: &str,
        transaction_type: crate::types::TransactionType,
        tx_hash: &str,
        vault_group_key: Option<k256::ProjectivePoint>,
        amount: u128,
    ) -> Result<()> {
        // Execute contract call directly - sequencer removed
        if let Some(signing_node) = &mut self.signing_node {
            crate::chain_abstraction::MpcChainExecutor::execute_contract_call(
                signing_node,
                self.node_manager.as_ref(),
                self.dkg_node.as_ref(),
                intent,
                intent_hash,
                transaction_type,
                vault_group_key,
                amount,
                tx_hash,
                None, // No request_id
                None, // No original_request
            )
            .await
        } else {
            warn!("❌ [NETWORK] Signing node not available for contract call execution");
            Ok(())
        }
    }

    /// Execute refund intent contract call directly (sequencer removed)
    pub(crate) async fn submit_refund_intent_to_sequencer(
        &mut self,
        intent_id: &str,
        transaction_hash: &str,
        timestamp: &str,
        reason: &str,
        vault_group_key: Option<k256::ProjectivePoint>,
    ) -> Result<()> {
        // Execute refund intent contract call directly - sequencer removed
        if let Some(signing_node) = &mut self.signing_node {
            crate::utils::contract::execute_refund_intent_contract_call(
                signing_node,
                self.node_manager.as_ref(),
                self.dkg_node.as_ref(),
                intent_id,
                transaction_hash,
                timestamp,
                reason,
                vault_group_key,
                None, // No request_id
                None, // No original_request
            )
            .await
        } else {
            warn!("❌ [NETWORK] Signing node not available for refund intent contract call execution");
            Ok(())
        }
    }


    /// Process a single contract transaction (sequencer removed - method kept for compatibility but unused)
    #[allow(dead_code)]
    /// Process a single contract transaction (sequencer removed - method kept for compatibility but unused)
    #[allow(dead_code)]
    pub(crate) async fn process_contract_transaction(
        &mut self,
        _request: crate::network::sequencer::ContractTransactionRequest,
    ) -> Result<()> {
        // Contract sequencer removed - transactions are executed directly
        Ok(())
    }
}

/// Parse semantic version string into (major, minor, patch)
pub fn parse_semantic_version(version: &str) -> Result<(u32, u32, u32)> {
    use anyhow::anyhow;

    let parts: Vec<&str> = version.split('.').collect();

    if parts.len() != 3 {
        return Err(anyhow!("Invalid semantic version format: {}", version));
    }

    Ok((
        parts[0]
            .parse()
            .map_err(|e| anyhow!("Invalid major version: {}", e))?,
        parts[1]
            .parse()
            .map_err(|e| anyhow!("Invalid minor version: {}", e))?,
        parts[2]
            .parse()
            .map_err(|e| anyhow!("Invalid patch version: {}", e))?,
    ))
}
