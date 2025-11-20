/// Channel message handler
/// Handles all internal channel messages: Broadcast, Unicast, DepositIntent, etc.
///
/// NOTE: This module contains the channel message handling logic from the original network/mod.rs
/// The implementation should be ported from lines ~3561-5042 of the original file
use anyhow::Result;
use ff::PrimeField;
use libp2p::{gossipsub, PeerId};
use tracing::{debug, error, info, warn};

use crate::{
    signing::{BitcoinSigner, EthereumSigner},
    types::{rpc::RPCRequest, ChannelMessage, GossipsubMessage},
};

use super::types::{MpcNetworkBehaviour, MpcNetworkLayer};

impl MpcNetworkLayer {
    // ChannelMessage is related to the MPSC channel only
    pub(crate) async fn handle_channel_message(
        &mut self,
        message: ChannelMessage,
        swarm: &mut libp2p::Swarm<MpcNetworkBehaviour>,
    ) -> Result<()> {
        info!("[handle_channel_message()] {:?}", message);
        match message {
            ChannelMessage::PeerDiscoveryRetry { attempt } => {
                info!(
                    "Received peer discovery retry notification (attempt {})",
                    attempt
                );
                if !self.peer_discovery.pending_peer_discovery_retry {
                    info!(
                        "Received stale peer discovery retry notification (attempt {}), ignoring",
                        attempt
                    );
                    return Ok(());
                }

                self.peer_discovery.pending_peer_discovery_retry = false;

                if self.has_additional_peers() {
                    info!(
                        "✅ Additional peers detected (attempt {}); broadcasting local presence",
                        attempt
                    );
                    self.broadcast_local_presence().await?;
                } else if attempt >= Self::MAX_PEER_DISCOVERY_RETRIES {
                    warn!(
                        "⚠️ Peer discovery retry attempt {} reached limit {}; not broadcasting yet",
                        attempt,
                        Self::MAX_PEER_DISCOVERY_RETRIES
                    );
                } else {
                    info!(
                        "⏳ Peer discovery retry attempt {} found no additional peers; rescheduling",
                        attempt
                    );
                    self.schedule_peer_discovery_retry(attempt + 1);
                }
            }
            // this is used in the dkg code
            ChannelMessage::Broadcast { topic, data } => {
                // dkg.s.1
                info!("📢 [BROADCAST] Attempting to broadcast to topic: {}", topic);
                let topic_hash = gossipsub::IdentTopic::new(topic.clone());
                info!("🏷️ [BROADCAST] Topic hash: {:?}", topic_hash.hash());

                // here the channel msg is sent to other peer(s) as Gossipsub MSG type
                // if peer(s) have already subscribed to this topic, they will recieve this
                // msg (check subscribe_to_default_topics())
                let swarm_mut = swarm.behaviour_mut();
                let peer_count = swarm_mut.gossipsub.all_peers().count();
                info!(
                    "📊 [BROADCAST] Available peers for topic {}: {}",
                    topic, peer_count
                );

                if peer_count > 0 {
                    info!("👥 [BROADCAST] Connected peers:");
                    for (peer_id, _peer_info) in swarm_mut.gossipsub.all_peers() {
                        info!("   - Peer: {:?}", peer_id);
                    }

                    match swarm_mut.gossipsub.publish(topic_hash, data) {
                        Ok(_) => {
                            info!(
                                "✅ [BROADCAST] Successfully published message to topic: {}",
                                topic
                            );
                        }
                        Err(e) => {
                            warn!(
                                "❌ [BROADCAST] Failed to publish message to topic {}: {:?}",
                                topic, e
                            );
                        }
                    }
                } else {
                    warn!(
                        "⚠️ [BROADCAST] No peers available for broadcasting to topic: {}",
                        topic
                    );
                }
            }
            // this is not used anywhere yet
            ChannelMessage::Unicast { peer_id, data } => {
                // Implement direct message sending using request-response protocol
                let peer_id = PeerId::from_bytes(&hex::decode(peer_id)?)
                    .map_err(|e| anyhow::anyhow!("Invalid peer ID: {}", e))?;
                let request = RPCRequest::Custom {
                    id: "custom".to_string(),
                    data,
                };
                // this will send the channel msg as
                // NetworkEvent::RequestResponse under ReqRespMessage::Request type
                // to just single peer
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, request);
            }
            ChannelMessage::IntentHash {
                intent_hash,
                signer,
                intent,
            } => {
                info!("📝 [NETWORK] Storing intent hash from signer {}", signer);

                if let Some(user_intent_manager) = &self.user_intent_manager {
                    if let Err(e) = user_intent_manager
                        .store_intent_hash(intent_hash.clone(), &signer, &intent)
                        .await
                    {
                        warn!("❌ [NETWORK] Failed to store intent hash: {}", e);
                    } else {
                        info!("✅ [NETWORK] Intent hash stored locally");
                    }
                } else {
                    warn!("❌ [NETWORK] No user registry available to store intent hash");
                }

                let intent_hash_hex = hex::encode(&intent_hash);
                let gossip_msg = GossipsubMessage::IntentHash {
                    intent_hash: intent_hash_hex.clone(),
                    signer: signer.clone(),
                    intent: intent.clone(),
                };
                let msg_bytes = serde_json::to_vec(&gossip_msg).map_err(|e| {
                    anyhow::anyhow!("Failed to serialize intent hash message: {}", e)
                })?;
                let topic = gossipsub::IdentTopic::new("intent-hashes");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted intent hash {}", intent_hash_hex);
            }
            ChannelMessage::DepositIntent {
                intent,
                intent_id,
                user_eth_address,
                transaction_type,
                amount,
            } => {
                info!(
                    "📝 [NETWORK] Processing deposit intent locally: {:?}",
                    intent
                );

                // Only broadcast to other nodes via gossipsub when using network share (no user_eth_address)
                info!("🌐 [NETWORK] Using network share - broadcasting to P2P network");
                let deposit_intent_msg = GossipsubMessage::DepositIntent {
                    intent: intent.clone(),
                    intent_id: intent_id.clone(),
                    user_eth_address: user_eth_address.clone(),
                    transaction_type: transaction_type.clone(),
                    amount: amount.clone(),
                };
                let msg_bytes = serde_json::to_vec(&deposit_intent_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize deposit intent: {}", e))?;

                // Broadcast to all peers via gossipsub
                let topic = gossipsub::IdentTopic::new("deposit-intents");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted deposit intent to P2P network");

                // Calculate intent hash for transaction ID storage
                let intent_hash = crate::utils::calculate_intent_hash(&intent);
                info!("🔐 [LOCAL] Calculated intent hash: {}", intent_hash);

                // Prepare unsigned transaction for on-chain deposit intent recording
                // self.prepare_deposit_intent_tx(&intent, &intent_hash).await;

                // Determine chain type based on transaction type:
                // - UserToVault: use source_chain (user is depositing FROM this chain)
                // - NetworkToTarget: use target_chain (network is withdrawing TO this chain)
                // - VaultToNetwork: use source_chain (vault is sending back to network on source chain)
                let chain_to_use = match transaction_type {
                    crate::types::TransactionType::UserToVault => {
                        &intent.source_chain.to_lowercase()
                    }
                    crate::types::TransactionType::NetworkToTarget => {
                        &intent.target_chain.to_lowercase()
                    }
                    crate::types::TransactionType::VaultToNetwork => {
                        &intent.source_chain.to_lowercase()
                    }
                };
                info!(
                    "🔗 [LOCAL] Processing deposit intent for chain: {} (transaction_type: {:?})",
                    chain_to_use, transaction_type
                );

                // Get the appropriate signing key based on transaction type
                let signing_key: Option<k256::Scalar> = match transaction_type {
                    crate::types::TransactionType::UserToVault => {
                        // For user deposits, use user's tweaked secret share
                        self.get_signing_key_for_user(user_eth_address.as_ref())
                            .await
                    }
                    crate::types::TransactionType::NetworkToTarget => {
                        // For network withdrawals, use network's DKG secret share
                        if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_final_secret_share().await
                        } else {
                            None
                        }
                    }
                    crate::types::TransactionType::VaultToNetwork => {
                        // For vault-to-network, use vault's tweaked secret share
                        if let Some(dkg_node) = &self.dkg_node {
                            dkg_node.get_vault_tweaked_secret_share().await
                        } else {
                            None
                        }
                    }
                };

                // Process locally first (this node will sign it)
                if let Some(signing_node) = &mut self.signing_node {
                    // Set appropriate chain handler based on the determined chain
                    if crate::utils::transaction::is_evm_chain(chain_to_use) {
                        if let Some(chain_id) =
                            crate::utils::transaction::get_chain_id_from_name(chain_to_use)
                        {
                            let chain_handler =
                                crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(
                                    chain_id,
                                );
                            signing_node.set_chain_handler(chain_handler.into());
                            info!(
                                "🔗 [LOCAL] Set Ethereum chain handler for chain: {} (ID: {})",
                                chain_to_use, chain_id
                            );
                        }
                    } else if chain_to_use == "bitcoin" || chain_to_use == "btc" {
                        let mut chain_handler =
                            crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler(
                                "testnet".to_string(),
                            );

                        // Set appropriate group public key in Bitcoin chain handler based on transaction type
                        match transaction_type {
                            crate::types::TransactionType::UserToVault => {
                                // For user deposits, use user's specific group key
                                if let Some(eth_addr) = &user_eth_address {
                                    if let Some(user_intent_manager) = &self.user_intent_manager {
                                        if let Some(user) =
                                            user_intent_manager.get_user_by_address(eth_addr).await
                                        {
                                            if let Some(user_group_key) = &user.user_group_key {
                                                let affine_point = user_group_key.0; // user_group_key is SerializablePoint(AffinePoint)
                                                let encoded_point =
                                                    k256::EncodedPoint::from(affine_point);
                                                let compressed_bytes =
                                                    encoded_point.compress().to_bytes().to_vec();

                                                if let Some(btc_handler) = chain_handler.as_any_mut().downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>() {
                                                    btc_handler.set_group_public_key(compressed_bytes);
                                                    info!("🔑 [LOCAL] Set user-specific group public key in Bitcoin chain handler for user: {}", eth_addr);
                                                }
                                            } else {
                                                warn!("❌ [LOCAL] User {} has no group key for Bitcoin transaction", eth_addr);
                                            }
                                        } else {
                                            warn!("❌ [LOCAL] User {} not found for Bitcoin transaction", eth_addr);
                                        }
                                    } else {
                                        warn!("❌ [LOCAL] User registry not available for Bitcoin transaction");
                                    }
                                } else {
                                    warn!("❌ [LOCAL] UserToVault transaction requires user_eth_address");
                                }
                            }
                            crate::types::TransactionType::NetworkToTarget => {
                                // For network withdrawals, use network's DKG group key
                                if let Some(dkg_node) = &self.dkg_node {
                                    if let Some(group_key) = dkg_node.get_final_public_key().await {
                                        let affine_point = group_key.to_affine();
                                        let encoded_point = k256::EncodedPoint::from(affine_point);
                                        let compressed_bytes =
                                            encoded_point.compress().to_bytes().to_vec();

                                        if let Some(btc_handler) = chain_handler
                                            .as_any_mut()
                                            .downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>(
                                        ) {
                                            btc_handler.set_group_public_key(compressed_bytes);
                                            info!("🔑 [LOCAL] Set network DKG group public key in Bitcoin chain handler");
                                        }
                                    }
                                }
                            }
                            crate::types::TransactionType::VaultToNetwork => {
                                // For vault-to-network, use vault's group key
                                if let Some(dkg_node) = &self.dkg_node {
                                    if let Some(vault_group_key) =
                                        dkg_node.get_vault_group_key().await
                                    {
                                        let affine_point = vault_group_key.to_affine();
                                        let encoded_point = k256::EncodedPoint::from(affine_point);
                                        let compressed_bytes =
                                            encoded_point.compress().to_bytes().to_vec();

                                        if let Some(btc_handler) = chain_handler
                                            .as_any_mut()
                                            .downcast_mut::<crate::chain_abstraction::BitcoinChainHandler>(
                                        ) {
                                            btc_handler.set_group_public_key(compressed_bytes);
                                            info!("🔑 [LOCAL] Set vault group public key in Bitcoin chain handler");
                                        }
                                    }
                                }
                            }
                        }

                        signing_node.set_chain_handler(chain_handler.into());
                        info!("🔗 [LOCAL] Set Bitcoin chain handler");
                    } else {
                        warn!(
                            "❌ [LOCAL] Unsupported chain: {}, using default Ethereum handler",
                            chain_to_use
                        );
                    }

                    // Get derived addresses based on transaction type
                    let (derived_eth_addr, derived_btc_addr) = match transaction_type {
                        crate::types::TransactionType::UserToVault => {
                            // For user deposits, use user's derived addresses
                            if let Some(eth_addr) = &user_eth_address {
                                if let Some(user_intent_manager) = &self.user_intent_manager {
                                    if let Some(user) =
                                        user_intent_manager.get_user_by_address(eth_addr).await
                                    {
                                        (
                                            user.derived_eth_address.clone(),
                                            user.derived_btc_address.clone(),
                                        )
                                    } else {
                                        warn!("❌ [LOCAL] User {} not found in registry", eth_addr);
                                        (None, None)
                                    }
                                } else {
                                    warn!("❌ [LOCAL] User registry not available");
                                    (None, None)
                                }
                            } else {
                                warn!(
                                    "❌ [LOCAL] UserToVault transaction requires user_eth_address"
                                );
                                (None, None)
                            }
                        }
                        crate::types::TransactionType::NetworkToTarget
                        | crate::types::TransactionType::VaultToNetwork => {
                            // For network withdrawals and vault-to-network, no derived addresses needed
                            (None, None)
                        }
                    };

                    let group_public_key = if let Some(dkg_node) = &self.dkg_node {
                        dkg_node.get_final_public_key().await
                    } else {
                        None
                    };

                    // Get vault addresses from database
                    let (vault_eth_addr, vault_btc_addr) =
                        if let Some(registry) = &self.user_intent_manager {
                            let database = registry.get_database();
                            let vault_eth = database
                                .get_string(&crate::database::keys::DKG_VAULT_ETH_ADDRESS)
                                .ok()
                                .flatten();
                            let vault_btc = database
                                .get_string(&crate::database::keys::DKG_VAULT_BTC_ADDRESS)
                                .ok()
                                .flatten();
                            (vault_eth, vault_btc)
                        } else {
                            return Err(anyhow::anyhow!("User registry not available"));
                        };

                    let chain_transaction_result =
                        crate::utils::transaction::create_chain_transaction_from_deposit_intent(
                            &intent,
                            group_public_key,
                            derived_eth_addr.as_ref(),
                            derived_btc_addr.as_ref(),
                            transaction_type.clone(),
                            vault_eth_addr.as_ref(),
                            vault_btc_addr.as_ref(),
                            amount,
                        )
                        .await;

                    match chain_transaction_result {
                        Ok(chain_transaction) => {
                            info!(
                                "📝 [LOCAL] Created {} transaction from deposit intent",
                                signing_node.get_chain_type()
                            );

                            // Set available nodes from node manager before signing
                            let available_nodes: Vec<PeerId> =
                                self.node_manager.get_active_nodes().into_iter().collect();
                            signing_node.set_available_nodes(available_nodes);

                            // Use the signing key we got earlier
                            if let Some(key) = signing_key {
                                info!("🔐 [LOCAL] Got signing key for deposit intent");
                                signing_node.set_private_key_from_scalar(key);

                                // Set the appropriate group public key based on transaction type
                                match transaction_type {
                                    crate::types::TransactionType::UserToVault => {
                                        // For user deposits, use user-specific group key
                                        if let Some(eth_address) = &user_eth_address {
                                            if let Some(user_intent_manager) =
                                                &self.user_intent_manager
                                            {
                                                if let Some(user) = user_intent_manager
                                                    .get_user_by_address(eth_address)
                                                    .await
                                                {
                                                    if let Some(user_group_key) =
                                                        &user.user_group_key
                                                    {
                                                        signing_node.set_group_public_key(
                                                            user_group_key.0.into(),
                                                        ); // Convert AffinePoint to ProjectivePoint
                                                        info!("🔑 [LOCAL] Set user-specific group public key for: {}", eth_address);
                                                    } else {
                                                        warn!("❌ [LOCAL] User {} has no group key available", eth_address);
                                                        return Ok(());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    crate::types::TransactionType::NetworkToTarget => {
                                        // For network withdrawals, use the original DKG group key
                                        if let Some(dkg_node) = &self.dkg_node {
                                            if let Some(group_key) =
                                                dkg_node.get_final_public_key().await
                                            {
                                                signing_node.set_group_public_key(group_key);
                                                info!(
                                                    "🔑 [LOCAL] Set network DKG group public key"
                                                );
                                            }
                                        }
                                    }
                                    crate::types::TransactionType::VaultToNetwork => {
                                        // For vault-to-network, use the vault group key
                                        if let Some(dkg_node) = &self.dkg_node {
                                            if let Some(vault_group_key) =
                                                dkg_node.get_vault_group_key().await
                                            {
                                                signing_node.set_vault_group_key(vault_group_key);
                                                info!("🔑 [LOCAL] Set vault group public key");
                                            }
                                        }
                                    }
                                }
                            } else {
                                info!("❌ [LOCAL] Could not get signing key for deposit intent");
                                return Ok(());
                            }

                            // Create transaction bytes using the chain handler
                            let tx_bytes = signing_node
                                .get_chain_handler()
                                .create_transaction_bytes(&chain_transaction)
                                .unwrap_or_else(|e| {
                                    warn!("Failed to create transaction bytes: {}", e);
                                    vec![]
                                });
                            info!(
                                "🔐 [LOCAL] Starting {} signing process for deposit intent: 0x{}",
                                signing_node.get_chain_type(),
                                hex::encode(tx_bytes.clone())
                            );

                            // Handle Bitcoin and EVM differently - DummyTransaction is only for EVM!
                            match chain_transaction {
                                crate::chain_abstraction::ChainTransaction::Bitcoin(ref btc_tx) => {
                                    // For Bitcoin, use direct signing with tx_bytes and original transaction
                                    {
                                        let mut btc_signer = BitcoinSigner::new(signing_node);
                                        btc_signer
                                            .sign_transaction(
                                                tx_bytes.clone(),
                                                Some(btc_tx.clone()),
                                                user_eth_address.clone(),
                                                Some(intent_hash.clone()),
                                                Some(transaction_type.clone()),
                                                signing_key,
                                                None,
                                            )
                                            .await?;
                                    }
                                }
                                crate::chain_abstraction::ChainTransaction::Ethereum(
                                    ref eth_tx,
                                ) => {
                                    let tx_bytes =
                                        crate::utils::transaction::create_transaction_for_signing(
                                            &eth_tx,
                                        );
                                    debug!("→ RLP payload: 0x{}", hex::encode(&tx_bytes));

                                    // Get signing key based on transaction type
                                    let user_tweaked_share = match transaction_type {
                                        crate::types::TransactionType::UserToVault => {
                                            // For user deposits, use user's tweaked secret share
                                            if let Some(eth_addr) = &user_eth_address {
                                                if let Some(user_intent_manager) =
                                                    &self.user_intent_manager
                                                {
                                                    if let Some(user) = user_intent_manager
                                                        .get_user_by_address(eth_addr)
                                                        .await
                                                    {
                                                        user.tweaked_secret_share.map(|s| s.0)
                                                    } else {
                                                        None
                                                    }
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        }
                                        crate::types::TransactionType::NetworkToTarget => {
                                            // For network withdrawals, use network's DKG secret share
                                            if let Some(dkg_node) = &self.dkg_node {
                                                dkg_node.get_final_secret_share().await
                                            } else {
                                                None
                                            }
                                        }
                                        crate::types::TransactionType::VaultToNetwork => {
                                            // For vault-to-network, use vault's tweaked secret share
                                            if let Some(dkg_node) = &self.dkg_node {
                                                dkg_node.get_vault_tweaked_secret_share().await
                                            } else {
                                                None
                                            }
                                        }
                                    };
                                    {
                                        let mut eth_signer = EthereumSigner::new(signing_node);
                                        eth_signer
                                            .sign_transaction(
                                                tx_bytes.clone(),
                                                &eth_tx,
                                                user_tweaked_share,
                                                user_eth_address.clone(),
                                                Some(intent_hash.clone()),
                                                Some(transaction_type.clone()),
                                                None,
                                            )
                                            .await?;
                                    }
                                    // // Only execute contract transaction for UserToVault transaction type
                                    // if matches!(transaction_type, crate::types::TransactionType::UserToVault) {
                                    //     info!("📝 [LOCAL] UserToVault transaction detected - executing contract call");

                                    //     let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> = sha3::Keccak256::new();
                                    //     hasher.update(&tx_bytes);
                                    //     let tx_hash = hasher.finalize();
                                    //     info!("Tx hash contract call: 0x{}", hex::encode(&tx_hash));

                                    //     tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                                    //     let contract_call_result = crate::utils::transaction::create_chain_transaction_from_contract_call(vault_group_key, amount, &intent, &intent_hash, tx_hash.to_vec(), transaction_type.clone()).await;

                                    //     match contract_call_result {
                                    //         Ok(contract_transaction) => {

                                    //             info!("📝 [LOCAL] Created contract call transaction");
                                    //             let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                                    //             signing_node.set_available_nodes(available_nodes);

                                    //             match contract_transaction {
                                    //                 crate::chain_abstraction::ChainTransaction::Ethereum(ref eth_tx) => {
                                    //                     let contract_tx = crate::types::ContractTransaction {
                                    //                         to: eth_tx.to.clone(),
                                    //                         value: eth_tx.value.clone(),
                                    //                         nonce: eth_tx.nonce,
                                    //                         gas_limit: eth_tx.gas_limit,
                                    //                         gas_price: eth_tx.gas_price.clone(),
                                    //                         chain_id: eth_tx.chain_id,
                                    //                         data: eth_tx.data.as_ref().map(|d| format!("0x{}", hex::encode(d))).unwrap_or_else(|| "0x".to_string()),
                                    //                     };
                                    //                     let contract_tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                                    //                     debug!("→ RLP payload contract call: 0x{}", hex::encode(&contract_tx_bytes));

                                    //                     let vault_tweaked_share = if let Some(dkg_node) = &self.dkg_node {
                                    //                         dkg_node.get_vault_tweaked_secret_share().await
                                    //                     } else {
                                    //                         None
                                    //                     };
                                    //                     signing_node.sign_contract_message(contract_tx_bytes, &contract_tx, vault_tweaked_share, None).await?;
                                    //                 }
                                    //                 _ => {
                                    //                     info!("📝 [LOCAL] Contract call transaction is not Ethereum type, skipping");
                                    //                 }
                                    //             }
                                    //         }
                                    //         Err(e) => {
                                    //             warn!("❌ [LOCAL] Failed to create contract call transaction: {}", e);
                                    //         }
                                    //     }
                                    // } else if matches!(transaction_type, crate::types::TransactionType::NetworkToTarget){
                                    //     info!("📝 [GOSSIPSUB] networkToTarget transaction detected - executing contract call");

                                    //     let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> = sha3::Keccak256::new();
                                    //     hasher.update(&tx_bytes);
                                    //     let tx_hash = hasher.finalize();
                                    //     info!("Tx hash contract call: 0x{}", hex::encode(&tx_hash));

                                    //     tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                                    //     let contract_call_result = crate::utils::transaction::create_chain_transaction_from_contract_call(vault_group_key, amount, &intent, &intent_hash, tx_hash.to_vec(), transaction_type.clone()).await;

                                    //     match contract_call_result {
                                    //         Ok(contract_transaction) => {

                                    //             info!("📝 [GOSSIPSUB] Created contract call transaction");
                                    //             let available_nodes: Vec<PeerId> = self.node_manager.get_active_nodes().into_iter().collect();
                                    //             signing_node.set_available_nodes(available_nodes);

                                    //             match contract_transaction {
                                    //                 crate::chain_abstraction::ChainTransaction::Ethereum(ref eth_tx) => {
                                    //                     let contract_tx = crate::types::ContractTransaction {
                                    //                         to: eth_tx.to.clone(),
                                    //                         value: eth_tx.value.clone(),
                                    //                         nonce: eth_tx.nonce,
                                    //                         gas_limit: eth_tx.gas_limit,
                                    //                         gas_price: eth_tx.gas_price.clone(),
                                    //                         chain_id: eth_tx.chain_id,
                                    //                         data: eth_tx.data.as_ref().map(|d| format!("0x{}", hex::encode(d))).unwrap_or_else(|| "0x".to_string()),
                                    //                     };
                                    //                     let contract_tx_bytes = crate::utils::transaction::create_transaction_for_signing_contract(&contract_tx);
                                    //                     debug!("→ RLP payload contract call: 0x{}", hex::encode(&contract_tx_bytes));

                                    //                     let vault_tweaked_share = if let Some(dkg_node) = &self.dkg_node {
                                    //                         dkg_node.get_vault_tweaked_secret_share().await
                                    //                     } else {
                                    //                         None
                                    //                     };
                                    //                     signing_node.sign_contract_message(contract_tx_bytes, &contract_tx, vault_tweaked_share, None).await?;
                                    //                 }
                                    //                 _ => {
                                    //                     info!("📝 [GOSSIPSUB] Contract call transaction is not Ethereum type, skipping");
                                    //                 }
                                    //             }
                                    //         }
                                    //         Err(e) => {
                                    //             warn!("❌ [GOSSIPSUB] Failed to create contract call transaction: {}", e);
                                    //         }
                                    //     }
                                    // }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("❌ [LOCAL] Failed to create chain transaction from deposit intent: {}", e);
                        }
                    }
                } else {
                    warn!("❌ [LOCAL] Signing node not available for deposit intent");
                }
            }

            ChannelMessage::TransactionIdBroadcast {
                intent_hash,
                transaction_id,
                transaction_type,
                solver_address,
                node_id,
            } => {
                info!(
                    "📡 [NETWORK] Received transaction ID broadcast from node {}",
                    node_id
                );
                info!("💳 [NETWORK] Transaction ID: {}", transaction_id);
                info!("🔄 [NETWORK] Transaction type: {}", transaction_type);
                if let Some(hash) = &intent_hash {
                    info!("🔗 [NETWORK] Intent hash: {}", hash);
                } else if let Some(solver) = &solver_address {
                    info!("🧩 [NETWORK] Solver address: {}", solver);
                } else {
                    info!("ℹ️ [NETWORK] No intent hash or solver address supplied with transaction ID broadcast");
                }

                // Gossip the transaction ID broadcast to other peers immediately so everyone can contribute their share in parallel
                let gossip_message = GossipsubMessage::TransactionIdBroadcast {
                    intent_hash: intent_hash.clone(),
                    transaction_id: transaction_id.clone(),
                    transaction_type: transaction_type.clone(),
                    solver_address: solver_address.clone(),
                    node_id: node_id.clone(),
                };

                let msg_bytes = match serde_json::to_vec(&gossip_message) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!("❌ [NETWORK] Failed to serialize transaction ID broadcast for gossiping: {}", e);
                        return Ok(());
                    }
                };

                let topic = gossipsub::IdentTopic::new("transaction-id-sync");
                if let Err(e) = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), msg_bytes)
                {
                    error!(
                        "❌ [NETWORK] Failed to gossip transaction ID broadcast to other peers: {}",
                        e
                    );
                } else {
                    match (intent_hash.as_ref(), solver_address.as_ref()) {
                        (Some(hash), _) => {
                            info!("📡 [NETWORK] Gossiped transaction ID {} for intent {} (type: {}) to other peers", transaction_id, hash, transaction_type);
                        }
                        (None, Some(solver)) => {
                            info!("📡 [NETWORK] Gossiped reward transaction ID {} for solver {} (type: {}) to other peers", transaction_id, solver, transaction_type);
                        }
                        _ => {
                            info!(
                                "📡 [NETWORK] Gossiped transaction ID {} (type: {}) to other peers",
                                transaction_id, transaction_type
                            );
                        }
                    }
                }

                // Now process locally using shared handler
                match (intent_hash.as_ref(), solver_address.as_ref()) {
                    (Some(intent_hash), _) => {
                        if let Err(e) = self
                            .handle_transaction_id_storage(
                                intent_hash,
                                &transaction_id,
                                &transaction_type,
                                &node_id,
                            )
                            .await
                        {
                            error!(
                                "❌ [NETWORK] Failed to handle transaction ID storage: {}",
                                e
                            );
                        }
                    }
                    (None, Some(solver_addr)) => {
                        if let Err(e) = self
                            .handle_reward_transaction_id_storage(
                                solver_addr,
                                &transaction_id,
                                &transaction_type,
                            )
                            .await
                        {
                            error!(
                                "❌ [NETWORK] Failed to handle reward transaction ID storage: {}",
                                e
                            );
                        }
                    }
                    _ => {
                        warn!("⚠️ [NETWORK] Transaction ID broadcast missing both intent hash and solver address");
                    }
                }
            }
            ChannelMessage::IntentHashBroadcast {
                intent_hash,
                node_id,
            } => {
                info!(
                    "📡 [NETWORK] Broadcasting intent hash {} from node {}",
                    intent_hash, node_id
                );
                let broadcast_msg = GossipsubMessage::IntentHashBroadcast {
                    intent_hash: intent_hash.clone(),
                    node_id: node_id.clone(),
                };
                let msg_bytes = serde_json::to_vec(&broadcast_msg).map_err(|e| {
                    anyhow::anyhow!("Failed to serialize intent hash broadcast: {}", e)
                })?;
                let topic = gossipsub::IdentTopic::new("intent-hashes");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted intent hash to P2P network");
            }
            ChannelMessage::UserRegistration {
                ethereum_address,
                node_id,
            } => {
                info!(
                    "👤 [NETWORK] Broadcasting user registration: {} from node {}",
                    ethereum_address, node_id
                );

                // Directly update commitments locally using the stored HMAC constant
                if let (Some(user_intent_manager), Some(dkg_node)) =
                    (&self.user_intent_manager, &self.dkg_node)
                {
                    if let Some(reg) = user_intent_manager
                        .get_user_by_address(&ethereum_address)
                        .await
                    {
                        if let Some(tweak_scalar) =
                            k256::Scalar::from_repr_vartime(reg.hmac_constant.into())
                        {
                            // Derive and store user-specific group key from updated commitments
                            match dkg_node
                                .derive_user_specific_group_key_from_commitments(tweak_scalar)
                                .await
                            {
                                Ok(group_key) => {
                                    if let Err(e) = user_intent_manager
                                        .set_user_group_key(&ethereum_address, group_key)
                                        .await
                                    {
                                        warn!("❌ [NETWORK] Failed to store user group key for {}: {}", ethereum_address, e);
                                    } else {
                                        info!("🔑 [NETWORK] Stored user-specific group key and derived addresses for {}", ethereum_address);
                                        // Log the derived addresses
                                        if let Some(user) = user_intent_manager
                                            .get_user_by_address(&ethereum_address)
                                            .await
                                        {
                                            if let Some(eth_addr) = &user.derived_eth_address {
                                                info!(
                                                    "📬 [NETWORK] Derived ETH address for {}: {}",
                                                    ethereum_address, eth_addr
                                                );
                                            }
                                            if let Some(btc_addr) = &user.derived_btc_address {
                                                info!(
                                                    "📬 [NETWORK] Derived BTC address for {}: {}",
                                                    ethereum_address, btc_addr
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("❌ [NETWORK] Failed to derive user-specific group key for {}: {}", ethereum_address, e);
                                }
                            }
                        }
                    } else {
                        warn!(
                            "❌ [NETWORK] Invalid HMAC tweak scalar for {}",
                            ethereum_address
                        );
                    }
                } else {
                    warn!("❌ [NETWORK] Missing user_intent_manager or dkg_node; cannot update commitments locally for {}", ethereum_address);
                }

                // Create and broadcast user registration message via gossipsub (same pattern as deposit intent)
                let user_reg_msg = GossipsubMessage::UserRegistration {
                    ethereum_address: ethereum_address.clone(),
                    timestamp: chrono::Utc::now().timestamp(),
                    node_id: node_id.clone(),
                };
                let msg_bytes = serde_json::to_vec(&user_reg_msg)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize user registration: {}", e))?;

                // Broadcast to all peers via gossipsub
                let topic = gossipsub::IdentTopic::new("user-registrations");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!("📡 [NETWORK] Broadcasted user registration to P2P network");
            }
            ChannelMessage::RefundInitiation { intent_hash, data } => {
                info!(
                    "💸 [NETWORK] Received refund initiation for intent: {}",
                    intent_hash
                );

                // Deserialize refund message to get details
                match serde_json::from_slice::<serde_json::Value>(&data) {
                    Ok(refund_data) => {
                        info!("📋 [NETWORK] Refund details: {:?}", refund_data);

                        // Get the intent to create the refund transaction
                        if let Some(user_intent_manager) = &self.user_intent_manager {
                            if let Some(mut intent) =
                                user_intent_manager.get_intent(&intent_hash).await
                            {
                                info!("🔄 [NETWORK-REFUND] Creating refund transaction from network to user's source address");
                                info!("💰 [NETWORK-REFUND] Refunding {} from network to source address: {} on {}", 
                                      intent.amount, intent.source_address, intent.source_chain);

                                // Modify the intent to create a refund transaction:
                                // - From: Network address (DKG group key)
                                // - To: User's source address
                                // - Chain: Source chain (where user originally sent from)
                                let original_target = intent.target_address.clone();
                                let original_target_chain = intent.target_chain.clone();

                                // Set target to user's source address on source chain for the refund
                                intent.target_address = intent.source_address.clone();
                                intent.target_chain = intent.source_chain.clone();

                                info!(
                                    "🔄 [NETWORK-REFUND] Refund routing: Network → {} ({})",
                                    intent.target_address, intent.target_chain
                                );
                                info!("🔄 [NETWORK-REFUND] Original failed transaction was to: {} ({})", 
                                      original_target, original_target_chain);

                                // Create a refund transaction from network to user's source address
                                // Use NetworkToTarget type since we're sending from network address to a target
                                let refund_intent_id = format!("refund-{}", intent_hash);
                                let refund_message = ChannelMessage::DepositIntent {
                                    intent: intent.clone(),
                                    intent_id: refund_intent_id,
                                    user_eth_address: None, // Use network's DKG key for refund
                                    transaction_type:
                                        crate::types::TransactionType::NetworkToTarget,
                                    amount: intent.amount,
                                };

                                // Send the refund message through the channel to be processed
                                if let Err(e) = self.message_tx.send(refund_message).await {
                                    error!("❌ [NETWORK-REFUND] Failed to send refund transaction message: {}", e);
                                } else {
                                    info!("✅ [NETWORK-REFUND] Successfully initiated refund transaction for intent: {}", intent_hash);
                                }
                            } else {
                                warn!("❌ [NETWORK-REFUND] Intent not found: {}", intent_hash);
                            }
                        } else {
                            warn!("❌ [NETWORK-REFUND] User registry not available");
                        }
                    }
                    Err(e) => {
                        error!(
                            "❌ [NETWORK-REFUND] Failed to deserialize refund data: {}",
                            e
                        );
                    }
                }
            }
            ChannelMessage::ScheduledDKGStart => {
                let total = self.node_manager.get_total_nodes();
                let threshold = self.node_manager.get_threshold();

                if let Some(dkg) = &mut self.dkg_node {
                    // This should only be called for initial DKG with 4 nodes
                    let initial_dkg_complete = dkg.is_initial_dkg_complete().await;

                    if initial_dkg_complete {
                        warn!("⚠️ [DKG] ScheduledDKGStart called but initial DKG already complete. This should not happen.");
                        return Ok(());
                    }

                    // Start the initial DKG with 4 nodes
                    info!("🚀 [DKG] Starting initial DKG with {} nodes", total);

                    if total != 4 {
                        warn!(
                            "⚠️ [DKG] Expected 4 nodes for initial DKG, but have {}",
                            total
                        );
                    }

                    if let Err(e) = dkg.update_node_params(total, threshold) {
                        warn!("❌ [DKG] Invalid params for scheduled start: {}", e);
                        return Ok(());
                    }
                    if let Err(e) = dkg.reset().await {
                        warn!("❌ [DKG] Failed to reset before scheduled start: {}", e);
                        return Ok(());
                    }
                    if let Some(signing_node) = &mut self.signing_node {
                        signing_node.set_threshold(total / 2 + 1);
                    }
                    self.node_manager.set_threshold(total / 2 + 1);
                    info!(
                        "🔄 DKG parameters updated: total_nodes={}, threshold={}",
                        total, threshold
                    );
                    if let Err(e) = dkg.start_dkg(self.node_manager.clone()).await {
                        warn!("❌ Scheduled DKG start failed: {:?}", e);
                    }
                } else {
                    warn!("❌ DKG node not initialized at scheduled start!");
                }
            }
            ChannelMessage::ClaimReward {
                solver_address,
                btc_address,
                eth_address,
                reward_btc,
                reward_tics,
            } => {
                info!("🎁 [NETWORK] Processing reward claim for solver: {}, ETH address: {:?}, BTC address: {:?}", 
                  solver_address, eth_address, btc_address);
                info!(
                    "💰 [NETWORK] Reward details - BTC: {:?}, TICS: {:?}",
                    reward_btc, reward_tics
                );

                // Broadcast the reward claim to other nodes via gossipsub immediately
                let claim_reward_msg = GossipsubMessage::ClaimReward {
                    solver_address: solver_address.clone(),
                    btc_address: btc_address.clone(),
                    eth_address: eth_address.clone(),
                    reward_btc: reward_btc.clone(),
                    reward_tics: reward_tics.clone(),
                };
                let msg_bytes = serde_json::to_vec(&claim_reward_msg).map_err(|e| {
                    anyhow::anyhow!("Failed to serialize claim reward message: {}", e)
                })?;

                // Broadcast to all peers via gossipsub
                let topic = gossipsub::IdentTopic::new("claim-rewards");
                swarm.behaviour_mut().gossipsub.publish(topic, msg_bytes)?;
                info!(
                    "📡 [NETWORK] Broadcasted claim reward to P2P network for solver: {}",
                    solver_address
                );

                // Validate that at least one reward type is present
                if reward_btc.is_none() && reward_tics.is_none() {
                    warn!("❌ [NETWORK] Invalid reward claim - both BTC and TICS rewards are None for solver: {}", solver_address);
                    return Ok(());
                }

                // Process TICS rewards (Ethereum) if available
                if let Some(ref tics_reward_str) = reward_tics {
                    if let Some(ref eth_addr) = eth_address {
                        if let Ok(tics_amount) = tics_reward_str.parse::<u128>() {
                            info!(
                                "🎁 [NETWORK] Processing TICS reward: {} -> {} (amount: {})",
                                solver_address, eth_addr, tics_amount
                            );

                            // Get network address for sending rewards
                            if let Some(dkg_node) = &self.dkg_node {
                                if let Some(group_key) = dkg_node.get_final_public_key().await {
                                    let network_address =
                                        crate::utils::get_eth_address_from_group_key(group_key);

                                    // Create Ethereum transaction for TICS reward
                                    match crate::utils::transaction::create_ethereum_transaction(
                                        &network_address,
                                        &eth_addr,
                                        tics_amount,
                                        "qubetics", // Use Qubetics chain for TICS
                                    )
                                    .await
                                    {
                                        Ok(eth_tx) => {
                                            info!("✅ [NETWORK] Created TICS reward transaction: {:?}", eth_tx);

                                            // Sign the transaction using MPC
                                            if let Some(signing_node) = &mut self.signing_node {
                                                // Set available nodes from node manager before signing
                                                let available_nodes: Vec<PeerId> = self
                                                    .node_manager
                                                    .get_active_nodes()
                                                    .into_iter()
                                                    .collect();
                                                signing_node.set_available_nodes(available_nodes);
                                                signing_node.set_chain_handler(crate::chain_abstraction::ChainHandlerFactory::create_ethereum_handler(eth_tx.chain_id).into());

                                                if let Some(dkg_node) = &self.dkg_node {
                                                    if let Some(secret_share) =
                                                        dkg_node.get_final_secret_share().await
                                                    {
                                                        info!("🔐 [REWARD] Got secret share from DKG for TICS reward");
                                                        signing_node.set_private_key_from_scalar(
                                                            secret_share,
                                                        );

                                                        // Set the DKG group public key
                                                        if let Some(group_key) =
                                                            dkg_node.get_final_public_key().await
                                                        {
                                                            signing_node
                                                                .set_group_public_key(group_key);
                                                            info!("🔑 [REWARD] Set DKG group public key for TICS reward signing");
                                                        }

                                                        // Convert transaction to bytes for signing
                                                        let tx_bytes = crate::utils::transaction::create_transaction_for_signing(&eth_tx);
                                                        info!("🔐 [REWARD] Starting TICS reward signing process: 0x{}", hex::encode(tx_bytes.clone()));

                                                        // Sign with only necessary parameters for transaction
                                                        {
                                                            let mut eth_signer =
                                                                EthereumSigner::new(signing_node);
                                                            eth_signer
                                                                .sign_transaction(
                                                                    tx_bytes,
                                                                    &eth_tx,
                                                                    None,
                                                                    None,
                                                                    None,
                                                                    None,
                                                                    Some(solver_address.clone()),
                                                                )
                                                                .await?;
                                                        }
                                                        info!("✅ [REWARD] TICS reward signing completed");
                                                    } else {
                                                        info!("⏳ [REWARD] DKG not completed yet, no secret share available for TICS reward");
                                                    }
                                                } else {
                                                    info!("❌ [REWARD] DKG node not available for TICS reward");
                                                }
                                            } else {
                                                warn!("❌ [REWARD] Signing node not available for TICS reward");
                                            }
                                        }
                                        Err(e) => {
                                            error!("❌ [NETWORK] Failed to create TICS reward transaction: {}", e);
                                        }
                                    }
                                } else {
                                    warn!("❌ [NETWORK] No group key available for TICS reward transaction");
                                }
                            } else {
                                warn!("❌ [NETWORK] DKG node not available for TICS reward transaction");
                            }
                        } else {
                            warn!(
                                "❌ [NETWORK] Invalid TICS reward amount: {}",
                                tics_reward_str
                            );
                        }
                    } else {
                        warn!("❌ [NETWORK] TICS reward available but no ETH address provided");
                    }
                }

                // Process BTC rewards if available
                if let Some(ref btc_reward_str) = reward_btc {
                    if let Some(ref btc_addr) = btc_address {
                        if let Ok(btc_amount) = btc_reward_str.parse::<u128>() {
                            info!(
                                "🎁 [NETWORK] Processing BTC reward: {} -> {} (amount: {})",
                                solver_address, btc_addr, btc_amount
                            );

                            // Get network BTC address for sending rewards
                            if let Some(dkg_node) = &self.dkg_node {
                                if let Some(group_key) = dkg_node.get_final_public_key().await {
                                    let network_btc_address =
                                        crate::utils::get_btc_address_from_group_key(group_key);

                                    // Create Bitcoin transaction for BTC reward
                                    match crate::utils::transaction::create_bitcoin_transaction(
                                        &network_btc_address,
                                        &btc_addr,
                                        btc_amount,
                                    )
                                    .await
                                    {
                                        Ok(btc_tx) => {
                                            info!(
                                                "✅ [NETWORK] Created BTC reward transaction: {:?}",
                                                btc_tx
                                            );

                                            // Sign the transaction using MPC
                                            if let Some(signing_node) = &mut self.signing_node {
                                                // Set available nodes from node manager before signing
                                                let available_nodes: Vec<PeerId> = self
                                                    .node_manager
                                                    .get_active_nodes()
                                                    .into_iter()
                                                    .collect();
                                                signing_node.set_available_nodes(available_nodes);
                                                signing_node.set_chain_handler(crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler("testnet".to_string()).into());

                                                if let Some(dkg_node) = &self.dkg_node {
                                                    if let Some(secret_share) =
                                                        dkg_node.get_final_secret_share().await
                                                    {
                                                        info!("🔐 [REWARD] Got secret share from DKG for BTC reward");
                                                        signing_node.set_private_key_from_scalar(
                                                            secret_share,
                                                        );

                                                        // Set the DKG group public key
                                                        if let Some(group_key) =
                                                            dkg_node.get_final_public_key().await
                                                        {
                                                            signing_node
                                                                .set_group_public_key(group_key);
                                                            info!("🔑 [REWARD] Set DKG group public key for BTC reward signing");
                                                        }

                                                        // Convert transaction to bytes for signing
                                                        let chain_tx =
                                                            crate::chain_abstraction::ChainTransaction::Bitcoin(
                                                                btc_tx.clone(),
                                                            );
                                                        // set chain handler as btc
                                                        signing_node.set_chain_handler(crate::chain_abstraction::ChainHandlerFactory::create_bitcoin_handler("testnet".to_string()).into());
                                                        let tx_bytes = signing_node
                                                            .get_chain_handler()
                                                            .create_transaction_bytes(&chain_tx)
                                                            .unwrap();
                                                        info!("🔐 [REWARD] Starting BTC reward signing process: 0x{}", hex::encode(tx_bytes.clone()));

                                                        // Sign with Bitcoin-specific parameters
                                                        {
                                                            let mut btc_signer =
                                                                BitcoinSigner::new(signing_node);
                                                            btc_signer
                                                                .sign_transaction(
                                                                    tx_bytes,
                                                                    Some(btc_tx),
                                                                    None,
                                                                    None,
                                                                    None,
                                                                    None,
                                                                    Some(solver_address.clone()),
                                                                )
                                                                .await?;
                                                        }
                                                        info!("✅ [REWARD] BTC reward signing completed");
                                                    } else {
                                                        info!("⏳ [REWARD] DKG not completed yet, no secret share available for BTC reward");
                                                    }
                                                } else {
                                                    info!("❌ [REWARD] DKG node not available for BTC reward");
                                                }
                                            } else {
                                                warn!("❌ [REWARD] Signing node not available for BTC reward");
                                            }
                                        }
                                        Err(e) => {
                                            error!("❌ [NETWORK] Failed to create BTC reward transaction: {}", e);
                                        }
                                    }
                                } else {
                                    warn!("❌ [NETWORK] No group key available for BTC reward transaction");
                                }
                            } else {
                                warn!("❌ [NETWORK] DKG node not available for BTC reward transaction");
                            }
                        } else {
                            warn!("❌ [NETWORK] Invalid BTC reward amount: {}", btc_reward_str);
                        }
                    } else {
                        warn!("❌ [NETWORK] BTC reward available but no BTC address provided");
                    }
                }

                info!(
                    "✅ [NETWORK] Reward claim processed successfully for solver: {}",
                    solver_address
                );
            }
        }
        Ok(())
    }
}
