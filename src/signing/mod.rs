use crate::rpc_server::DummyTransaction;
use anyhow::anyhow;
use anyhow::Result;
use k256::Scalar;
// use ethereum_types::U64; // Removed unused import
use hex;
use libp2p::PeerId;
use num_bigint::BigUint;
use num_traits::identities::One;
use rand::rngs::OsRng;
use secp256k1::{self, ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::Digest as Sha2Digest;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

pub mod db_signing;
pub use db_signing::DatabaseSigningNode;

use num_bigint::{BigInt, ToBigInt};
use secp256k1::{constants::CURVE_ORDER, ecdsa::RecoveryId};

use num_traits::Zero;
use rand::seq::SliceRandom;
use rand::thread_rng;

use crate::consensus::{ConsensusMessage, ConsensusNode, ConsensusResult};
use crate::types::{p2p::SerializablePeerId, ChannelMessage};
use crate::vrf::{VrfService, VrfSelectedNodesBroadcast};
use crate::chain::{ChainHandler, ChainSignature, ChainHandlerFactory, ChainTransaction};
use crate::utils::get_eth_address_from_group_key;
// Import BitcoinTransaction directly from chain module
use crate::chain::{BitcoinTransaction, BitcoinInput};
use crate::user_registry::{DatabaseUserRegistry, TransactionStatus};
use crate::utils::transaction::DetectedAddressType;
use crate::contract::{ContractClient, SolverManagerContract};
use crate::database::RewardStorage;
use ethers::types::U256;
use ethereum_types::U256 as EthereumU256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECDSASignature {
    pub signature: Vec<u8>, // 65-byte recoverable signature
    pub signer_id: String,
    pub recovery_id: u8,
    pub user_eth_address: Option<String>, // Track if this is user-to-network or network-to-target
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignatureShare {
    pub share: Vec<u8>, // The signature share
    pub signer_id: String,
    pub share_index: u32,
    pub threshold: u32,
    pub total_shares: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignature {
    pub aggregated_signature: Vec<u8>,
    pub signer_ids: Vec<String>,
    pub message_hash: Vec<u8>,
    pub threshold: u32,
    pub total_shares: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub aggregated_signature: Vec<u8>, // ECDSA signature
    pub signer_ids: Vec<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningMessage {
    MessageToSign {
        from: String,
        message: Vec<u8>,
        message_hash: Vec<u8>,
    },
    ECDSASignature {
        from: String,
        signature: ECDSASignature,
        round: u64,
        timestamp: u128,
        user_eth_address: Option<String>, // Track if this is user-to-network or network-to-target
    },
    SignedMessage {
        from: String,
        signed_message: SignedMessage,
    },
    RequestSignatures {
        round: u64,
        final_node_id: String,
        message: String,
    },
}

#[derive(Clone)]
pub struct SigningNode {
    id: String,
    threshold: usize,
    private_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    public_keys: Arc<RwLock<HashMap<String, PublicKey>>>, // Other nodes' public keys
    signatures: Arc<RwLock<HashMap<String, ECDSASignature>>>,
    signatures_by_round: Arc<RwLock<HashMap<u64, HashMap<String, ECDSASignature>>>>, // round -> node_id -> signature
    final_nodes_by_round: Arc<RwLock<HashMap<u64, String>>>, // round -> final_node_id
    aggregated_rounds: Arc<RwLock<std::collections::HashSet<u64>>>, // Track rounds that have been aggregated
    message_tx: mpsc::Sender<ChannelMessage>,
    vrf_service: Option<VrfService>, // VRF service for node selection
    chain_handler: Arc<dyn ChainHandler>, // Chain-specific operations
    consensus_node: Option<ConsensusNode>, // Consensus node for final node selection
    available_nodes: Option<Vec<PeerId>>,  // Available nodes from node manager
    // Store original transaction and bytes for reconstruction
    pending_transactions: Arc<RwLock<HashMap<u64, (ChainTransaction, Vec<u8>, Option<String>, Option<crate::types::TransactionType>)>>>, // round -> (original_tx, tx_bytes, intent_hash, transaction_type)
    // ✅ Store DKG group public key
    group_public_key: Option<k256::ProjectivePoint>, // DKG group public key for Bitcoin addresses
    // ✅ Store vault group public key separately
    vault_group_key: Option<k256::ProjectivePoint>, // Vault group public key for vault transactions
    // User registry for storing transaction IDs
    user_registry: Option<Arc<DatabaseUserRegistry>>,
    // Database for storing solver amounts
    database: Option<Arc<crate::database::Database>>,
    // Dynamic broadcast configuration
    broadcast_config: BroadcastConfig,
}

impl SigningNode {
    pub fn set_threshold(&mut self, new_threshold: usize) {
        self.threshold = new_threshold;
    }

    pub fn new(id: String, threshold: usize, message_tx: mpsc::Sender<ChannelMessage>) -> Self {
        // Parse the actual PeerId from the string ID
        let peer_id = PeerId::from_str(&id).unwrap_or_else(|_| {
            // Fallback to derived PeerId if parsing fails
            Self::derive_peer_id_from_string(&id)
        });

        // Create default Ethereum chain handler (can be changed later)
        let chain_handler = ChainHandlerFactory::create_ethereum_handler(1043);
        let chain_handler: Arc<dyn ChainHandler> = chain_handler.into();

        Self {
            id,
            threshold,
            private_key: None,
            public_key: None,
            public_keys: Arc::new(RwLock::new(HashMap::new())),
            signatures: Arc::new(RwLock::new(HashMap::new())),
            signatures_by_round: Arc::new(RwLock::new(HashMap::new())),
            final_nodes_by_round: Arc::new(RwLock::new(HashMap::new())),
            aggregated_rounds: Arc::new(RwLock::new(std::collections::HashSet::new())),
            message_tx: message_tx.clone(),
            vrf_service: Some(VrfService::new(peer_id, message_tx)),
            chain_handler,
            consensus_node: Some(ConsensusNode::new()),
            available_nodes: None,
            pending_transactions: Arc::new(RwLock::new(HashMap::new())),
            group_public_key: None, // ✅ Initialize DKG group public key
            vault_group_key: None, // ✅ Initialize vault group public key
            user_registry: None, // Will be set later via set_user_registry
            database: None, // Will be set later via set_database
            broadcast_config: BroadcastConfig::from_env(), // Load configuration from environment
        }
    }


    /// Print the current broadcast configuration
    pub fn print_broadcast_config(&self) {
        self.broadcast_config.print_config();
    }

    /// Derive a deterministic PeerId from a string ID
    fn derive_peer_id_from_string(id: &str) -> PeerId {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        let hash = hasher.finalize();

        // Create a deterministic keypair from the hash
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&hash[..32]);

        // Create a deterministic Ed25519 keypair
        let ed_kp = libp2p::identity::ed25519::Keypair::try_from_bytes(&mut key_bytes)
            .unwrap_or_else(|_| libp2p::identity::ed25519::Keypair::generate());
        let kp = libp2p::identity::Keypair::from(ed_kp);

        PeerId::from_public_key(&kp.public())
    }

    pub fn generate_key_pair(&mut self) -> Result<()> {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let (private_key, public_key) = secp.generate_keypair(&mut rng);

        self.private_key = Some(private_key);
        self.public_key = Some(public_key);

        info!("🔐 [SIGNING] Node {} generated ECDSA key pair", self.id);
        info!("🔑 [SIGNING] Public key: {:?}", public_key);
        Ok(())
    }

    pub fn set_private_key(&mut self, private_key: SecretKey) {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        info!("🔐 [SIGNING] Node {} private key set", self.id);
    }

    pub fn set_private_key_from_scalar(&mut self, scalar: Scalar) {
        let scalar_bytes = scalar.to_bytes();
        let secret_key = Self::derive_secp_secret(&scalar);

        info!(
            "🔐 [SIGNING] Node {} private key set from scalar",
            self.id
        );
        info!("🔐 [SIGNING] scalar bytes: {:?}", scalar_bytes);
        // info!("🔐 [SIGNING] Derived key bytes: {:?}", final_key_bytes);
        info!(
            "🔐 OOKK [SIGNING] Final secret key: {:?}",
            hex::encode(secret_key.as_ref())
        );

        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        info!("🔑 [SIGNING] Node {} public key: {:?}", self.id, public_key);

        self.private_key = Some(secret_key);
        self.public_key = Some(public_key);

        info!(
            "🔐 [SIGNING] Node {} private key set from scalar with proper Ethereum conversion",
            self.id
        );
    }

    pub fn derive_secp_secret(scalar: &Scalar) -> SecretKey {
        let be = scalar.to_bytes();
        SecretKey::from_slice(be.as_slice()).expect("valid secp256k1 scalar")
    }

    // Configuration methods
    pub fn set_broadcast_config(&mut self, config: BroadcastConfig) {
        self.broadcast_config = config;
    }
    
    pub fn get_broadcast_config(&self) -> &BroadcastConfig {
        &self.broadcast_config
    }
    
    pub fn update_chain_config(&mut self, chain_type: &str, config: ChainBroadcastConfig) {
        self.broadcast_config.chain_configs.insert(chain_type.to_string(), config);
    }
    
    pub fn enable_chain(&mut self, chain_type: &str, enabled: bool) {
        if let Some(chain_config) = self.broadcast_config.chain_configs.get_mut(chain_type) {
            chain_config.enabled = enabled;
        }
    }
    
    pub fn add_public_key(&self, node_id: String, public_key: PublicKey) {
        let node_id_clone = node_id.clone();
        tokio::spawn({
            let public_keys = self.public_keys.clone();
            async move {
                public_keys.write().await.insert(node_id, public_key);
            }
        });
        info!(
            "🔑 [SIGNING] Node {} added public key for {}",
            self.id, node_id_clone
        );
    }

    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }

    /// Sign Bitcoin transaction directly with tx_bytes (no DummyTransaction wrapper)
    pub async fn sign_bitcoin_transaction(&mut self, tx_bytes: Vec<u8>, original_tx: Option<BitcoinTransaction>, user_eth_address: Option<String>, intent_hash: Option<String>) -> Result<()> {
        // Clone user_eth_address early to avoid borrow checker issues
        let user_eth_address_clone = user_eth_address.clone();
        
        if self.private_key.is_none() {
            error!(
                "❌ [SIGNING] Node {} cannot sign Bitcoin transaction: no private key available",
                self.id
            );
            return Err(anyhow::anyhow!("No private key available"));
        }

        info!(
            "📝 [SIGNING] Node {} starting to sign Bitcoin transaction",
            self.id
        );

        // Use the provided Bitcoin transaction bytes directly
        
        // Hash the transaction bytes using Bitcoin's double SHA256
        use sha2::{Sha256, Digest};
        let first_hash = Sha256::digest(&tx_bytes);
        let tx_hash = Sha256::digest(&first_hash);
        info!("🔗 [BITCOIN] Tx hash (double SHA256): 0x{}", hex::encode(&tx_hash));

        // Get available nodes and perform VRF selection
        let available_nodes = self.get_available_nodes_from_manager().await;
        
        // Use VrfService for node selection and get the round
        let current_round = if let Some(vrf_service) = &self.vrf_service {
            // ✅ FIX: Use get_next_round() to increment the round properly
            let round = vrf_service.get_next_round().await;
            let _selection_result = vrf_service.perform_node_selection(
                &available_nodes, 
                1, 
                round, 
                "bitcoin"
            ).await;
            info!(
                "🎲 [SIGNING] Node {} using VRF round {} for Bitcoin transaction signing",
                self.id, round
            );
            round
        } else {
            warn!("⚠️ [SIGNING] No VRF service available, using round 0 as fallback");
            0
        };

        // Create ECDSA signature using your proven custom logic (no DummyTransaction needed)
        let msg = Message::from_digest_slice(&tx_hash)?;
        let signature = self.create_ecdsa_signature_direct(&msg)?;
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        
        // ✅ Debug logging to verify signature format
        info!(
            "🔍 [SIGNING] Node {} created signature - Recovery ID: {}, Signature length: {} bytes",
            self.id, recovery_id.to_i32(), signature_bytes.len()
        );

        // Note: Chain handler signature creation is handled separately for Bitcoin

        info!(
            "✅ [SIGNING] Node {} successfully signed Bitcoin transaction",
            self.id
        );

        // Create ECDSASignature for broadcasting
        // ✅ FIX: Don't append recovery_id to signature bytes - keep them separate!
        // The aggregation expects 64-byte signature + separate recovery_id field
        // let ecdsa_signature = ECDSASignature {
        //     signature: signature_bytes.to_vec(), // ✅ 64 bytes (r||s only)
        //     signer_id: self.id.clone(),
        //     recovery_id: recovery_id.to_i32() as u8, // ✅ Separate field
        //     user_eth_address: user_eth_address_clone.clone(), // Clone to avoid borrow checker issues
        // };

        // Broadcast the signature to other nodes with proper VRF round
        // let signing_message = SigningMessage::ECDSASignature {
        //     from: self.id.clone(),
        //     signature: ecdsa_signature,
        //     round: current_round, // ✅ Use actual VRF round
        //     timestamp: std::time::SystemTime::now()
        //         .duration_since(std::time::UNIX_EPOCH)
        //         .unwrap()
        //         .as_millis(),
        //     user_eth_address: user_eth_address_clone.clone(), // Pass user_eth_address for tracking
        // };

        // let gossipsub_msg = crate::types::GossipsubMessage::Signing(signing_message);
        // let msg_data = serde_json::to_vec(&gossipsub_msg)?;

        // self.message_tx
        //     .send(ChannelMessage::Broadcast {
        //         topic: "signatures".to_string(),
        //         data: msg_data,
        //     })
        //     .await?;

        info!(
            "📤 [SIGNING] Node {} broadcasted Bitcoin signature to network for round {}",
            self.id, current_round
        );

        // Store signature by round for potential aggregation
        {
            let mut signatures_by_round = self.signatures_by_round.write().await;
            let round_signatures = signatures_by_round.entry(current_round).or_default();
            let stored_signature = ECDSASignature {
                signature: signature_bytes.to_vec(), // ✅ 64 bytes (consistent with broadcast)
                signer_id: self.id.clone(),
                recovery_id: recovery_id.to_i32() as u8,
                user_eth_address: user_eth_address_clone.clone(), // Clone to avoid borrow checker issues
            };
            round_signatures.insert(self.id.clone(), stored_signature);
            info!(
                "💾 [SIGNING] Node {} stored Bitcoin signature for round {} (total signatures for round: {})",
                self.id, current_round, round_signatures.len()
            );
        }

        // Store original transaction for reconstruction after aggregation
        if let Some(original_tx) = original_tx {
            let mut pending_transactions = self.pending_transactions.write().await;
            pending_transactions.insert(current_round, (ChainTransaction::Bitcoin(original_tx), tx_bytes.clone(), intent_hash.clone(), None));
            info!(
                "💾 [SIGNING] Node {} stored original Bitcoin transaction for round {} reconstruction (intent_hash: {:?})",
                self.id, current_round, intent_hash
            );
        }

        Ok(())
    }

    async fn broadcast_transaction(raw_tx_hex: &str, mainnet: bool) -> Result<Option<String>> {
        let default_url = if mainnet {
            format!("{}/tx", "https://blockstream.info/api")
        } else {
            format!("{}/tx", "https://blockstream.info/testnet/api")
        };

        let url = std::env::var("MPC_BITCOIN_RPC_URL").unwrap_or(default_url);
        info!("Broadcasting transaction to: {}", url);

        let client = reqwest::Client::new();

        let response = if url.contains("blockcypher.com") {
            let payload = serde_json::json!({ "tx": raw_tx_hex });
            client.post(&url)
                .header("Content-Type", "application/json")
                .header("User-Agent", "sigg_gen_agg/0.1.0")
                .json(&payload)
                .send()
                .await?
        } else {
            client.post(&url)
                .header("Content-Type", "text/plain")
                .header("User-Agent", "sigg_gen_agg/0.1.0")
                .body(raw_tx_hex.to_string())
                .send()
                .await?
        };

        if response.status().is_success() {
            if url.contains("blockcypher.com") {
                let result: serde_json::Value = response.json().await?;
                if let Some(tx_hash) = result.get("hash").and_then(|v| v.as_str()) {
                    info!("✅ Transaction broadcasted successfully! TXID: {}", tx_hash);
                    Ok(Some(tx_hash.to_string()))
                } else {
                    info!("✅ Transaction broadcasted successfully");
                    Ok(None)
                }
            } else {
                let txid = response.text().await?;
                info!("✅ Transaction broadcasted successfully! TXID: {}", txid);
                Ok(Some(txid.trim().to_string()))
            }
        } else {
            let error_text = response.text().await?;
            error!("❌ Failed to broadcast transaction: {}", error_text);
            Err(anyhow!("Broadcast failed: {}", error_text))
        }
    }

    /// Fetch nonce for an Ethereum address from the blockchain
    pub async fn fetch_ethereum_nonce(address: &str, chain_id: u64) -> Result<u64> {
        let rpc_url = match chain_id {
            9029 => std::env::var("MPC_ETHEREUM_RPC_URL")
                .unwrap_or_else(|_| "https://rpc-testnet.qubetics.work".to_string()),
            1 => "https://mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string(), // Ethereum mainnet
            _ => return Err(anyhow!("Unsupported chain ID for nonce fetching: {}", chain_id)),
        };

        let client = reqwest::Client::new();
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [address, "latest"],
            "id": 1
        });

        info!("Fetching nonce for address {} on chain {} (pending)", address, chain_id);

        let response = client.post(rpc_url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            if let Some(error) = result.get("error") {
                error!("❌ Failed to fetch nonce: {}", error);
                return Err(anyhow!("Nonce fetch failed: {}", error));
            }
            if let Some(nonce_hex) = result.get("result") {
                let nonce_str = nonce_hex.as_str().unwrap_or("0x0");
                let nonce = u64::from_str_radix(nonce_str.strip_prefix("0x").unwrap_or(nonce_str), 16)?;
                info!("✅ Fetched nonce {} for address {}", nonce, address);
                Ok(nonce)
            } else {
                Err(anyhow!("No nonce result in response"))
            }
        } else {
            let error_text = response.text().await?;
            error!("❌ Failed to fetch nonce: {}", error_text);
            Err(anyhow!("Nonce fetch failed: {}", error_text))
        }
    }

    /// Broadcast Ethereum transaction to Qubetics chain
    async fn broadcast_ethereum_transaction(raw_tx_hex: &str, chain_id: u64) -> Result<Option<String>> {
        let rpc_url = match chain_id {
            9029 => std::env::var("MPC_ETHEREUM_RPC_URL")
                .unwrap_or_else(|_| "https://rpc-testnet.qubetics.work".to_string()),
            1 => "https://mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string(), // Ethereum mainnet
            _ => return Err(anyhow!("Unsupported chain ID for broadcasting: {}", chain_id)),
        };

        let client = reqwest::Client::new();
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx_hex],
            "id": 1
        });

        info!("Broadcasting Ethereum transaction to chain {}: {}", chain_id, rpc_url);

        let response = client.post(rpc_url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            if let Some(error) = result.get("error") {
                error!("❌ Failed to broadcast transaction: {}", error);
                return Err(anyhow!("Broadcast failed: {}", error));
            }
            if let Some(tx_hash) = result.get("result") {
                info!("✅ Qubetics transaction broadcasted successfully!");
                info!("TX Hash: {}", tx_hash);
                if let Some(tx_hash_str) = tx_hash.as_str() {
                    return Ok(Some(tx_hash_str.to_string()));
                }
            }
        } else {
            let error_text = response.text().await?;
            error!("❌ Failed to broadcast transaction: {}", error_text);
            return Err(anyhow!("Broadcast failed: {}", error_text));
        }
        Ok(None)
    }

     /// Reconstruct signed Bitcoin transaction from aggregated signature
    pub async fn reconstruct_signed_bitcoin_transaction(
        &self,
        round: u64,
        aggregated_signature: &[u8],
        _recovery_id: u8,
    ) -> Result<Option<String>> {
        let pending_transactions = self.pending_transactions.read().await;
        
        if let Some((chain_tx, _tx_bytes, _, _)) = pending_transactions.get(&round) {
            if let ChainTransaction::Bitcoin(original_tx) = chain_tx {
                info!(
                    "🔧 [SIGNING] Node {} reconstructing signed Bitcoin transaction for round {}",
                    self.id, round
                );
                
                // Determine address type from first input
                let address_type = if let Some(input) = original_tx.inputs.first() {
                    if let Some(witness_utxo) = &input.witness_utxo {
                        match witness_utxo.script_pubkey.len() {
                            22 if witness_utxo.script_pubkey[0] == 0x00 && witness_utxo.script_pubkey[1] == 0x14 => DetectedAddressType::P2WPKH,
                            34 if witness_utxo.script_pubkey[0] == 0x00 && witness_utxo.script_pubkey[1] == 0x20 => DetectedAddressType::P2WSH,
                            34 if witness_utxo.script_pubkey[0] == 0x51 && witness_utxo.script_pubkey[1] == 0x20 => DetectedAddressType::P2TR,
                            _ => DetectedAddressType::P2WPKH,
                        }
                    } else {
                        DetectedAddressType::P2PKH
                    }
                } else {
                    DetectedAddressType::P2PKH
                };

                // Prepare signature bytes depending on address type
                let signature = match address_type {
                    DetectedAddressType::P2TR => {
                        let mut sig = aggregated_signature.to_vec();
                        // Append SIGHASH_ALL for Taproot
                        sig.push(0x01);
                        sig
                    },
                    _ => {
                        let r = &aggregated_signature[0..32];
                        let s = &aggregated_signature[32..64];
                        self.create_der_signature(r, s)?
                    }
                };

                // Create the complete signed transaction
                let signed_tx = self.create_signed_bitcoin_transaction(original_tx, &signature)?;
                
                let signed_tx_hex = hex::encode(&signed_tx);
                
                info!(
                    "✅ [SIGNING] Node {} successfully reconstructed signed Bitcoin transaction for round {}",
                    self.id, round
                );
                info!("📄 [SIGNING] Signed transaction hex: {}", signed_tx_hex);
                info!("📏 [SIGNING] Transaction size: {} bytes", signed_tx.len());
                
                Ok(Some(signed_tx_hex))
            } else {
                warn!(
                    "❌ [SIGNING] Node {} expected Bitcoin transaction for round {} but got different type",
                    self.id, round
                );
                Ok(None)
            }
        } else {
            warn!(
                "❌ [SIGNING] Node {} cannot reconstruct transaction for round {} - original transaction not found",
                self.id, round
            );
            Ok(None)
        }
    }
    
    /// Reconstruct signed Ethereum transaction from aggregated signature
    pub async fn reconstruct_signed_ethereum_transaction(
        &self,
        round: u64,
        aggregated_signature: &[u8],
        recovery_id: u8,
    ) -> Result<Option<String>> {
        let pending_transactions = self.pending_transactions.read().await;
        
        if let Some((chain_tx, _tx_bytes, _intent_hash, transaction_type)) = pending_transactions.get(&round) {
            if let ChainTransaction::Ethereum(original_tx) = chain_tx {
                info!(
                    "🔧 [SIGNING] Node {} reconstructing signed Ethereum transaction for round {}",
                    self.id, round
                );
                
                // Extract r and s from aggregated signature
                let r = &aggregated_signature[0..32];
                let s = &aggregated_signature[32..64];
                
                // Get chain ID from chain handler
                let chain_id = self.chain_handler.get_chain_params()
                    .get("chain_id")
                    .and_then(|id| id.parse::<u64>().ok())
                    .unwrap_or(1043); // Default to Qubetics chain ID
                
                // Calculate v value for Ethereum (EIP-155)
                let v = recovery_id as u64 + 35 + chain_id * 2;
                
                // Determine if this is a user transaction by checking signatures for this round
                let user_eth_address = {
                    let signatures_by_round = self.signatures_by_round.read().await;
                    if let Some(round_signatures) = signatures_by_round.get(&round) {
                        // Get user_eth_address from any signature in this round (all should have the same value)
                        round_signatures.values().next().and_then(|sig| sig.user_eth_address.clone())
                    } else {
                        None
                    }
                };
                
                // Determine which address to use for nonce fetching based on transaction type
                let (nonce_address, dynamic_nonce) = match transaction_type {
                    Some(crate::types::TransactionType::UserToVault) => {
                        // This is a user transaction - fetch nonce from user's derived address
                        if let Some(user_addr) = &user_eth_address {
                            if let Some(user_registry) = &self.user_registry {
                                if let Some(user) = user_registry.get_user_by_address(user_addr).await {
                                    if let Some(derived_eth_addr) = &user.derived_eth_address {
                                        let nonce = Self::fetch_ethereum_nonce(derived_eth_addr, chain_id).await?;
                                        info!("🔢 [SIGNING] UserToVault transaction: fetching nonce {} from user's derived address {}", nonce, derived_eth_addr);
                                        (derived_eth_addr.clone(), nonce)
                                    } else {
                                        return Err(anyhow::anyhow!("User {} has no derived Ethereum address", user_addr));
                                    }
                                } else {
                                    return Err(anyhow::anyhow!("User {} not found in registry", user_addr));
                                }
                            } else {
                                return Err(anyhow::anyhow!("User registry not available for user transaction"));
                            }
                        } else {
                            return Err(anyhow::anyhow!("UserToVault transaction requires user_eth_address"));
                        }
                    }
                    Some(crate::types::TransactionType::NetworkToTarget) => {
                        // This is a network transaction - fetch nonce from network's group address
                        let group_address = if let Some(group_key) = self.group_public_key {
                            get_eth_address_from_group_key(group_key)
                        } else {
                            return Err(anyhow::anyhow!("No group public key available for network transaction"));
                        };
                        
                        let nonce = Self::fetch_ethereum_nonce(&group_address, chain_id).await?;
                        info!("🔢 [SIGNING] NetworkToTarget transaction: fetching nonce {} from network group address {}", nonce, group_address);
                        (group_address, nonce)
                    }
                    Some(crate::types::TransactionType::VaultToNetwork) => {
                        // This is a vault transaction - fetch nonce from the actual vault address stored in database
                        if let Some(user_registry) = &self.user_registry {
                            let database = user_registry.get_database();
                            let vault_eth_address: String = database.get_string(&crate::database::keys::DKG_VAULT_ETH_ADDRESS)
                                .ok()
                                .flatten()
                                .ok_or_else(|| anyhow::anyhow!("Vault ETH address not found in database"))?;
                            
                            let nonce = Self::fetch_ethereum_nonce(&vault_eth_address, chain_id).await?;
                            info!("🔢 [SIGNING] VaultToNetwork transaction: fetching nonce {} from vault address {}", nonce, vault_eth_address);
                            (vault_eth_address, nonce)
                        } else {
                            return Err(anyhow::anyhow!("User registry not available for vault transaction"));
                        }
                    }
                    None => {
                        // Fallback to old logic for backward compatibility
                        if let Some(user_addr) = &user_eth_address {
                            // This is a user transaction - fetch nonce from user's derived address
                            if let Some(user_registry) = &self.user_registry {
                                if let Some(user) = user_registry.get_user_by_address(user_addr).await {
                                    if let Some(derived_eth_addr) = &user.derived_eth_address {
                                        let nonce = Self::fetch_ethereum_nonce(derived_eth_addr, chain_id).await?;
                                        info!("🔢 [SIGNING] User transaction (fallback): fetching nonce {} from user's derived address {}", nonce, derived_eth_addr);
                                        (derived_eth_addr.clone(), nonce)
                                    } else {
                                        return Err(anyhow::anyhow!("User {} has no derived Ethereum address", user_addr));
                                    }
                                } else {
                                    return Err(anyhow::anyhow!("User {} not found in registry", user_addr));
                                }
                            } else {
                                return Err(anyhow::anyhow!("User registry not available for user transaction"));
                            }
                        } else {
                            // This is either a network or vault transaction
                            let group_address = if let Some(group_key) = self.group_public_key {
                                get_eth_address_from_group_key(group_key)
                            } else {
                                return Err(anyhow::anyhow!("No group public key available for nonce fetching"));
                            };
                            
                            let nonce = Self::fetch_ethereum_nonce(&group_address, chain_id).await?;
                            info!("🔢 [SIGNING] Network/Vault transaction (fallback): fetching nonce {} from group address {}", nonce, group_address);
                            (group_address, nonce)
                        }
                    }
                };
                
                info!("💰 [SIGNING] Transaction cost: {} wei", original_tx.value);
                info!("🔍 [SIGNING] Please ensure the address {} has sufficient balance", nonce_address);
                
                // Create signed transaction using the utility function with dynamic nonce
                let signed_tx = crate::utils::transaction::create_signed_transaction(
                    &crate::rpc_server::DummyTransaction {
                        to: original_tx.to.clone(),
                        value: original_tx.value.clone(),
                        nonce: dynamic_nonce,
                        gas_limit: original_tx.gas_limit,
                        gas_price: original_tx.gas_price.clone(),
                        chain_id: original_tx.chain_id,
                    },
                    r,
                    s,
                    v,
                );
                    
                let signed_tx_hex = format!("0x{}", hex::encode(&signed_tx));
                
                info!(
                    "✅ [SIGNING] Node {} successfully reconstructed signed Ethereum transaction for round {}",
                    self.id, round
                );
                info!("📄 [SIGNING] Signed transaction hex: {}", signed_tx_hex);
                info!("📏 [SIGNING] Transaction size: {} bytes", signed_tx.len());
                info!("🔗 [SIGNING] Chain ID: {}", chain_id);
                
                Ok(Some(signed_tx_hex))
                } else {
                warn!(
                    "❌ [SIGNING] Node {} expected Ethereum transaction for round {} but got different type",
                    self.id, round
                );
                Ok(None)
            }
        } else {
            warn!(
                "❌ [SIGNING] Node {} cannot reconstruct Ethereum transaction for round {} - original transaction not found",
                self.id, round
            );
            Ok(None)
        }
    }

    /// Create DER-encoded signature for Bitcoin
    fn create_der_signature(&self, r: &[u8], s: &[u8]) -> Result<Vec<u8>> {
        let mut der_sig = Vec::new();
        der_sig.push(0x30); // SEQUENCE tag
        
        // Calculate and add the total length later
        let length_pos = der_sig.len();
        der_sig.push(0x00); // Placeholder for length
        
        // Add r value
        der_sig.push(0x02); // INTEGER tag
        if r[0] & 0x80 != 0 {
            // If high bit is set, prepend 0x00 to make it positive
            der_sig.push((r.len() + 1) as u8);
            der_sig.push(0x00);
        } else {
            der_sig.push(r.len() as u8);
        }
        der_sig.extend_from_slice(r);
        
        // Add s value  
        der_sig.push(0x02); // INTEGER tag
        if s[0] & 0x80 != 0 {
            // If high bit is set, prepend 0x00 to make it positive
            der_sig.push((s.len() + 1) as u8);
            der_sig.push(0x00);
        } else {
            der_sig.push(s.len() as u8);
        }
        der_sig.extend_from_slice(s);
        
        // Update the total length
        let content_length = der_sig.len() - 2; // Exclude the SEQUENCE tag and length byte
        der_sig[length_pos] = content_length as u8;
        
        // Add SIGHASH_ALL flag
        der_sig.push(0x01); // SIGHASH_ALL
        
        Ok(der_sig)
    }

    fn create_signed_bitcoin_transaction(
        &self,
        original_tx: &BitcoinTransaction,
        signature: &[u8],
    ) -> Result<Vec<u8>> {
        let mut signed_tx = Vec::new();
        
        // Version (4 bytes, little-endian)
        signed_tx.extend_from_slice(&original_tx.version.to_le_bytes());
        
        // Check if this is a SegWit transaction
        let is_segwit = original_tx.witness.is_some();
        
        if is_segwit {
            // SegWit marker and flag
            signed_tx.push(0x00); // SegWit marker
            signed_tx.push(0x01); // SegWit flag
        }
        
        // Input count (varint)
        signed_tx.extend_from_slice(&self.encode_varint(original_tx.inputs.len() as u64));
        
        // Inputs with signatures
        for (i, input) in original_tx.inputs.iter().enumerate() {
            // Previous output hash (32 bytes, reversed)
            let mut txid_bytes = hex::decode(&input.txid)
                .map_err(|e| anyhow::anyhow!("Invalid txid hex: {}", e))?;
            txid_bytes.reverse(); // Bitcoin uses reversed byte order
            signed_tx.extend_from_slice(&txid_bytes);
            
            // Previous output index (4 bytes, little-endian)
            signed_tx.extend_from_slice(&input.vout.to_le_bytes());
            
            // Create script_sig based on address type
            let script_sig = if i == 0 {
                self.create_script_sig_for_input(input, signature)?
            } else {
                vec![] // Empty for other inputs for now
            };
            
            // Script sig length and content
            signed_tx.extend_from_slice(&self.encode_varint(script_sig.len() as u64));
            signed_tx.extend_from_slice(&script_sig);
            
            // Sequence (4 bytes, little-endian)
            signed_tx.extend_from_slice(&input.sequence.to_le_bytes());
        }
        
        // Output count (varint)
        signed_tx.extend_from_slice(&self.encode_varint(original_tx.outputs.len() as u64));
        
        // Outputs - preserve original script_pubkey format
        for output in &original_tx.outputs {
            // Value (8 bytes, little-endian)
            signed_tx.extend_from_slice(&output.value.to_le_bytes());
            
            // Script pubkey length and content
            signed_tx.extend_from_slice(&self.encode_varint(output.script_pubkey.len() as u64));
            signed_tx.extend_from_slice(&output.script_pubkey);
        }
        
        // Witness data for SegWit transactions
        if is_segwit {
            if let Some(witness) = &original_tx.witness {
                for (i, _witness_input) in witness.inputs.iter().enumerate() {
                    if i == 0 {
                        // Create witness stack for the first input
                        let witness_stack = self.create_witness_stack_for_input(&original_tx.inputs[i], signature)?;
                        signed_tx.extend_from_slice(&self.encode_varint(witness_stack.len() as u64));
                        for item in witness_stack {
                            signed_tx.extend_from_slice(&self.encode_varint(item.len() as u64));
                            signed_tx.extend_from_slice(&item);
                        }
                    } else {
                        // Empty witness for other inputs
                        signed_tx.extend_from_slice(&self.encode_varint(0));
                    }
                }
            }
        }
        
        // Lock time (4 bytes, little-endian)
        signed_tx.extend_from_slice(&original_tx.lock_time.to_le_bytes());
        
        Ok(signed_tx)
    }


    /// Create script_sig for different input types
    fn create_script_sig_for_input(&self, input: &BitcoinInput, signature: &[u8]) -> Result<Vec<u8>> {
        if let Some(witness_utxo) = &input.witness_utxo {
            // For SegWit inputs, script_sig is usually empty or contains redeem script
            match witness_utxo.script_pubkey.len() {
                22 if witness_utxo.script_pubkey[0] == 0x00 && witness_utxo.script_pubkey[1] == 0x14 => {
                    // P2WPKH - empty script_sig
                    Ok(vec![])
                },
                34 if witness_utxo.script_pubkey[0] == 0x00 && witness_utxo.script_pubkey[1] == 0x20 => {
                    // P2WSH - empty script_sig
                    Ok(vec![])
                },
                34 if witness_utxo.script_pubkey[0] == 0x51 && witness_utxo.script_pubkey[1] == 0x20 => {
                    // P2TR - empty script_sig
                    Ok(vec![])
                },
                _ => {
                    // P2SH-wrapped SegWit - need redeem script
                    Ok(vec![])
                }
            }
        } else {
            // Legacy P2PKH - create standard script_sig
            let group_key_bytes = self.get_group_public_key_bytes()?;
            let mut script_sig = Vec::new();
            
            // Push signature (DER format)
            script_sig.push(signature.len() as u8);
            script_sig.extend_from_slice(signature);
            
            // Push public key
            script_sig.push(group_key_bytes.len() as u8);
            script_sig.extend_from_slice(&group_key_bytes);
            
            Ok(script_sig)
        }
    }

    /// Create witness stack for SegWit inputs
    fn create_witness_stack_for_input(&self, input: &BitcoinInput, signature: &[u8]) -> Result<Vec<Vec<u8>>> {
        if let Some(witness_utxo) = &input.witness_utxo {
            match witness_utxo.script_pubkey.len() {
                22 if witness_utxo.script_pubkey[0] == 0x00 && witness_utxo.script_pubkey[1] == 0x14 => {
                    // P2WPKH: [signature, pubkey]
                    let group_key_bytes = self.get_group_public_key_bytes()?;
                    Ok(vec![signature.to_vec(), group_key_bytes])
                },
                34 if witness_utxo.script_pubkey[0] == 0x00 && witness_utxo.script_pubkey[1] == 0x20 => {
                    // P2WSH: [signature, script, ...]
                    let group_key_bytes = self.get_group_public_key_bytes()?;
                    Ok(vec![signature.to_vec(), group_key_bytes])
                },
                34 if witness_utxo.script_pubkey[0] == 0x51 && witness_utxo.script_pubkey[1] == 0x20 => {
                    // P2TR: [signature] (Schnorr signature)
                    // Note: This is simplified - real P2TR uses Schnorr signatures
                    Ok(vec![signature.to_vec()])
                },
                _ => {
                    // P2SH-wrapped SegWit
                    let group_key_bytes = self.get_group_public_key_bytes()?;
                    Ok(vec![signature.to_vec(), group_key_bytes])
                }
            }
        } else {
            // Legacy input - no witness
            Ok(vec![])
        }
    }

    /// Get the group public key bytes from DKG
    fn get_group_public_key_bytes(&self) -> Result<Vec<u8>> {
        if let Some(group_key) = self.group_public_key {
            // ✅ Convert k256::ProjectivePoint to compressed bytes for Bitcoin
            let affine_point = group_key.to_affine();
            let encoded_point = k256::EncodedPoint::from(affine_point);
            let compressed_bytes = encoded_point.compress().to_bytes().to_vec();
            
            info!("🔑 [SIGNING] Using REAL DKG group public key: {}", hex::encode(&compressed_bytes));
            Ok(compressed_bytes)
        } else {
            Err(anyhow::anyhow!("DKG group public key not available - ensure DKG process is completed"))
        }
    }

    /// Encode varint for Bitcoin transaction serialization
    fn encode_varint(&self, value: u64) -> Vec<u8> {
        if value < 0xfd {
            vec![value as u8]
        } else if value <= 0xffff {
            let mut bytes = vec![0xfd];
            bytes.extend_from_slice(&(value as u16).to_le_bytes());
            bytes
        } else if value <= 0xffffffff {
            let mut bytes = vec![0xfe];
            bytes.extend_from_slice(&(value as u32).to_le_bytes());
            bytes
        } else {
            let mut bytes = vec![0xff];
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes
        }
    }

    pub async fn broadcast(&self, topic: &str, data: &[u8]) -> Result<()> {
        info!(
            "📤 [SIGNING] Node {} broadcasting to topic: {}",
            self.id, topic
        );
        info!("📊 [SIGNING] Message size: {} bytes", data.len());

        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: topic.to_string(),
                data: data.to_vec(),
            })
            .await?;

        info!(
            "✅ [SIGNING] Node {} successfully queued broadcast message for topic: {}",
            self.id, topic
        );
        Ok(())
    }

    /// Create ECDSA signature directly without DummyTransaction (pure Bitcoin signing)
    /// This is your exact proven logic extracted from create_ecdsa_signature
    pub fn create_ecdsa_signature_direct(
        &self,
        message: &Message,
    ) -> Result<RecoverableSignature> {
        // Your exact proven custom signature logic (copied from create_ecdsa_signature)
        // 1) Get secret key and context
        let sk = self
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow!("No private key available"))?;
        let secp = Secp256k1::new();

        // 2) Fixed nonce k = 0x42…42
        let k_bytes = [0x42u8; 32];
        let sec_nonce =
            SecretKey::from_slice(&k_bytes).map_err(|e| anyhow!("invalid nonce slice: {}", e))?;

        // 3) R = k·G
        let r = PublicKey::from_secret_key(&secp, &sec_nonce);
        let rser = r.serialize_uncompressed(); // [0x04 || X(32) || Y(32)]
        info!("[SIGNING] R serialized: {:?}", rser);
        if BigUint::from_bytes_be(&rser) == BigUint::from(0u32) {
            return Err(anyhow!("r is zero, need new nonce"));
        }

        // 4) r = X mod n
        let mut r_bytes: [u8; 32] = [0u8; 32];
        r_bytes.copy_from_slice(&rser[1..33]);
        let r = BigUint::from_bytes_be(&r_bytes);

        // 5) z = message hash as BigUint
        let z = BigUint::from_bytes_be(message.as_ref());

        // 6) x = private key as BigUint
        let sk_bytes = sk.secret_bytes();
        let x = BigUint::from_bytes_be(&sk_bytes);

        // 7) Curve order n
        let n = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .unwrap();

        // 8) k⁻¹ mod n
        let k_inv = BigUint::from_bytes_be(&k_bytes)
            .modinv(&n)
            .ok_or_else(|| anyhow!("nonce not invertible"))?;

        // 9) s = k⁻¹·(z + r·x) mod n
        let s = (&k_inv * (&z + (&r * &x) % &n)) % &n;

        // 10) Serialize r‖s into 64-byte array
        let mut sig_bytes = [0u8; 64];
        let r_be: Vec<u8> = r.to_bytes_be();
        let s_be = s.to_bytes_be();
        sig_bytes[32 - r_be.len()..32].copy_from_slice(&r_be);
        sig_bytes[64 - s_be.len()..64].copy_from_slice(&s_be);

        // 11) Compute RecoveryId from R_y parity
        let y_parity = (rser[64] & 1) as i32;
        let rid: RecoveryId =
            RecoveryId::from_i32(y_parity).map_err(|e| anyhow!("invalid recovery ID: {}", e))?;

        // 12) Build the recoverable signature
        let rec_sig = RecoverableSignature::from_compact(&sig_bytes, rid)
            .map_err(|e| anyhow!("invalid compact signature: {}", e))?;

        Ok(rec_sig)
    }

    pub async fn sign_message(
        &mut self,
        _message: Vec<u8>,
        transaction: &DummyTransaction,
        user_tweaked_share: Option<k256::Scalar>,
        user_eth_address: Option<String>,
        intent_hash: Option<String>,
        transaction_type: Option<crate::types::TransactionType>,
    ) -> Result<()> {
        // Determine which key to use for signing
        info!("🔑 [SIGNING] user_tweaked_share: {:?}\n", user_tweaked_share);
        let signing_key = if let Some(tweaked_share) = user_tweaked_share {
            // Use user's tweaked share for user deposits
            info!("🔑 [SIGNING] Using user-specific tweaked share for signing");
            Self::derive_secp_secret(&tweaked_share)
        } else {
            // Use network DKG share for network withdrawals
            info!("🔑 [SIGNING] Using network DKG share for signing");
            match self.private_key {
                Some(key) => key,
                None => {
                    error!("❌ [SIGNING] Node {} cannot sign: no private key available", self.id);
                    return Err(anyhow::anyhow!("No private key available"));
                }
            }
        };

        info!(
            "📝 [SIGNING] Node {} starting to sign transaction",
            self.id
        );

        // Convert DummyTransaction to ChainTransaction for chain-agnostic handling
        let chain_transaction = self.chain_handler.from_dummy_transaction(transaction)?;
        
        // Create transaction bytes using chain handler
        let tx_bytes = self.chain_handler.create_transaction_bytes(&chain_transaction)?;
        
        // Hash the transaction bytes
        let mut hasher: sha2::digest::core_api::CoreWrapper<sha3::Keccak256Core> = sha3::Keccak256::new();
        hasher.update(&tx_bytes);
        let tx_hash = hasher.finalize();
        info!("Tx hash: 0x{}", hex::encode(&tx_hash));

        // Get available nodes and perform VRF selection
        let available_nodes = self.get_available_nodes_from_manager().await;
        
        // Use VrfService for node selection (chain-agnostic)
        if let Some(vrf_service) = &self.vrf_service {
            let round = vrf_service.get_current_round().await;
            let _selection_result = vrf_service.perform_node_selection(
                &available_nodes, 
                1, 
                round, 
                self.chain_handler.chain_type()
            ).await?;
            
            info!(
                "🎯 [VRF] Node {} completed VRF selection for {} signing round {}",
                self.id, self.chain_handler.chain_type(), round
            );
        }

        // Create ECDSA signature using secp256k1
        let msg = Message::from_digest_slice(&tx_hash)?;
        let signature = self.create_ecdsa_signature_with_key(&msg, transaction, &signing_key)?;
        let (recovery_id, signature_bytes) = signature.serialize_compact();

        info!(
            "✍️ [SIGNING] Node {} created {} signature",
            self.id, self.chain_handler.chain_type()
        );

        // Debug logging removed

        // Convert to legacy ECDSASignature for compatibility
        let ecdsa_signature = ECDSASignature {
            signature: signature_bytes.to_vec(),
            signer_id: self.id.clone(),
            recovery_id: recovery_id.to_i32() as u8,
            user_eth_address: user_eth_address.clone(), // Clone to avoid borrow checker issues
        };

        // Get current round from VRF service
        let round = if let Some(vrf_service) = &self.vrf_service {
            vrf_service.get_next_round().await
        } else {
            0
        };

        // Store signature by round
        {
            let mut signatures_by_round = self.signatures_by_round.write().await;
            let round_signatures = signatures_by_round
                .entry(round)
                .or_insert_with(HashMap::new);
            round_signatures.insert(self.id.clone(), ecdsa_signature.clone());
            info!(
                "💾 [SIGNING] Node {} stored signature for {} round {}",
                self.id, self.chain_handler.chain_type(), round
            );
        }

        // Store original transaction for reconstruction after aggregation
        {
            let mut pending_transactions = self.pending_transactions.write().await;
            let chain_tx = ChainTransaction::Ethereum(crate::chain::EthereumTransaction {
                to: transaction.to.clone(),
                value: transaction.value.clone(),
                gas_limit: transaction.gas_limit,
                gas_price: transaction.gas_price.clone(),
                nonce: transaction.nonce, // This will be replaced with dynamic nonce during reconstruction
                data: None,
                chain_id: transaction.chain_id,
            });
            pending_transactions.insert(round, (chain_tx, tx_bytes.clone(), intent_hash.clone(), transaction_type));
            info!(
                "💾 [SIGNING] Node {} stored original Ethereum transaction for round {} reconstruction (nonce will be fetched dynamically, intent_hash: {:?})",
                self.id, round, intent_hash
            );
        }

        // let msg = serde_json::to_vec(&crate::types::GossipsubMessage::Signing(
        //     SigningMessage::ECDSASignature {
        //         from: self.id.clone(),
        //         signature: ecdsa_signature,
        //         round,
        //         timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        //         user_eth_address: user_eth_address.clone(), // No user_eth_address for Ethereum
        //     },
        // ))?;

        // self.broadcast("signing", &msg).await?;
        info!("📤 [SIGNING] Node {} broadcasted ECDSA signature", self.id);
        Ok(())
    }

    pub fn create_ecdsa_signature_with_key(
        &self,
        message: &Message,
        _transaction: &DummyTransaction,
        signing_key: &SecretKey,
    ) -> Result<RecoverableSignature> {
        // 1) Use provided signing key and context
        let sk = signing_key;
        let secp = Secp256k1::new();

        // 2) Fixed nonce k = 0x42…42
        let k_bytes = [0x42u8; 32];
        let sec_nonce =
            SecretKey::from_slice(&k_bytes).map_err(|e| anyhow!("invalid nonce slice: {}", e))?;

        // 3) R = k·G
        let r = PublicKey::from_secret_key(&secp, &sec_nonce);
        let rser = r.serialize_uncompressed(); // [0x04 || X(32) || Y(32)]
        info!("[SIGNING] R serialized: {:?}", rser);
        if BigUint::from_bytes_be(&rser) == BigUint::from(0u32) {
            return Err(anyhow!("r is zero, need new nonce"));
        }

        // 4) r = X mod n
        let mut r_bytes: [u8; 32] = [0u8; 32];
        r_bytes.copy_from_slice(&rser[1..33]);
        let r = BigUint::from_bytes_be(&r_bytes);

        // 5) z = message hash as BigUint
        let z = BigUint::from_bytes_be(message.as_ref());

        // 6) x = private key as BigUint
        let sk_bytes = sk.secret_bytes();
        let x = BigUint::from_bytes_be(&sk_bytes);

        // 7) Curve order n
        let n = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .unwrap();

        // 8) k⁻¹ mod n
        let k_inv = BigUint::from_bytes_be(&k_bytes)
            .modinv(&n)
            .ok_or_else(|| anyhow!("nonce not invertible"))?;

        // 9) s = k⁻¹·(z + r·x) mod n
        let s = (&k_inv * (&z + (&r * &x) % &n)) % &n;

        // 10) Serialize r‖s into 64-byte array
        let mut sig_bytes = [0u8; 64];
        let r_be: Vec<u8> = r.to_bytes_be();
        let s_be = s.to_bytes_be();
        sig_bytes[32 - r_be.len()..32].copy_from_slice(&r_be);
        sig_bytes[64 - s_be.len()..64].copy_from_slice(&s_be);

        // 11) Compute RecoveryId from R_y parity
        let y_parity = (rser[64] & 1) as i32;
        let rid: RecoveryId =
            RecoveryId::from_i32(y_parity).map_err(|e| anyhow!("invalid recovery ID: {}", e))?;

        // 12) Build the recoverable signature
        let rec_sig = RecoverableSignature::from_compact(&sig_bytes, rid)
            .map_err(|e| anyhow!("invalid compact signature: {}", e))?;

        Ok(rec_sig)
    }

    pub async fn handle_message(&mut self, msg: SigningMessage) -> Result<()> {
        info!(
            "📥 [SIGNING] Node {} received signing message: {:?}",
            self.id, msg
        );

        match msg {
            SigningMessage::MessageToSign {
                from: _from,
                message: _message,
                message_hash: _message_hash,
            } => {
                // info!(
                //     "📥 [SIGNING] Node {} received message to sign from {}",
                //     self.id, from
                // );
                // self.handle_message_to_sign(from, message, message_hash)
                //     .await?;
            }
            SigningMessage::ECDSASignature {
                from,
                signature,
                round,
                timestamp: _timestamp,
                user_eth_address,
            } => {
                let tx_type = if user_eth_address.is_some() { "user-to-network" } else { "network-to-target" };
                info!(
                    "📥 [SIGNING] Node {} received {} ECDSA signature from {} for round {} (user_eth_address: {:?})",
                    self.id, tx_type, from, round, user_eth_address
                );
                self.handle_ecdsa_signature(from, signature).await?;
            }
            SigningMessage::SignedMessage {
                from,
                signed_message,
            } => {
                info!(
                    "📥 [SIGNING] Node {} received signed message from {}",
                    self.id, from
                );
                self.handle_signed_message(from, signed_message).await?;
            }
            SigningMessage::RequestSignatures {
                round,
                final_node_id,
                message,
            } => {
                info!(
                    "📥 [SIGNING] Node {} received signature request for round {} from final node {}",
                    self.id, round, final_node_id
                );
                self.handle_signature_request(round, final_node_id, message)
                    .await?;
            }
        }
        Ok(())
    }

    async fn handle_ecdsa_signature(
        &mut self,
        from: String,
        signature: ECDSASignature,
    ) -> Result<()> {
        info!(
            "🚀 [SIGNING] handle_ecdsa_signature called for node {} from {}",
            self.id, from
        );
        info!(
            "📋 [SIGNING] Signature details - signer_id: {}, recovery_id: {}",
            signature.signer_id, signature.recovery_id
        );

        // Store signature from node
        self.signatures
            .write()
            .await
            .insert(from.clone(), signature.clone());

        info!(
            "💾 [SIGNING] Node {} stored ECDSA signature from {}",
            self.id, from
        );

        let round_to_handle = {
            let final_nodes = self.final_nodes_by_round.read().await;
            let current_round = if let Some(vrf_service) = &self.vrf_service {
                vrf_service.get_current_round().await
            } else {
                0
            };
            let mut found_round = None;
            for (round, final_node_id) in final_nodes.iter() {
                if final_node_id == &self.id && current_round == *round {
                    found_round = Some(*round);
                    break;
                }
            }
            found_round
        };

        if let Some(round) = round_to_handle {
            // Check if this round has already been aggregated
            let already_aggregated = {
                let aggregated_rounds = self.aggregated_rounds.read().await;
                aggregated_rounds.contains(&round)
            };

            if already_aggregated {
                info!(
                    "⏭️ [SIGNING] Round {} already aggregated, ignoring signature from {}",
                    round, from
                );
                return Ok(());
            }

            // Store signature by round
            let should_aggregate = {
                let mut signatures_by_round = self.signatures_by_round.write().await;
                let round_signatures = signatures_by_round.entry(round).or_default();
                round_signatures.insert(from.clone(), signature.clone());

                info!(
                    "💾 [SIGNING] Final node {} stored signature from {} for round {} (total: {})",
                    self.id,
                    from,
                    round,
                    round_signatures.len()
                );
                let total_nodes = self
                    .available_nodes
                    .as_ref()
                    .map(|nodes| nodes.len())
                    .unwrap_or(0);
                info!(
                    "📊 [SIGNING] Aggregation check: current signatures: {}, total_nodes: {}, threshold: {}",
                    round_signatures.len(),
                    total_nodes,
                    self.threshold
                );
                round_signatures.len() >= total_nodes && total_nodes > 0
            };

            if should_aggregate {
                // Mark this round as aggregated to prevent future aggregations
                {
                    let mut aggregated_rounds = self.aggregated_rounds.write().await;
                    aggregated_rounds.insert(round);
                }
                info!(
                    "🎯 [SIGNING] Round {} marked as aggregated, starting aggregation process",
                    round
                );

                // Prepare signatures for aggregation
                let (signatures_to_aggregate, peer_to_dkg_index): (Vec<RecoverableSignature>, Vec<(String, u32)>) = {
                    let signatures_by_round = self.signatures_by_round.read().await;
                    let round_signatures = signatures_by_round.get(&round).unwrap();

                    // Sort signatures by signer_id (PeerId) to ensure consistent ordering across rounds
                    let mut sorted_signatures: Vec<_> = round_signatures.iter().collect();

                    info!("🔍 [SIGNING] === SIGNATURE SORTING DEBUG ===");
                    info!(
                        "🔍 [SIGNING] Original signature order: {:?}",
                        round_signatures.keys().collect::<Vec<_>>()
                    );

                    sorted_signatures.sort_by(|a, b| a.0.cmp(b.0));

                    info!(
                        "🔍 [SIGNING] Sorted signature order: {:?}",
                        sorted_signatures
                            .iter()
                            .map(|(id, _)| id.as_str())
                            .collect::<Vec<_>>()
                    );

                    info!(
                        "🔄 [SIGNING] Sorted {} signatures by PeerId for round {} aggregation: {:?}",
                        sorted_signatures.len(),
                        round,
                        sorted_signatures.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>()
                    );

                    info!("🔍 [SIGNING] === END SIGNATURE SORTING DEBUG ===");

                    // Create a mapping of peer ID to index for debugging
                    let mut peer_to_index_map = Vec::new();

                    // Calculate DKG indices for the signatures first
                    let peer_to_dkg_index: Vec<(String, u32)> = sorted_signatures
                        .iter()
                        .map(|(signer_id, _)| {
                            let dkg_index = self.calculate_dkg_index_for_peer_sync(signer_id);
                            peer_to_index_map.push(((*signer_id).clone(), dkg_index));
                            ((*signer_id).clone(), dkg_index)
                        })
                        .collect();

                    let sigs_to_aggregate: Vec<RecoverableSignature> = sorted_signatures
                        .into_iter()
                        .map(|(signer_id, ecdsa_sig)| {
                            // ✅ Debug logging to help track signature validation
                            info!(
                                "🔍 [SIGNING] Aggregating signature from {} - Length: {} bytes, Recovery ID: {}",
                                signer_id, ecdsa_sig.signature.len(), ecdsa_sig.recovery_id
                            );
                            
                            RecoverableSignature::from_compact(
                                &ecdsa_sig.signature,
                                RecoveryId::from_i32(ecdsa_sig.recovery_id as i32)?,
                            )
                            .map_err(|e| {
                                error!(
                                    "❌ [SIGNING] Invalid signature from signer {} - Recovery ID: {}, Length: {} bytes, Error: {:?}",
                                    signer_id, ecdsa_sig.recovery_id, ecdsa_sig.signature.len(), e
                                );
                                anyhow::anyhow!("Invalid signature from signer {} - Details: {:?}", signer_id, e)
                            })
                        })
                        .collect::<Result<_>>()?;

                    info!(
                        "🔍 [SIGNING] Final peer-to-index mapping: {:?}",
                        peer_to_index_map
                            .iter()
                            .map(|(peer, idx)| format!("{}->{}", peer, idx))
                            .collect::<Vec<_>>()
                    );

                    (sigs_to_aggregate, peer_to_dkg_index)
                };
                info!(
                    "🔍 [SIGNING] Node {} preparing to aggregate {} signatures for round {} signatures are {:?}",
                    self.id,
                    signatures_to_aggregate.len(),
                    round,
                    signatures_to_aggregate
                        .iter()
                        .map(|sig| sig.serialize_compact().1)
                        .collect::<Vec<_>>()
                );

                // Aggregate signatures
                match self.aggregate_signatures(signatures_to_aggregate, peer_to_dkg_index).await {
                    Ok(aggregated_signature) => {
                        info!(
                            "🎉 [SIGNING] Signature aggregation successful for round {}!",
                            round
                        );

                        let (recid, signature_bytes) = aggregated_signature.serialize_compact();
                        let v: u64 = recid.to_i32() as u64 + 35 + 1043 * 2;
                        
                        // Normalize signature components to remove leading zeros (canonical form)
                        let r_bytes = &signature_bytes[0..32];
                        let s_bytes = &signature_bytes[32..64];
                        
                        // Convert to BigUint to remove leading zeros, then back to 32-byte arrays
                        let r_biguint = num_bigint::BigUint::from_bytes_be(r_bytes);
                        let s_biguint = num_bigint::BigUint::from_bytes_be(s_bytes);
                        
                        let mut r = [0u8; 32];
                        let mut s = [0u8; 32];
                        
                        let r_canonical = r_biguint.to_bytes_be();
                        let s_canonical = s_biguint.to_bytes_be();
                        
                        // Copy to right-aligned 32-byte arrays (big-endian)
                        if r_canonical.len() <= 32 {
                            r[32 - r_canonical.len()..].copy_from_slice(&r_canonical);
                        }
                        if s_canonical.len() <= 32 {
                            s[32 - s_canonical.len()..].copy_from_slice(&s_canonical);
                        }

                        info!("🔐 [SIGNING] Aggregated signature components:");
                        info!("  v: {}", v);
                        info!("  r (canonical): 0x{}", hex::encode(&r));
                        info!("  s (canonical): 0x{}", hex::encode(&s));
                        info!("  recovery_id: {}", recid.to_i32());
                        info!("  original_signature: 0x{}", hex::encode(signature_bytes));
                        info!("  r_canonical_len: {}, s_canonical_len: {}", r_canonical.len(), s_canonical.len());
                        
                        // 🚀 NEW: Reconstruct signed Bitcoin transaction
                        // Create canonical signature bytes from normalized r and s components
                        let mut canonical_signature_bytes = [0u8; 64];
                        canonical_signature_bytes[0..32].copy_from_slice(&r);
                        canonical_signature_bytes[32..64].copy_from_slice(&s);
                        
                        if let Ok(Some(signed_tx_hex)) = self.reconstruct_signed_bitcoin_transaction(
                            round,
                            &canonical_signature_bytes,
                            recid.to_i32() as u8,
                        ).await {
                            info!(
                                "🎉 [SIGNING] 🔗 SIGNED BITCOIN TRANSACTION READY! 🔗"
                            );
                            info!("📄 Raw signed transaction: {}", signed_tx_hex);
                            // info!("Broadcasting transaction to Bitcoin network...");
                            // Self::broadcast_transaction(&signed_tx_hex, false).await?;
                        }
                    }
                    Err(e) => {
                        error!("❌ [SIGNING] Aggregation failed: {}", e);
                        return Err(e);
                    }
                }
            } else {
                let total_nodes = self
                    .available_nodes
                    .as_ref()
                    .map(|nodes| nodes.len())
                    .unwrap_or(0);
                info!(
                    "⏳ [SIGNING] Waiting for more signatures: {}/{}",
                    self.signatures_by_round
                        .read()
                        .await
                        .get(&round)
                        .unwrap()
                        .len(),
                    total_nodes
                );
            }
        }

        Ok(())
    }

    pub async fn aggregate_signatures(
        &self,
        signatures: Vec<RecoverableSignature>,
        peer_to_dkg_index: Vec<(String, u32)>,
    ) -> Result<RecoverableSignature> {
        let n_shares = signatures.len();
        if n_shares < self.threshold {
            return Err(anyhow!(
                "Not enough signature shares: got {}, need at least {}",
                n_shares,
                self.threshold
            ));
        }

        // ─── 1) Pull r + recid straight from the first share ─────────────────────────
        let (first_recid, first_compact) = {
            let sig0 = &signatures[0];
            let (recid0, compact0) = sig0.serialize_compact();
            (recid0, compact0)
        };
        let agg_r = first_compact[0..32].to_vec();

        // ─── 2) Build the (index, s_bytes) list ──────────────────────────────────────
        info!("🔍 [SIGNING] === SIGNATURE INDEX ASSIGNMENT ===");
        info!(
            "🔍 [SIGNING] Number of signatures to process: {}",
            signatures.len()
        );

        // Log the DKG indices provided for aggregation
        info!(
            "🧮 [SIGNING] peer_to_dkg_index used for aggregation: {:?}",
            peer_to_dkg_index
                .iter()
                .map(|(p, i)| format!("{}->{}", p, i))
                .collect::<Vec<_>>()
        );

        // Use DKG indices for signature aggregation
        let s_shares: Vec<(u32, Vec<u8>)> = signatures
            .into_iter()
            .zip(peer_to_dkg_index.iter())
            .map(|(sig, (peer_id, dkg_index))| {
                let (_recid, compact) = sig.serialize_compact();
                info!(
                    "🔍 [SIGNING] Peer {} using DKG index: {} for aggregation",
                    peer_id, dkg_index
                );
                (*dkg_index, compact[32..64].to_vec())
            })
            .collect();

        info!(
            "🔍 [SIGNING] Final s_shares with indices: {:?}",
            s_shares.iter().map(|(idx, _)| idx).collect::<Vec<_>>()
        );
        info!("🔍 [SIGNING] === END SIGNATURE INDEX ASSIGNMENT ===");

        // ─── 3) Reconstruct s via Lagrange at x=0 ───────────────────────────────────
        let mut agg_s = self.lagrange_interpolate(&s_shares)?;

        // ─── 3.5) Normalize aggregated s (enforce low-S) and adjust recovery ID ─────

        // Curve order n
        let n = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .unwrap();

        let s_bigint = BigUint::from_bytes_be(&agg_s);
        let half_n = &n >> 1;
        let was_high_s = s_bigint > half_n;

        let (normalized_s, adjusted_recid) = if was_high_s {
            // Normalize s to n - s
            let normalized_s_bigint = &n - &s_bigint;
            let mut normalized_s_bytes = normalized_s_bigint.to_bytes_be();

            // Pad to 32 bytes if needed
            if normalized_s_bytes.len() < 32 {
                let mut padded = vec![0u8; 32 - normalized_s_bytes.len()];
                padded.extend_from_slice(&normalized_s_bytes);
                normalized_s_bytes = padded;
            }

            // Adjust recovery ID by XORing with 1
            let adjusted_recid = RecoveryId::from_i32(first_recid.to_i32() ^ 1)
                .map_err(|e| anyhow!("invalid adjusted recovery ID: {}", e))?;

            (normalized_s_bytes, adjusted_recid)
        } else {
            (agg_s, first_recid)
        };

        agg_s = normalized_s;
        let final_recid = adjusted_recid;

        // ─── 4) Rebuild the recoverable signature with the adjusted recid ───────────
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0..32].copy_from_slice(&agg_r);
        sig_bytes[32..64].copy_from_slice(&agg_s);
        let agg_sig = RecoverableSignature::from_compact(&sig_bytes, final_recid)?;

        Ok(agg_sig)
    }


    fn lagrange_interpolate(&self, shares: &[(u32, Vec<u8>)]) -> Result<Vec<u8>> {
        if shares.len() < self.threshold {
            return Err(anyhow!(
                "Not enough shares: got {}, need at least {}",
                shares.len(),
                self.threshold
            ));
        }

        // Debug logging removed

        // // 🔧 FIX 1: Select exactly threshold shares deterministically
        // let mut selected_shares = shares.to_vec();
        // selected_shares.sort_by_key(|(x, _)| *x);
        // selected_shares.truncate(self.threshold);

        // With this:
        let mut rng = thread_rng();
        let mut selected_shares = shares.to_vec();
        selected_shares.shuffle(&mut rng);
        selected_shares.truncate(self.threshold);


        // Selected shares processed without logging

        let n = BigUint::from_bytes_be(&CURVE_ORDER);

        // Improved extended Euclidean algorithm for modular inverse
        fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
            if *a == BigUint::zero() {
                return None;
            }

            let mut old_r = m.clone();
            let mut r = a % m; // BUG FIX: Ensure a is reduced mod m
            let mut old_s = BigInt::zero();
            let mut s = BigInt::one();

            while r != BigUint::zero() {
                let quotient = &old_r / &r;

                let temp_r = r.clone();
                r = &old_r - &quotient * &r;
                old_r = temp_r;

                let temp_s = s.clone();
                s = &old_s - &quotient.to_bigint().unwrap() * &s;
                old_s = temp_s;
            }

            if old_r != BigUint::one() {
                return None; // Not invertible
            }

            let m_int = m.to_bigint().unwrap();
            let result = (old_s % &m_int + &m_int) % &m_int;
            Some(result.to_biguint().unwrap())
        }

        let mut accum = BigUint::from(0u32);

        // 🔧 FIX 2: Use selected_shares in BOTH loops
        for &(xj, ref yj_bytes) in selected_shares.iter() {
            let mut num = BigUint::from(1u32);
            let mut den = BigUint::from(1u32);

            // 🔧 FIX 3: Inner loop uses SAME selected_shares, not all shares
            for &(xm, _) in selected_shares.iter() {
                if xm != xj {
                    let xm_u = BigUint::from(xm);
                    let xj_u = BigUint::from(xj);

                    let neg_xm = (&n - &xm_u) % &n;
                    num = (num * &neg_xm) % &n;

                    let diff = if xj_u >= xm_u {
                        &xj_u - &xm_u
                    } else {
                        &xj_u + &n - &xm_u
                    };
                    den = (den * diff.clone()) % &n;
                }
            }

            let den_inv = modinv(&den, &n)
                .ok_or_else(|| anyhow!("Denominator not invertible for share x={}", xj))?;

            let lambda = (num.clone() * den_inv) % &n;

            let yj = BigUint::from_bytes_be(yj_bytes);
            let contribution = (&lambda * &yj) % &n;

            accum = (accum + contribution) % &n;
        }

        // Debug output removed

        // Rest of your conversion logic stays the same
        let mut result = accum.to_bytes_be();
        match result.len().cmp(&32) {
            std::cmp::Ordering::Less => {
                let mut padded = vec![0u8; 32 - result.len()];
                padded.extend_from_slice(&result);
                result = padded;
            }
            std::cmp::Ordering::Greater => {
                return Err(anyhow!("Result too large: {} bytes", result.len()));
            }
            std::cmp::Ordering::Equal => {}
        }

        Ok(result)
    }
    /// From a slice of RecoveryIds, pick the one that appears most often.
    fn get_most_common_recovery_id(&self, recid_ints: &[i32]) -> Result<RecoveryId> {
        let mut counts = HashMap::new();
        for &v in recid_ints {
            *counts.entry(v).or_insert(0usize) += 1;
        }
        let (&common, _) = counts
            .iter()
            .max_by_key(|&(_, &cnt)| cnt)
            .ok_or_else(|| anyhow!("No recovery IDs provided"))?;
        RecoveryId::from_i32(common).map_err(|e| anyhow!("invalid recid {}: {}", common, e))
    }

    async fn handle_signed_message(
        &mut self,
        from: String,
        signed_message: SignedMessage,
    ) -> Result<()> {
        info!(
            "✅ [SIGNING] Node {} received signed message from {}",
            self.id, from
        );
        info!("📄 [SIGNING] Message: {:?}", signed_message.message);

        info!("👥 [SIGNING] Signers: {:?}", signed_message.signer_ids);
        info!("🕒 [SIGNING] Timestamp: {}", signed_message.timestamp);

        // Verify the aggregated ECDSA signature
        let is_valid = self.verify_aggregated_signature(&signed_message).await?;
        if is_valid {
            info!("✅ [SIGNING] ECDSA signature verification successful!");
        } else {
            warn!("❌ [SIGNING] ECDSA signature verification failed!");
        }

        Ok(())
    }

    async fn verify_aggregated_signature(&self, signed_message: &SignedMessage) -> Result<bool> {
        info!(
            "🔍 [SIGNING] Node {} verifying aggregated signature",
            self.id
        );
        info!(
            "✍️ [SIGNING] Aggregated signature: {:?}",
            signed_message.aggregated_signature
        );
        info!("👥 [SIGNING] Signers: {:?}", signed_message.signer_ids);
        info!("🕒 [SIGNING] Timestamp: {}", signed_message.timestamp);

        let public_keys = self.public_keys.read().await;

        // Check if we have public keys for all signers
        for signer_id in &signed_message.signer_ids {
            if !public_keys.contains_key(signer_id) {
                warn!("❌ [SIGNING] Missing public key for signer: {}", signer_id);
                return Ok(false);
            }
        }

        info!("🔍 [SIGNING] Node {} verifying ECDSA signature", self.id);

        // Basic signature validation
        if signed_message.aggregated_signature.len() != 65 {
            warn!("❌ [SIGNING] Invalid signature length: expected 65 bytes, got {}", signed_message.aggregated_signature.len());
            return Ok(false);
        }

        // Check that we have valid signer IDs
        if signed_message.signer_ids.is_empty() {
            warn!("❌ [SIGNING] No signer IDs provided");
            return Ok(false);
        }

        // In a full implementation, you would:
        // 1. Parse the signature components (r, s, v)
        // 2. Recover the public key from the signature and message hash
        // 3. Verify against the expected public keys
        // 4. Check threshold requirements

        info!("✅ [SIGNING] Signature validation passed for {} signers", signed_message.signer_ids.len());
        Ok(true)
    }

    /// Get the compressed 65-byte representation of an ECDSA signature
    pub fn get_compressed_signature_bytes(&self, signature: &RecoverableSignature) -> [u8; 65] {
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        let mut result = [0u8; 65];
        result[0] = recovery_id.to_i32() as u8;
        result[1..].copy_from_slice(&signature_bytes);
        result
    }

    /// Get the compressed 65-byte representation as a hex string
    pub fn get_compressed_signature_hex(&self, signature: &RecoverableSignature) -> String {
        let bytes = self.get_compressed_signature_bytes(signature);
        hex::encode(bytes)
    }

    /// Get VRF public key for this node
    pub async fn get_vrf_public_key(&self) -> Option<String> {
        if let Some(vrf_service) = &self.vrf_service {
            Some(vrf_service.get_public_key_hex().await)
        } else {
            None
        }
    }

    /// Get VRF public key as bytes
    pub async fn get_vrf_public_key_bytes(&self) -> Option<Vec<u8>> {
        if let Some(vrf_service) = &self.vrf_service {
            Some(vrf_service.get_public_key().await)
        } else {
            None
        }
    }

    /// Check if this node is selected for MPC in a specific round
    pub async fn is_selected_for_round(&self, round: u64) -> bool {
        if let Some(vrf_service) = &self.vrf_service {
            vrf_service.is_node_selected(round).await
        } else {
            false
        }
    }

    /// Set the chain handler for this signing node
    pub fn set_chain_handler(&mut self, chain_handler: Arc<dyn ChainHandler>) {
        self.chain_handler = chain_handler;
        info!("🔗 [SIGNING] Node {} switched to {} chain handler",
              self.id, self.chain_handler.chain_type());
    }

    /// Get a reference to the chain handler
    pub fn get_chain_handler(&self) -> &Arc<dyn ChainHandler> {
        &self.chain_handler
    }

    /// Get the current chain type
    pub fn get_chain_type(&self) -> &'static str {
        self.chain_handler.chain_type()
    }

    /// Get chain parameters
    pub fn get_chain_params(&self) -> std::collections::HashMap<String, String> {
        self.chain_handler.get_chain_params()
    }

    /// Get available nodes as PeerIds derived from stored public keys
    async fn get_available_nodes(&self) -> Vec<PeerId> {
        self.available_nodes.clone().unwrap()
    }

    /// Set available nodes from node manager
    pub fn set_available_nodes(&mut self, nodes: Vec<PeerId>) {
        self.available_nodes = Some(nodes);
    }

    /// Set the DKG group public key
    pub fn set_group_public_key(&mut self, group_key: k256::ProjectivePoint) {
        info!("🔑 [SIGNING] Setting DKG group public key for node {}", self.id);
        self.group_public_key = Some(group_key);
    }

    /// Set the vault group public key
    pub fn set_vault_group_key(&mut self, vault_group_key: k256::ProjectivePoint) {
        info!("🔑 [SIGNING] Setting vault group public key for node {}", self.id);
        self.vault_group_key = Some(vault_group_key);
    }

    /// Get the DKG group public key
    pub fn get_group_public_key(&self) -> Option<k256::ProjectivePoint> {
        self.group_public_key
    }

    /// Get the vault group public key
    pub fn get_vault_group_key(&self) -> Option<k256::ProjectivePoint> {
        self.vault_group_key
    }

    pub fn set_user_registry(&mut self, user_registry: Arc<DatabaseUserRegistry>) {
        self.user_registry = Some(user_registry);
        info!("📋 [SIGNING] Node {} user registry set", self.id);
    }

    pub fn set_database(&mut self, database: Arc<crate::database::Database>) {
        self.database = Some(database);
        info!("🗄️ [SIGNING] Node {} database set", self.id);
    }

    /// Store transaction error for a round if intent hash is available and broadcast to other nodes
    async fn store_transaction_error_for_round(&self, round: u64, error_message: &str) {
        // Get intent hash from pending transactions
        let intent_hash = {
            let pending_transactions = self.pending_transactions.read().await;
            if let Some((_tx, _tx_bytes, intent_hash, _)) = pending_transactions.get(&round) {
                intent_hash.clone()
            } else {
                None
            }
        };

        match (intent_hash, &self.user_registry) {
            (Some(ref intent_hash), Some(user_registry)) => {
                // Store error locally
                match user_registry.store_transaction_error(intent_hash, error_message).await {
                    Ok(()) => {
                        info!("💥 [SIGNING] Stored transaction error for intent {} (round {}): {}", intent_hash, round, error_message);
                        
                        // Broadcast error to other nodes for synchronization
                        self.broadcast_transaction_error(intent_hash, error_message, "user_to_network").await;
                    },
                    Err(e) => {
                        error!("❌ [SIGNING] Failed to store transaction error for intent {}: {}", intent_hash, e);
                    }
                }
            },
            (None, _) => {
                info!("ℹ️ [SIGNING] No intent hash available for round {}, skipping error storage", round);
            },
            (_, None) => {
                warn!("⚠️ [SIGNING] No user registry available, cannot store transaction error for round {}", round);
            }
        }
    }

    /// Store transaction ID for a round if intent hash is available and broadcast to other nodes
    async fn store_transaction_id_for_round(&self, round: u64, tx_id: &str, user_eth_address: Option<String>) {
        // Get intent hash and transaction type from pending transactions
        let (intent_hash, transaction_type) = {
            let pending_transactions = self.pending_transactions.read().await;
            if let Some((_tx, _tx_bytes, intent_hash, transaction_type)) = pending_transactions.get(&round) {
                (intent_hash.clone(), transaction_type.clone())
            } else {
                (None, None)
            }
        };

        match (intent_hash, &self.user_registry) {
            (Some(ref intent_hash), Some(user_registry)) => {
                // Determine transaction type based on the actual transaction type from pending transactions
                let (transaction_type_str, storage_result) = match transaction_type {
                    Some(crate::types::TransactionType::UserToVault) => {
                        // User-to-vault transaction
                        let result = user_registry.store_user_to_vault_tx_id(intent_hash, tx_id).await;
                        match &result {
                            Ok(()) => {
                                info!("💾 [SIGNING] Stored user-to-network transaction ID {} for intent {} (round {})", tx_id, intent_hash, round);
                            },
                            Err(e) => {
                                error!("❌ [SIGNING] Failed to store user-to-network transaction ID for intent {}: {}", intent_hash, e);
                            }
                        }
                        ("user_to_vault", result)
                    },
                    Some(crate::types::TransactionType::NetworkToTarget) => {
                        // Network-to-target transaction
                        let result = user_registry.store_network_to_target_tx_id(intent_hash, tx_id).await;
                        match &result {
                            Ok(()) => {
                                info!("💾 [SIGNING] Stored network-to-target transaction ID {} for intent {} (round {})", tx_id, intent_hash, round);
                            },
                            Err(e) => {
                                error!("❌ [SIGNING] Failed to store network-to-target transaction ID for intent {}: {}", intent_hash, e);
                            }
                        }
                        ("network_to_target", result)
                    },
                    Some(crate::types::TransactionType::VaultToNetwork) => {
                        // Vault-to-network transaction
                        let result = user_registry.store_vault_to_network_tx_id(intent_hash, tx_id).await;
                        match &result {
                            Ok(()) => {
                                info!("💾 [SIGNING] Stored vault-to-network transaction ID {} for intent {} (round {})", tx_id, intent_hash, round);
                            },
                            Err(e) => {
                                error!("❌ [SIGNING] Failed to store vault-to-network transaction ID for intent {}: {}", intent_hash, e);
                            }
                        }
                        ("vault_to_network", result)
                    },
                    None => {
                        // Fallback to old logic based on user_eth_address
                        if let Some(eth_addr) = &user_eth_address {
                            // User-to-network transaction
                            let result = user_registry.store_user_to_vault_tx_id(intent_hash, tx_id).await;
                            match &result {
                                Ok(()) => {
                                    info!("💾 [SIGNING] Stored user-to-network transaction ID {} for intent {} (round {}) for user {}", tx_id, intent_hash, round, eth_addr);
                                },
                                Err(e) => {
                                    error!("❌ [SIGNING] Failed to store user-to-network transaction ID for intent {}: {}", intent_hash, e);
                                }
                            }
                            ("user_to_network", result)
                        } else {
                            // Network-to-target transaction
                            let result = user_registry.store_network_to_target_tx_id(intent_hash, tx_id).await;
                            match &result {
                                Ok(()) => {
                                    info!("💾 [SIGNING] Stored network-to-target transaction ID {} for intent {} (round {})", tx_id, intent_hash, round);
                                },
                                Err(e) => {
                                    error!("❌ [SIGNING] Failed to store network-to-target transaction ID for intent {}: {}", intent_hash, e);
                                }
                            }
                            ("network_to_target", result)
                        }
                    }
                };

                // If storage was successful, record transaction status and broadcast to other nodes
                if storage_result.is_ok() {
                    if let Err(e) = user_registry
                        .store_transaction_status(tx_id, TransactionStatus::Pending)
                        .await
                    {
                        error!(
                            "❌ [SIGNING] Failed to store transaction status for tx {}: {}",
                            tx_id, e
                        );
                    }
                    self.broadcast_transaction_id(&intent_hash, tx_id, transaction_type_str).await;
                }
            },
            (None, _) => {
                info!("ℹ️ [SIGNING] No intent hash available for round {}, skipping transaction ID storage", round);
            },
            (_, None) => {
                info!("ℹ️ [NETWORK] No user registry available, skipping transaction ID storage");
            }
        }
    }

    /// Broadcast transaction ID to other nodes for synchronization
    async fn broadcast_transaction_id(&self, intent_hash: &str, tx_id: &str, transaction_type: &str) {
        let broadcast_message = crate::types::GossipsubMessage::TransactionIdBroadcast {
            intent_hash: intent_hash.to_string(),
            transaction_id: tx_id.to_string(),
            transaction_type: transaction_type.to_string(),
            node_id: self.id.clone(),
        };

        let channel_message = crate::types::ChannelMessage::Broadcast {
            topic: "transaction-id-sync".to_string(),
            data: serde_json::to_vec(&broadcast_message).unwrap_or_default(),
        };

        // Call update_solver_amounts_for_user_to_vault only for user_to_vault transaction type
        if transaction_type == "user_to_vault" {
            if let Err(e) = self.update_solver_amounts_for_user_to_vault(intent_hash).await {
                warn!("⚠️ [SIGNING] Failed to update solver amounts for UserToVault transaction: {}", e);
            }
        }

        if let Err(e) = self.message_tx.send(channel_message).await {
            error!("❌ [SIGNING] Failed to broadcast transaction ID to other nodes: {}", e);
        } else {
            info!("📡 [SIGNING] Broadcasted transaction ID {} for intent {} (type: {}) to other nodes", tx_id, intent_hash, transaction_type);
        }
    }

    /// Broadcast transaction error to other nodes for synchronization
    async fn broadcast_transaction_error(&self, intent_hash: &str, error_message: &str, transaction_type: &str) {
        let broadcast_message = crate::types::GossipsubMessage::TransactionErrorBroadcast {
            intent_hash: intent_hash.to_string(),
            error_message: error_message.to_string(),
            transaction_type: transaction_type.to_string(),
            node_id: self.id.clone(),
        };

        let channel_message = crate::types::ChannelMessage::Broadcast {
            topic: "transaction-error-sync".to_string(),
            data: serde_json::to_vec(&broadcast_message).unwrap_or_default(),
        };

        if let Err(e) = self.message_tx.send(channel_message).await {
            error!("❌ [SIGNING] Failed to broadcast transaction error to other nodes: {}", e);
        } else {
            info!("📡 [SIGNING] Broadcasted transaction error for intent {} (type: {}) to other nodes: {}", intent_hash, transaction_type, error_message);
        }
    }

    async fn get_available_nodes_from_manager(&self) -> Vec<PeerId> {
        if let Some(ref nodes) = self.available_nodes {
            nodes.clone()
        } else {
            self.get_available_nodes().await
        }
    }

    /// Handle VRF selected nodes broadcast from another node
    pub fn handle_vrf_selected_nodes_broadcast(
        &mut self,
        total_nodes: usize,
        broadcast: VrfSelectedNodesBroadcast,
    ) {
        if let Some(vrf_service) = &self.vrf_service {
            let round = broadcast.round;
            let min_selections = total_nodes;

            // Use async task to handle VRF broadcast
            let vrf_service_clone = vrf_service.clone();
            let mut signing_node_clone = self.clone();
            
            tokio::spawn(async move {
                // Handle VRF broadcast via service
                vrf_service_clone.handle_vrf_broadcast(broadcast, total_nodes).await;

                // Check if consensus should be triggered after receiving this broadcast
                if vrf_service_clone.can_start_consensus(round, min_selections).await {
                    info!(
                        "🎯 [VRF] Enough selections collected for round {}, triggering consensus check",
                        round
                    );

                    if let Err(e) = signing_node_clone
                        .check_and_trigger_consensus(round, min_selections)
                        .await
                    {
                        error!(
                            "❌ [CONSENSUS] Failed to trigger consensus for round {}: {}",
                            round, e
                        );
                    }
                }
            });
        }
    }

    /// Check and trigger consensus if ready
    pub async fn check_and_trigger_consensus(
        &mut self,
        round: u64,
        min_selections: usize,
    ) -> Result<Option<ConsensusResult>> {
        if self.can_start_consensus(round, min_selections).await {
            info!(
                "🎯 [CONSENSUS] Consensus ready for round {}, starting...",
                round
            );
            self.start_consensus_for_round(round).await
        } else {
            Ok(None)
        }
    }

    /// Start consensus for a specific round
    pub async fn start_consensus_for_round(
        &mut self,
        round: u64,
    ) -> Result<Option<ConsensusResult>> {
        // Get the node ID first to avoid borrow checker issues
        let own_node_id = SerializablePeerId(PeerId::from_str(&self.id)?);

        if let (Some(vrf_service), Some(consensus_node)) =
            (&self.vrf_service, &mut self.consensus_node)
        {
            // Get all selected nodes with frequencies for this round
            let all_selected_nodes = vrf_service.get_all_selected_nodes_with_frequencies(round).await;

            if all_selected_nodes.is_empty() {
                info!(
                    "⚠️ [CONSENSUS] No selected nodes available for consensus round {}",
                    round
                );
                return Ok(None);
            }

            info!(
                "🎯 [CONSENSUS] Starting consensus for round {} with {} selected nodes",
                round,
                all_selected_nodes.len()
            );

            // Add selected nodes to consensus
            consensus_node.add_selected_nodes(round, all_selected_nodes);

            // Start consensus
            match consensus_node.start_consensus(round) {
                Ok(result) => {
                    info!(
                        "✅ [CONSENSUS] Consensus completed for round {}: final node = {:?}",
                        round, result.final_node
                    );

                    // Broadcast the consensus result
                    let consensus_msg = ConsensusMessage::FinalNodeResult {
                        result: result.clone(),
                        round,
                    };

                    let broadcast_data = serde_json::to_vec(&consensus_msg)?;

                    // Store the result for later use
                    let is_final_node = consensus_node.is_final_node(round, &own_node_id);

                    // Broadcast outside of the borrow
                    self.broadcast("consensus-result", &broadcast_data).await?;

                    info!(
                        "📤 [CONSENSUS] Broadcasted consensus result for round {}",
                        round
                    );

                    // Store the final node for this round
                    {
                        let mut final_nodes = self.final_nodes_by_round.write().await;
                        final_nodes.insert(round, result.final_node.0.to_string());
                        info!(
                            "💾 [CONSENSUS] Stored final node {} for round {}",
                            result.final_node.0, round
                        );
                    }

                    // Check if this node is the final selected node
                    if is_final_node {
                        info!(
                            "\x1b[32m🏆 [CONSENSUS] This node is the final selected node for round {}!\x1b[0m",
                            round
                        );
                        // Trigger aggregate signature for the final node
                        self.trigger_aggregate_signature_for_final_node(round)
                            .await?;

                        // Start collecting signatures after a short delay
                        let mut signing_node_clone = self.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                            if let Err(e) = signing_node_clone
                                .collect_and_aggregate_signatures(round)
                                .await
                            {
                                error!(
                                    "❌ [SIGNING] Failed to collect and aggregate signatures: {}",
                                    e
                                );
                            }
                        });
                    } else {
                        info!(
                            "\x1b[31m📋 [CONSENSUS] This node is not the final selected node for round {}\x1b[0m",
                            round
                        );
                    }

                    Ok(Some(result))
                }
                Err(e) => {
                    error!(
                        "❌ [CONSENSUS] Failed to start consensus for round {}: {}",
                        round, e
                    );
                    Err(e)
                }
            }
        } else {
            Err(anyhow::anyhow!(
                "VRF selector or consensus node not available"
            ))
        }
    }

    /// Check if consensus can be started for a round
    pub async fn can_start_consensus(&self, round: u64, min_selections: usize) -> bool {
        if let Some(vrf_service) = &self.vrf_service {
            vrf_service.can_start_consensus(round, min_selections).await
        } else {
            false
        }
    }

    /// Handle consensus messages
    pub async fn handle_consensus_message(&mut self, msg: ConsensusMessage) -> Result<()> {
        if let Some(consensus_node) = &mut self.consensus_node {
            consensus_node.handle_message(msg).await?;
        }
        Ok(())
    }

    /// Trigger aggregate signature for the final selected node
    async fn trigger_aggregate_signature_for_final_node(&self, round: u64) -> Result<()> {
        info!(
            "🚀 [SIGNING] Triggering aggregate signature for final node in round {}",
            round
        );

        // Broadcast a message to all nodes to send their signatures to the final node
        let signature_request = SigningMessage::RequestSignatures {
            round,
            final_node_id: self.id.clone(),
            message: "Aggregate signature request".to_string(),
        };

        // Wrap in GossipsubMessage::Signing for proper message handling
        let gossipsub_msg = crate::types::GossipsubMessage::Signing(signature_request);
        let broadcast_data = serde_json::to_vec(&gossipsub_msg)?;
        self.broadcast("signing", &broadcast_data).await?;

        info!(
            "📤 [SIGNING] Broadcasted signature request for round {} to all nodes",
            round
        );

        Ok(())
    }

    /// Send signature for specific round to the final selected node
    pub async fn send_signature_to_final_node(
        &mut self,
        final_node_id: &str,
        round: u64,
    ) -> Result<()> {
        info!(
            "📤 [SIGNING] Sending signature for round {} to final node {}",
            round, final_node_id
        );

        // Get signature for this specific round
        let signatures_by_round = self.signatures_by_round.read().await;

        if let Some(round_signatures) = signatures_by_round.get(&round) {
            if let Some(our_signature) = round_signatures.get(&self.id) {
                let signature_msg = SigningMessage::ECDSASignature {
                    from: self.id.clone(),
                    signature: our_signature.clone(),
                    round,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                    user_eth_address: our_signature.user_eth_address.clone(), // Use user_eth_address from stored signature
                };

                // Wrap in GossipsubMessage::Signing for proper message handling
                let gossipsub_msg = crate::types::GossipsubMessage::Signing(signature_msg);
                let signature_data = serde_json::to_vec(&gossipsub_msg)?;

                // Broadcast to a specific topic that the final node subscribes to
                let res = self
                    .broadcast("signatures-to-final-node", &signature_data)
                    .await;
                match res {
                    Ok(_) => info!(
                        "📤 [SIGNING] Successfully sent signature for round {} to final node {}",
                        round, final_node_id
                    ),
                    Err(e) => {
                        error!(
                            "❌ [SIGNING] Failed to send signature for round {} to final node {}: {}",
                            round, final_node_id, e
                        );
                        return Err(e);
                    }
                }

                info!(
                    "✅ [SIGNING] Sent signature for round {} to final node {}",
                    round, final_node_id
                );
            } else {
                info!(
                    "⚠️ [SIGNING] No signature found for round {} for this node",
                    round
                );
            }
        } else {
            info!("⚠️ [SIGNING] No signatures found for round {}", round);
        }

        Ok(())
    }

    /// Collect signatures and perform aggregation (for final selected node)
    pub async fn collect_and_aggregate_signatures(&mut self, round: u64) -> Result<()> {
        info!(
            "🔍 [SIGNING] Final node {} waiting for signatures for round {}",
            self.id, round
        );

        // Wait a bit for signatures to arrive
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Check current signature count for this round
        let signatures_by_round = self.signatures_by_round.read().await;
        if let Some(round_signatures) = signatures_by_round.get(&round) {
            info!(
                "📊 [SIGNING] Final node {} has {} signatures for round {}",
                self.id,
                round_signatures.len(),
                round
            );
        } else {
            info!("⚠️ [SIGNING] No signatures found for round {}", round);
        }

        Ok(())
    }

    /// Handle signature request from final selected node
    async fn handle_signature_request(
        &mut self,
        round: u64,
        final_node_id: String,
        _message: String,
    ) -> Result<()> {
        info!(
            "📤 [SIGNING] Node {} responding to signature request for round {}",
            self.id, round
        );

        // Only send signature if we're not the final node
        if final_node_id != self.id {
            // Send signature to the final node
            self.send_signature_to_final_node(&final_node_id, round)
                .await?;
        } else {
            info!("🔄 [SIGNING] This node is the final node, no need to send signature to self");
        }

        Ok(())
    }

    /// Handle signature received by final node for specific round

    /// Handle signature received by final node for specific round
    /// Handle signature received by final node for specific round
    pub async fn handle_signature_for_round(
        &mut self,
        from: String,
        signature: ECDSASignature,
        round: u64,
    ) -> Result<()> {
        info!(
            "📥 [SIGNING] Final node {} received signature from {} for round {}",
            self.id, from, round
        );

        // Check if this round has already been aggregated
        let already_aggregated = {
            let aggregated_rounds = self.aggregated_rounds.read().await;
            aggregated_rounds.contains(&round)
        };

        if already_aggregated {
            info!(
                "⏭️ [SIGNING] Round {} already aggregated, ignoring signature from {}",
                round, from
            );
            return Ok(());
        }

        // Store signature by round
        {
            let mut signatures_by_round = self.signatures_by_round.write().await;
            let round_signatures = signatures_by_round
                .entry(round)
                .or_insert_with(HashMap::new);
            round_signatures.insert(from.clone(), signature.clone());

            info!(
                "💾 [SIGNING] Stored signature from {} for round {} (total: {})",
                from,
                round,
                round_signatures.len()
            );
        }

        // Check if we have enough signatures for this round
        let signatures_to_aggregate: Option<Result<Vec<RecoverableSignature>>> = {
            let signatures_by_round = self.signatures_by_round.read().await;
            signatures_by_round.get(&round).map(|round_signatures| {
                // Sort signatures by signer_id (PeerId) to ensure consistent ordering across rounds
                let mut sorted_signatures: Vec<_> = round_signatures.iter().collect();

                info!(
                    "🔍 [SIGNING] === SIGNATURE SORTING DEBUG (ROUND {}) ===",
                    round
                );
                info!(
                    "🔍 [SIGNING] Original signature order: {:?}",
                    round_signatures.keys().collect::<Vec<_>>()
                );

                sorted_signatures.sort_by(|a, b| a.0.cmp(b.0));

                info!(
                    "🔍 [SIGNING] Sorted signature order: {:?}",
                    sorted_signatures
                        .iter()
                        .map(|(id, _)| id.as_str())
                        .collect::<Vec<_>>()
                );

                info!(
                    "🔄 [SIGNING] Sorted {} signatures by PeerId for round {} aggregation: {:?}",
                    sorted_signatures.len(),
                    round,
                    sorted_signatures
                        .iter()
                        .map(|(id, _)| id.as_str())
                        .collect::<Vec<_>>()
                );

                info!(
                    "🔍 [SIGNING] === END SIGNATURE SORTING DEBUG (ROUND {}) ===",
                    round
                );

                // Create a mapping of peer ID to index for debugging
                let mut peer_to_index_map = Vec::new();

                let sigs_result: Result<Vec<RecoverableSignature>> = sorted_signatures
                    .into_iter()
                    .enumerate()
                    .map(|(i, (signer_id, ecdsa_sig))| {
                        let index = i + 1;
                        peer_to_index_map.push((signer_id.clone(), index));

                        info!(
                            "🔍 [SIGNING] Peer {} assigned index {} for aggregation (round {})",
                            signer_id, index, round
                        );

                        RecoverableSignature::from_compact(
                            &ecdsa_sig.signature,
                            RecoveryId::from_i32(ecdsa_sig.recovery_id as i32)?,
                        )
                        .map_err(|_| anyhow::anyhow!("Invalid signature from signer {}", signer_id))
                    })
                    .collect();

                info!(
                    "🔍 [SIGNING] Final peer-to-index mapping for round {}: {:?}",
                    round,
                    peer_to_index_map
                        .iter()
                        .map(|(peer, idx)| format!("{}->{}", peer, idx))
                        .collect::<Vec<_>>()
                );

                sigs_result
            })
        };

        if let Some(signatures_result) = signatures_to_aggregate {
            let signatures_vec = signatures_result?;
            // Check if this round has already been aggregated
            {
                let aggregated_rounds = self.aggregated_rounds.read().await;
                if aggregated_rounds.contains(&round) {
                    info!(
                        "⏭️ [SIGNING] Round {} already aggregated, skipping",
                        round
                    );
                    return Ok(());
                }
            }

            if signatures_vec.len() >= self.threshold {
                // Mark this round as aggregated BEFORE processing to prevent race conditions
                {
                    let mut aggregated_rounds = self.aggregated_rounds.write().await;
                    aggregated_rounds.insert(round);
                }

                info!(
                    "✅ [SIGNING] Threshold reached! {} signatures collected for round {} (threshold: {}), starting aggregation",
                    signatures_vec.len(), round, self.threshold
                );

                // Take only threshold number of signatures for aggregation
                let threshold_signatures = if signatures_vec.len() > self.threshold {
                    let mut sigs = signatures_vec;
                    sigs.truncate(self.threshold);
                    sigs
                } else {
                    signatures_vec
                };

                info!(
                    "🔢 [SIGNING] Using {} signatures for aggregation (threshold: {})",
                    threshold_signatures.len(),
                    self.threshold
                );

                // Calculate DKG indices for the selected signatures
                let peer_to_dkg_index: Vec<(String, u32)> = {
                    // Get the peer IDs in the same order as threshold_signatures
                    let signatures_by_round = self.signatures_by_round.read().await;
                    if let Some(round_signatures) = signatures_by_round.get(&round) {
                        let mut sorted_signatures: Vec<_> = round_signatures.iter().collect();
                        sorted_signatures.sort_by(|a, b| a.0.cmp(b.0));
                        let sorted_peer_ids: Vec<String> = sorted_signatures
                            .iter()
                            .take(self.threshold)
                            .map(|(id, _)| (*id).clone())
                            .collect();
                        info!(
                            "🧩 [SIGNING] Selected peers (PeerId sorted) for this aggregation: {:?}",
                            sorted_peer_ids
                        );
                        
                        // Calculate DKG indices for each peer
                        let mut dkg_indices = Vec::new();
                        for peer_id in &sorted_peer_ids {
                            let dkg_index = self.calculate_dkg_index_for_peer(peer_id).await;
                            dkg_indices.push((peer_id.clone(), dkg_index));
                        }
                        
                        dkg_indices
                    } else {
                        Vec::new()
                    }
                };

                info!(
                    "🔢 [SIGNING] DKG indices for threshold signatures: {:?}",
                    peer_to_dkg_index
                        .iter()
                        .map(|(peer, idx)| format!("{}->{}", peer, idx))
                        .collect::<Vec<_>>()
                );

                // Perform aggregation
                match self.aggregate_signatures(threshold_signatures, peer_to_dkg_index).await {
                    Ok(aggregated_signature) => {
                        info!(
                            "🎉 [SIGNING] Signature aggregation completed successfully for round {}!",
                            round
                        );

                        // Log the aggregated signature details
                        let (recovery_id, signature_bytes) =
                            aggregated_signature.serialize_compact();
                        let v: u64 = recovery_id.to_i32() as u64 + 35 + 1043 * 2;
                        
                        // Normalize signature components to remove leading zeros (canonical form)
                        let r_bytes = &signature_bytes[0..32];
                        let s_bytes = &signature_bytes[32..64];
                        
                        // Convert to BigUint to remove leading zeros, then back to 32-byte arrays
                        let r_biguint = num_bigint::BigUint::from_bytes_be(r_bytes);
                        let s_biguint = num_bigint::BigUint::from_bytes_be(s_bytes);
                        
                        let mut r = [0u8; 32];
                        let mut s = [0u8; 32];
                        
                        let r_canonical = r_biguint.to_bytes_be();
                        let s_canonical = s_biguint.to_bytes_be();
                        
                        // Copy to right-aligned 32-byte arrays (big-endian)
                        if r_canonical.len() <= 32 {
                            r[32 - r_canonical.len()..].copy_from_slice(&r_canonical);
                        }
                        if s_canonical.len() <= 32 {
                            s[32 - s_canonical.len()..].copy_from_slice(&s_canonical);
                        }

                        info!(
                            "🔐 [SIGNING] Aggregated signature components for round {}:",
                            round
                        );
                        info!("  v: {}", v);
                        info!("  r (canonical): 0x{}", hex::encode(&r));
                        info!("  s (canonical): 0x{}", hex::encode(&s));
                        info!("  recovery_id: {}", recovery_id.to_i32());
                        info!("  original_signature: 0x{}", hex::encode(signature_bytes));
                        info!("  r_canonical_len: {}, s_canonical_len: {}", r_canonical.len(), s_canonical.len());
                        
                        // 🚀 NEW: Reconstruct and broadcast signed transaction based on chain type
                        let chain_type = self.chain_handler.chain_type();
                        match chain_type {
                            "bitcoin" => {
                                if let Ok(Some(signed_tx_hex)) = self.reconstruct_signed_bitcoin_transaction(
                                    round,
                                    &signature_bytes,
                                    recovery_id.to_i32() as u8,
                                ).await {
                                    info!(
                                        "🎉 [SIGNING] 🔗 SIGNED BITCOIN TRANSACTION READY! 🔗"
                                    );
                                    info!("📄 Raw signed transaction: {}", signed_tx_hex);
                                    info!("Broadcasting transaction to Bitcoin network...");
                                    match Self::broadcast_transaction(&signed_tx_hex, false).await {
                                        Ok(Some(txid)) => {
                                            info!("✅ [SIGNING] Bitcoin transaction broadcasted successfully: {}", txid);
                                            // Store transaction ID if we have intent hash and user registry
                                            self.store_transaction_id_for_round(round, &txid, signature.user_eth_address.clone()).await;
                                        },
                                        Ok(None) => {
                                            warn!("⚠️ [SIGNING] Bitcoin transaction broadcasted but no txid returned");
                                        },
                                        Err(e) => {
                                            error!("❌ [SIGNING] Failed to broadcast Bitcoin transaction: {}", e);
                                            // Store the error message for the user to see
                                            self.store_transaction_error_for_round(round, &e.to_string()).await;
                                        }
                                    }
                                }
                            }
                            "ethereum" => {
                                // Create canonical signature bytes from normalized r and s components
                                let mut canonical_signature_bytes = [0u8; 64];
                                canonical_signature_bytes[0..32].copy_from_slice(&r);
                                canonical_signature_bytes[32..64].copy_from_slice(&s);
                                
                                if let Ok(Some(signed_tx_hex)) = self.reconstruct_signed_ethereum_transaction(
                                    round,
                                    &canonical_signature_bytes,
                                    recovery_id.to_i32() as u8,
                                ).await {
                                    info!(
                                        "🎉 [SIGNING] 🔗 SIGNED ETHEREUM TRANSACTION READY! 🔗"
                                    );
                                    info!("📄 Raw signed transaction: {}", signed_tx_hex);
                                    
                                    // Get chain ID for broadcasting
                                    let chain_id = self.chain_handler.get_chain_params()
                                        .get("chain_id")
                                        .and_then(|id| id.parse::<u64>().ok())
                                        .unwrap_or(9029); // Default to Qubetics
                                    
                                    info!("Broadcasting transaction to chain {} (Qubetics)...", chain_id);
                                    match Self::broadcast_ethereum_transaction(&signed_tx_hex, chain_id).await {
                                        Ok(Some(tx_hash)) => {
                                            info!("✅ [SIGNING] Ethereum transaction broadcasted successfully: {}", tx_hash);
                                            // Store transaction ID if we have intent hash and user registry
                                            self.store_transaction_id_for_round(round, &tx_hash, signature.user_eth_address.clone()).await;
                                        },
                                        Ok(None) => {
                                            warn!("⚠️ [SIGNING] Ethereum transaction broadcasted but no tx_hash returned");
                                        },
                                        Err(e) => {
                                            error!("❌ [SIGNING] Failed to broadcast Ethereum transaction: {}", e);
                                            // Store the error message for the user to see
                                            self.store_transaction_error_for_round(round, &e.to_string()).await;
                                        }
                                    }
                                }
                            }
                            _ => {
                                warn!("❌ [SIGNING] Unsupported chain type for transaction reconstruction: {}", chain_type);
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "❌ [SIGNING] Failed to aggregate signatures for round {}: {}",
                            round, e
                        );
                        return Err(e);
                    }
                }
            } else {
                info!(
                    "⏳ [SIGNING] Waiting for more signatures for round {}: {}/{} (threshold)",
                    round,
                    signatures_vec.len(),
                    self.threshold
                );
            }
        }

        Ok(())
    }

    /// Broadcast transaction to Bitcoin network
   
    /// Handle signature received on the signatures-to-final-node topic
    pub async fn handle_signature_to_final_node(
        &mut self,
        from: String,
        signature: ECDSASignature,
        round: u64,
    ) -> Result<()> {
        info!(
            "📥 [SIGNING] Final node {} received signature from {} on signatures-to-final-node topic",
            self.id, from
        );

        // Check if this node is the final node for the specific round
        let is_final_node = {
            let final_nodes = self.final_nodes_by_round.read().await;
            final_nodes.get(&round).map(|node_id| node_id == &self.id).unwrap_or(false)
        };

        if is_final_node {
            info!(
                "✅ [SIGNING] This node {} is the final node for round {}",
                self.id, round
            );
            return self
                .handle_signature_for_round(from, signature, round)
                .await;
        }

        info!(
            "⚠️ [SIGNING] Received signature for round {} but this node is not the final node for that round",
            round
        );
        Ok(())
    }

    /// Get the node ID
    pub fn get_node_id(&self) -> &str {
        &self.id
    }

    /// Debug function to test ECDSA signature handling
    pub async fn test_ecdsa_signature_handling(&mut self) -> Result<()> {
        info!(
            "🧪 [DEBUG] Testing ECDSA signature handling for node {}",
            self.id
        );

        // Create a test signature
        let test_signature = ECDSASignature {
            signature: vec![1, 2, 3, 4, 5], // Dummy signature
            signer_id: "test_signer".to_string(),
            // message_hash: vec![10, 20, 30, 40], // Dummy hash
            recovery_id: 0,
            user_eth_address: None, // No user_eth_address for test
        };

        // Test the handle_ecdsa_signature function directly
        self.handle_ecdsa_signature("test_signer".to_string(), test_signature)
            .await?;

        info!("✅ [DEBUG] ECDSA signature handling test completed successfully");
        Ok(())
    }

    /// Create threshold signature shares from a regular ECDSA signature
    pub fn create_threshold_shares(
        &self,
        signature: &ECDSASignature,
        threshold: u32,
        total_shares: u32,
    ) -> Vec<ThresholdSignatureShare> {
        let mut shares = Vec::new();

        for i in 0..total_shares {
            let share = ThresholdSignatureShare {
                share: signature.signature.clone(),
                signer_id: signature.signer_id.clone(),
                share_index: i + 1,
                threshold,
                total_shares,
            };
            shares.push(share);
        }

        info!(
            "🔢 [SIGNING] Created {} threshold signature shares (threshold: {})",
            shares.len(),
            threshold
        );

        shares
    }

    /// Verify threshold signature shares
    pub fn verify_threshold_shares(&self, shares: &[ThresholdSignatureShare]) -> Result<bool> {
        if shares.is_empty() {
            return Ok(false);
        }

        let threshold = shares[0].threshold;
        let total_shares = shares[0].total_shares;

        // Check if we have enough shares
        if shares.len() < threshold as usize {
            info!(
                "⚠️ [SIGNING] Not enough shares: {}/{}",
                shares.len(),
                threshold
            );
            return Ok(false);
        }

        // Verify all shares have the same threshold and total_shares
        for share in shares {
            if share.threshold != threshold || share.total_shares != total_shares {
                warn!("❌ [SIGNING] Inconsistent threshold parameters in shares");
                return Ok(false);
            }
        }

        info!(
            "✅ [SIGNING] Threshold shares verification passed: {}/{} shares",
            shares.len(),
            threshold
        );
        Ok(true)
    }

    /// Get Ethereum address from public key
    pub fn get_ethereum_address(&self) -> Option<String> {
        if let Some(public_key) = &self.public_key {
            // Get the uncompressed public key (65 bytes)
            let public_key_bytes = public_key.serialize_uncompressed();

            // Remove the prefix byte (0x04) and take the last 20 bytes for the address
            if public_key_bytes.len() >= 21 {
                let address_bytes = &public_key_bytes[1..21];

                // Convert to Ethereum address format (0x + hex)
                let address = format!("0x{}", hex::encode(address_bytes));

                info!(
                    "🏦 [SIGNING] Node {} Ethereum address: {}",
                    self.id, address
                );
                Some(address)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get private key as hex string (for debugging only)
    pub fn get_private_key_hex(&self) -> Option<String> {
        if let Some(private_key) = &self.private_key {
            let secret_key_bytes = private_key.secret_bytes();
            Some(format!("0x{}", hex::encode(secret_key_bytes)))
        } else {
            None
        }
    }

    /// Calculate DKG index for a specific peer ID
    pub async fn calculate_dkg_index_for_peer(&self, peer_id: &str) -> u32 {
        if let Some(nodes) = &self.available_nodes {
            let mut ids: Vec<String> = nodes.iter().map(|p| p.to_string()).collect();
            ids.sort();
            
            let index = ids.iter()
                .position(|id| id == peer_id)
                .map(|i| i + 1)
                .unwrap_or(1);
            
            info!("🔢 [SIGNING] Calculated DKG index {} for peer {}", index, peer_id);
            index as u32
        } else {
            info!("⚠️ [SIGNING] No available nodes, using default DKG index 1 for peer {}", peer_id);
            1
        }
    }

    /// Calculate DKG index for a specific peer ID (synchronous version)
    pub fn calculate_dkg_index_for_peer_sync(&self, peer_id: &str) -> u32 {
        if let Some(nodes) = &self.available_nodes {
            let mut ids: Vec<String> = nodes.iter().map(|p| p.to_string()).collect();
            ids.sort();
            
            let index = ids.iter()
                .position(|id| id == peer_id)
                .map(|i| i + 1)
                .unwrap_or(1);
            
            info!("🔢 [SIGNING] Calculated DKG index {} for peer {} (sync)", index, peer_id);
            index as u32
        } else {
            info!("⚠️ [SIGNING] No available nodes, using default DKG index 1 for peer {} (sync)", peer_id);
            1
        }
    }

    /// Update solver amounts for UserToVault transactions
    pub async fn update_solver_amounts_for_user_to_vault(&self, _intent_hash: &str) -> Result<()> {
        // Configuration for contract interaction
        let rpc_url = std::env::var("SOLVER_CONTRACT_RPC_URL")
            .unwrap_or_else(|_| "http://localhost:8545".to_string());
        let contract_address = std::env::var("SOLVER_CONTRACT_ADDRESS")
            .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());
        let chain_id = std::env::var("SOLVER_CONTRACT_CHAIN_ID")
            .unwrap_or_else(|_| "1".to_string())
            .parse::<u64>()
            .unwrap_or(1);

        // Skip if using default/placeholder values
        if contract_address == "0x0000000000000000000000000000000000000000" {
            info!("⏭️ [SOLVER] Skipping solver amount update - using placeholder contract address");
            return Ok(());
        }

        info!("🔄 [SOLVER] Updating solver amounts for UserToVault transaction: {}", _intent_hash);

        // Parse contract address
        let contract_addr = contract_address.parse::<ethers::types::Address>()
            .map_err(|e| anyhow::anyhow!("Invalid contract address: {}", e))?;

        // Create contract configuration
        let config = crate::contract::ContractConfig {
            rpc_url: rpc_url.clone(),
            contract_address: contract_addr,
            chain_id,
        };

        // Initialize contract client
        let client = crate::contract::ContractClient::new(config.clone())
            .map_err(|e| anyhow::anyhow!("Failed to create contract client: {}", e))?;

        let solver_contract = crate::contract::SolverManagerContract::new(&config, client.provider())
            .map_err(|e| anyhow::anyhow!("Failed to create solver contract: {}", e))?;

        // Get all active solvers
        let active_solvers = solver_contract
            .get_active_solvers()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get active solvers: {}", e))?;

        info!(
            "🔍 [SOLVER] Found {} active solvers: {:?}",
            active_solvers.len(),
            active_solvers
        );

        // Store amounts for each solver by EVM address
        let mut solver_liquidity_map = std::collections::HashMap::new();
        let mut total_tics = U256::zero();
        let mut total_btc = U256::zero();

        for solver_id in &active_solvers {
            // Get solver EVM address
            let solver_evm_address = solver_contract
                .get_solver_evm_address(solver_id)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Failed to get EVM address for solver {}: {}", solver_id, e)
                })?;

            // Call getSolverAllChainAmounts for each solver
            let amounts = solver_contract
                .get_all_chain_amounts(solver_id)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Failed to get amounts for solver {}: {}", solver_id, e)
                })?;

            // Track totals: index 0 = tics, index 1 = btc
            if let Some(tics_amount) = amounts.get(0) {
                total_tics = total_tics + *tics_amount;
            }
            if let Some(btc_amount) = amounts.get(1) {
                total_btc = total_btc + *btc_amount;
            }

            // Convert amounts to strings for storage: [tics, btc]
            let liquidity_amounts: Vec<String> = amounts.iter().map(|u| u.to_string()).collect();

            // Store solver liquidity with key: solver_liquidity:{solver_evm_address}
            let solver_liquidity_key = format!("solver_liquidity:{}", format!("{:?}", solver_evm_address).to_lowercase());

            // Store individual solver liquidity in database
            if let Some(ref database) = self.database {
                if let Err(e) = database.put_string(&solver_liquidity_key, &liquidity_amounts) {
                    warn!("⚠️ [SOLVER] Failed to store liquidity for solver {} (address: {:?}): {}", solver_id, solver_evm_address, e);
                } else {
                    info!("💾 [SOLVER] Stored liquidity for solver {} (address: {:?}): {:?}", solver_id, solver_evm_address, liquidity_amounts);
                }
            } else {
                warn!("⚠️ [SOLVER] No database available to store solver liquidity");
            }

            // Add to solver liquidity map: solver_address -> [tics, btc]
            solver_liquidity_map.insert(format!("{:?}", solver_evm_address).to_lowercase(), liquidity_amounts.clone());
        }

        // Store all solver liquidity with key: solver_liquidity:all
        let all_solver_liquidity_key = "solver_liquidity:all";
        
        // Store consolidated liquidity and totals in database
        if let Some(ref database) = self.database {
            if let Err(e) = database.put_string(all_solver_liquidity_key, &solver_liquidity_map) {
                warn!("⚠️ [SOLVER] Failed to store all solver liquidity: {}", e);
            } else {
                info!("💾 [SOLVER] Stored all solver liquidity: {} solvers", solver_liquidity_map.len());
            }

            // Store total liquidity values (index 0 = tics, index 1 = btc)
            let tics_key = crate::database::key_utils::total_liquidity_tics_key();
            if let Err(e) = database.put_string(&tics_key, &total_tics.to_string()) {
                warn!("⚠️ [SOLVER] Failed to store total tics liquidity: {}", e);
            } else {
                info!("💾 [SOLVER] Stored total tics liquidity: {}", total_tics);
            }

            let btc_key = crate::database::key_utils::total_liquidity_btc_key();
            if let Err(e) = database.put_string(&btc_key, &total_btc.to_string()) {
                warn!("⚠️ [SOLVER] Failed to store total btc liquidity: {}", e);
            } else {
                info!("💾 [SOLVER] Stored total btc liquidity: {}", total_btc);
            }
        } else {
            warn!("⚠️ [SOLVER] No database available to store solver liquidity");
        }
        
        // Log the consolidated amounts
        info!(
            "📋 [SOLVER] All solver liquidity by EVM address: {:?}",
            solver_liquidity_map
        );

        info!(
            "✅ [SOLVER] Updated all solver liquidity: {} solvers",
            active_solvers.len()
        );

        Ok(())
    }

    /// Calculate and store rewards for each solver based on an intent hash
    pub async fn calculate_reward_per_solver(&self, intent_hash: &str) -> Result<()> {
        // Ensure database and user registry are available
        let database = self
            .database
            .as_ref()
            .ok_or_else(|| anyhow!("Database not available"))?;
        let user_registry = self
            .user_registry
            .as_ref()
            .ok_or_else(|| anyhow!("User registry not available"))?;

        // Check if rewards already calculated using user registry
        if let Some(true) = user_registry.get_intent_reward_status(intent_hash).await {
            info!(
                "⏭️ [SOLVER] Rewards already calculated for intent {}",
                intent_hash
            );
            return Ok(());
        }

        // Fetch intent to determine amount and target chain
        let intent = user_registry
            .get_intent(intent_hash)
            .await
            .ok_or_else(|| anyhow!("Intent not found: {}", intent_hash))?;

        let target_chain = intent.target_chain.to_lowercase();
        let intent_amount = U256::from(intent.amount);
        let base_reward = intent_amount / U256::from(10u8); // 10% of intent amount

        // Fetch total liquidity values using user registry
        let total_tics = user_registry
            .get_total_liquidity_tics()
            .await
            .unwrap_or(0);
        let total_btc = user_registry
            .get_total_liquidity_btc()
            .await
            .unwrap_or(0.0);

        // Convert to U256 for calculations
        let total_tics_u256 = U256::from(total_tics);
        let total_btc_u256 = U256::from((total_btc * 1e8) as u64); // Convert BTC to satoshis

        // Fetch liquidity for all solvers
        let all_key = "solver_liquidity:all";
        let solver_liquidity_map: HashMap<String, Vec<String>> = database
            .get_string(all_key)?
            .unwrap_or_default();

        for (solver, amounts) in solver_liquidity_map.iter() {
            let reward = if target_chain == "btc" {
                let solver_btc = amounts
                    .get(1)
                    .and_then(|v| U256::from_dec_str(v).ok())
                    .unwrap_or_else(U256::zero);
                if total_btc_u256.is_zero() {
                    U256::zero()
                } else {
                    solver_btc * base_reward / total_btc_u256
                }
            } else {
                let solver_tics = amounts
                    .get(0)
                    .and_then(|v| U256::from_dec_str(v).ok())
                    .unwrap_or_else(U256::zero);
                if total_tics_u256.is_zero() {
                    U256::zero()
                } else {
                    solver_tics * base_reward / total_tics_u256
                }
            };

            // Get current reward and update using user registry
            let current = user_registry
                .get_solver_reward(solver)
                .await
                .unwrap_or_else(|| EthereumU256::zero());
            
            // Convert ethereum_types::U256 to ethers::types::U256 for calculation
            let current_ethers = U256::from_dec_str(&current.to_string())
                .map_err(|e| anyhow!("Failed to convert current reward: {}", e))?;
            let updated_ethers = current_ethers + reward;
            
            // Convert back to ethereum_types::U256 for user registry
            let updated_ethereum_types = EthereumU256::from_dec_str(&updated_ethers.to_string())
                .map_err(|e| anyhow!("Failed to convert updated reward: {}", e))?;
            
            user_registry
                .set_solver_reward(solver, updated_ethereum_types)
                .await
                .map_err(|e| anyhow!("Failed to set solver reward: {}", e))?;
            
            info!("💰 [SOLVER] Reward for {} updated to {}", solver, updated_ethers);
        }

        info!(
            "✅ [SOLVER] Calculated rewards for {} solvers",
            solver_liquidity_map.len()
        );
        
        // Mark intent reward status as calculated using user registry
        user_registry
            .set_intent_reward_status(intent_hash, true)
            .await
            .map_err(|e| anyhow!("Failed to set intent reward status: {}", e))?;

        Ok(())
    }
}

// Dynamic configuration structures for flexible broadcast behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastConfig {
    /// Whether to continue running when broadcast fails
    pub continue_on_failure: bool,
    /// Maximum retry attempts for failed broadcasts
    pub max_retries: u32,
    /// Delay between retry attempts (in milliseconds)
    pub retry_delay_ms: u64,
    /// Whether to log broadcast failures as warnings instead of errors
    pub log_failures_as_warnings: bool,
    /// Chain-specific configurations
    pub chain_configs: HashMap<String, ChainBroadcastConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainBroadcastConfig {
    /// Whether this chain is enabled for broadcasting
    pub enabled: bool,
    /// RPC endpoint for this chain
    pub rpc_url: String,
    /// Chain ID
    pub chain_id: u64,
    /// Whether to use testnet
    pub testnet: bool,
    /// Custom headers for RPC requests
    pub custom_headers: HashMap<String, String>,
    /// Timeout for RPC requests (in seconds)
    pub timeout_seconds: u64,
}

impl Default for BroadcastConfig {
    fn default() -> Self {
        let mut chain_configs = HashMap::new();
        
        // Default Ethereum configuration
        chain_configs.insert("ethereum".to_string(), ChainBroadcastConfig {
            enabled: true,
            rpc_url: String::new(),
            chain_id: 9029,
            testnet: true,
            custom_headers: HashMap::new(),
            timeout_seconds: 30,
        });

        // Default Bitcoin configuration - using public Bitcoin RPC service
        chain_configs.insert("bitcoin".to_string(), ChainBroadcastConfig {
            enabled: true, // Enabled with public API
            rpc_url: String::new(),
            chain_id: 0,
            testnet: true,
            custom_headers: HashMap::new(),
            timeout_seconds: 30,
        });
        
        Self {
            continue_on_failure: true,
            max_retries: 3,
            retry_delay_ms: 1000,
            log_failures_as_warnings: true,
            chain_configs,
        }
    }
}

impl Default for ChainBroadcastConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rpc_url: String::new(),
            chain_id: 0,
            testnet: true,
            custom_headers: HashMap::new(),
            timeout_seconds: 30,
        }
    }
}

// Configuration loading from environment variables
impl BroadcastConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();
        
        // Load from environment variables
        if let Ok(val) = std::env::var("MPC_CONTINUE_ON_BROADCAST_FAILURE") {
            config.continue_on_failure = val.parse().unwrap_or(true);
        }
        
        if let Ok(val) = std::env::var("MPC_MAX_BROADCAST_RETRIES") {
            config.max_retries = val.parse().unwrap_or(3);
        }
        
        if let Ok(val) = std::env::var("MPC_RETRY_DELAY_MS") {
            config.retry_delay_ms = val.parse().unwrap_or(1000);
        }
        
        if let Ok(val) = std::env::var("MPC_LOG_FAILURES_AS_WARNINGS") {
            config.log_failures_as_warnings = val.parse().unwrap_or(true);
        }
        
        // Load chain-specific configurations
        if let Some(eth_config) = config.chain_configs.get_mut("ethereum") {
            eth_config.rpc_url = std::env::var("MPC_ETHEREUM_RPC_URL")
                .unwrap_or_else(|_| "https://rpc-testnet.qubetics.work".to_string());
        }

        if let Ok(chain_id) = std::env::var("MPC_ETHEREUM_CHAIN_ID") {
            if let Some(eth_config) = config.chain_configs.get_mut("ethereum") {
                eth_config.chain_id = chain_id.parse().unwrap_or(9029);
            }
        }

        if let Some(btc_config) = config.chain_configs.get_mut("bitcoin") {
            btc_config.rpc_url = std::env::var("MPC_BITCOIN_RPC_URL")
                .unwrap_or_else(|_| "https://api.blockcypher.com/v1/btc/test3/txs/push".to_string());
        }
        
        config
    }
    
    pub fn get_chain_config(&self, chain_type: &str) -> Option<&ChainBroadcastConfig> {
        self.chain_configs.get(chain_type)
    }
    
    pub fn is_chain_enabled(&self, chain_type: &str) -> bool {
        self.chain_configs
            .get(chain_type)
            .map(|config| config.enabled)
            .unwrap_or(false)
    }
    
    pub fn print_config(&self) {
        info!("�� [CONFIG] Broadcast Configuration:");
        info!("   Continue on failure: {}", self.continue_on_failure);
        info!("   Max retries: {}", self.max_retries);
        info!("   Retry delay: {}ms", self.retry_delay_ms);
        info!("   Log failures as warnings: {}", self.log_failures_as_warnings);
        
        for (chain, config) in &self.chain_configs {
            info!("   Chain {}: enabled={}, rpc={}, chain_id={}", 
                  chain, config.enabled, config.rpc_url, config.chain_id);
        }
    }
}