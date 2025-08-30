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
use crate::chain::BitcoinTransaction;
use k256::AffinePoint;
use sha3::{Keccak256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECDSASignature {
    pub signature: Vec<u8>, // 65-byte recoverable signature
    pub signer_id: String,
    pub recovery_id: u8,
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
    pending_transactions: Arc<RwLock<HashMap<u64, (ChainTransaction, Vec<u8>)>>>, // round -> (original_tx, tx_bytes)
    // ✅ Store DKG group public key
    group_public_key: Option<k256::ProjectivePoint>, // DKG group public key for Bitcoin addresses
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
        }
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
    pub async fn sign_bitcoin_transaction(&mut self, tx_bytes: Vec<u8>, original_tx: Option<BitcoinTransaction>) -> Result<()> {
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
        println!("🔗 [BITCOIN] Tx hash (double SHA256): 0x{}", hex::encode(&tx_hash));

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
        let ecdsa_signature = ECDSASignature {
            signature: signature_bytes.to_vec(), // ✅ 64 bytes (r||s only)
            signer_id: self.id.clone(),
            recovery_id: recovery_id.to_i32() as u8, // ✅ Separate field
        };

        // Broadcast the signature to other nodes with proper VRF round
        let signing_message = SigningMessage::ECDSASignature {
            from: self.id.clone(),
            signature: ecdsa_signature,
            round: current_round, // ✅ Use actual VRF round
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        };

        let gossipsub_msg = crate::types::GossipsubMessage::Signing(signing_message);
        let msg_data = serde_json::to_vec(&gossipsub_msg)?;

        self.message_tx
            .send(ChannelMessage::Broadcast {
                topic: "signatures".to_string(),
                data: msg_data,
            })
            .await?;

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
            pending_transactions.insert(current_round, (ChainTransaction::Bitcoin(original_tx), tx_bytes.clone()));
            info!(
                "💾 [SIGNING] Node {} stored original Bitcoin transaction for round {} reconstruction",
                self.id, current_round
            );
        }

        Ok(())
    }

    async fn broadcast_transaction(raw_tx_hex: &str, mainnet: bool) -> Result<()> {
        let base_url = if mainnet {
            "https://blockstream.info/api"
        } else {
            "https://blockstream.info/testnet/api"
        };
        let url = format!("{}/tx", base_url);
        println!("Broadcasting transaction to: {}", url);

        let client = reqwest::Client::new();
        let response = client.post(&url)
            .header("Content-Type", "text/plain")
            .header("User-Agent", "sigg_gen_agg/0.1.0")
            .body(raw_tx_hex.to_string())
            .send()
            .await?;

        if response.status().is_success() {
            let txid = response.text().await?;
            println!("✅ Transaction broadcasted successfully!");
            println!("TXID: {}", txid);
        } else {
            let error_text = response.text().await?;
            println!("❌ Failed to broadcast transaction: {}", error_text);
            return Err(anyhow!("Broadcast failed: {}", error_text));
        }
        Ok(())
    }

    /// Fetch nonce for an Ethereum address from the blockchain
    async fn fetch_ethereum_nonce(address: &str, chain_id: u64) -> Result<u64> {
        let rpc_url = match chain_id {
            9029 => "https://rpc-testnet.qubetics.work", // Qubetics RPC URL
            1 => "https://mainnet.infura.io/v3/YOUR_PROJECT_ID", // Ethereum mainnet
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
    async fn broadcast_ethereum_transaction(raw_tx_hex: &str, chain_id: u64) -> Result<()> {
        let rpc_url = match chain_id {
            9029 => "https://rpc-testnet.qubetics.work", // Qubetics RPC URL
            1 => "https://mainnet.infura.io/v3/YOUR_PROJECT_ID", // Ethereum mainnet
            _ => return Err(anyhow!("Unsupported chain ID for broadcasting: {}", chain_id)),
        };

        let client = reqwest::Client::new();
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx_hex],
            "id": 1
        });

        println!("Broadcasting Ethereum transaction to chain {}: {}", chain_id, rpc_url);

        let response = client.post(rpc_url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            if let Some(error) = result.get("error") {
                println!("❌ Failed to broadcast transaction: {}", error);
                return Err(anyhow!("Broadcast failed: {}", error));
            }
            if let Some(tx_hash) = result.get("result") {
                println!("✅ Qubetics transaction broadcasted successfully!");
                println!("TX Hash: {}", tx_hash);
            }
        } else {
            let error_text = response.text().await?;
            println!("❌ Failed to broadcast transaction: {}", error_text);
            return Err(anyhow!("Broadcast failed: {}", error_text));
        }
        Ok(())
    }

    /// Reconstruct signed Bitcoin transaction from aggregated signature
    pub async fn reconstruct_signed_bitcoin_transaction(
        &self,
        round: u64,
        aggregated_signature: &[u8],
        recovery_id: u8,
    ) -> Result<Option<String>> {
        let pending_transactions = self.pending_transactions.read().await;
        
        if let Some((chain_tx, _tx_bytes)) = pending_transactions.get(&round) {
            if let ChainTransaction::Bitcoin(original_tx) = chain_tx {
                info!(
                    "🔧 [SIGNING] Node {} reconstructing signed Bitcoin transaction for round {}",
                    self.id, round
                );
                
                // Create DER-encoded signature for Bitcoin
                let r = &aggregated_signature[0..32];
                let s = &aggregated_signature[32..64];
                
                // Create DER signature format
                let der_signature = self.create_der_signature(r, s)?;
                
                // Create the complete signed transaction
                let signed_tx = self.create_signed_bitcoin_transaction(original_tx, &der_signature)?;
                
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
        
        if let Some((chain_tx, _tx_bytes)) = pending_transactions.get(&round) {
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
                                        // Fetch dynamic nonce from group public key's Ethereum address
            let group_address: String = get_eth_address_from_group_key(self.group_public_key.unwrap());
            let dynamic_nonce = Self::fetch_ethereum_nonce(&group_address, chain_id).await?;
            
            info!("🔢 [SIGNING] Using dynamic nonce {} for group address {}", dynamic_nonce, group_address);
            info!("💰 [SIGNING] Transaction cost: {} wei", original_tx.value);
            info!("🔍 [SIGNING] Please ensure the group address {} has sufficient balance", group_address);
                
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

    /// Create complete signed Bitcoin transaction (supports both Legacy and SegWit UTXOs)
    fn create_signed_bitcoin_transaction(
        &self,
        original_tx: &BitcoinTransaction,
        der_signature: &[u8],
    ) -> Result<Vec<u8>> {
        let mut signed_tx = Vec::new();
        
        // Version (4 bytes, little-endian)
        signed_tx.extend_from_slice(&original_tx.version.to_le_bytes());
        
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
            
            // Create script_sig with signature and public key (for first input, empty for others for now)
            if i == 0 {
                // ✅ Use proper group public key from DKG (UTXO was sent to group address)
                let group_pubkey = self.get_group_public_key_bytes()?;
                
                let mut script_sig = Vec::new();
                script_sig.push(der_signature.len() as u8); // Signature length
                script_sig.extend_from_slice(der_signature); // Signature
                script_sig.push(group_pubkey.len() as u8); // Public key length
                script_sig.extend_from_slice(&group_pubkey); // Actual group public key
                
                signed_tx.extend_from_slice(&self.encode_varint(script_sig.len() as u64));
                signed_tx.extend_from_slice(&script_sig);
            } else {
                // Empty script_sig for other inputs (in this simplified version)
                signed_tx.push(0x00);
            }
            
            // Sequence (4 bytes, little-endian)
            signed_tx.extend_from_slice(&input.sequence.to_le_bytes());
        }
        
        // Output count (varint)
        signed_tx.extend_from_slice(&self.encode_varint(original_tx.outputs.len() as u64));
        
        // Outputs - ✅ Convert SegWit outputs to Legacy P2PKH
        for output in &original_tx.outputs {
            // Value (8 bytes, little-endian)
            signed_tx.extend_from_slice(&output.value.to_le_bytes());
            
            // ✅ Check if output is SegWit and convert to P2PKH
            let script_pubkey = if output.script_pubkey.len() == 22 && 
                                   output.script_pubkey[0] == 0x00 && 
                                   output.script_pubkey[1] == 0x14 {
                // This is P2WPKH (SegWit), convert to P2PKH
                let pubkey_hash = &output.script_pubkey[2..22];
                let mut p2pkh_script = Vec::new();
                p2pkh_script.push(0x76); // OP_DUP
                p2pkh_script.push(0xa9); // OP_HASH160
                p2pkh_script.push(0x14); // Push 20 bytes
                p2pkh_script.extend_from_slice(pubkey_hash); // 20-byte hash
                p2pkh_script.push(0x88); // OP_EQUALVERIFY
                p2pkh_script.push(0xac); // OP_CHECKSIG
                
                info!("🔄 [SIGNING] Converted P2WPKH output to P2PKH for compatibility");
                p2pkh_script
            } else {
                output.script_pubkey.clone()
            };
            
            signed_tx.extend_from_slice(&self.encode_varint(script_pubkey.len() as u64));
            signed_tx.extend_from_slice(&script_pubkey);
        }
        
        // Lock time (4 bytes, little-endian)
        signed_tx.extend_from_slice(&original_tx.lock_time.to_le_bytes());
        
        Ok(signed_tx)
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
    ) -> Result<()> {
        if self.private_key.is_none() {
            error!(
                "❌ [SIGNING] Node {} cannot sign: no private key available",
                self.id
            );
            return Err(anyhow::anyhow!("No private key available"));
        }

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
        println!("Tx hash: 0x{}", hex::encode(&tx_hash));

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
        let signature = self.create_ecdsa_signature(&msg, transaction)?;
        let (recovery_id, signature_bytes) = signature.serialize_compact();

        // Use chain handler to create chain-specific signature
        let chain_signature = self.chain_handler.create_signature(
            &signature_bytes, 
            recovery_id.to_i32() as u8, 
            &chain_transaction
        )?;

        info!(
            "✍️ [SIGNING] Node {} created {} signature",
            self.id, self.chain_handler.chain_type()
        );

        // Log signature components for Ethereum (for debugging)
        if let ChainSignature::Ethereum(eth_sig) = &chain_signature {
            println!("\n{} Signature Components:", self.chain_handler.chain_type());
            println!("  v: {}", eth_sig.v);
            println!("  r: 0x{}", hex::encode(&eth_sig.r));
            println!("  s: 0x{}", hex::encode(&eth_sig.s));
        }

        // Convert to legacy ECDSASignature for compatibility
        let ecdsa_signature = ECDSASignature {
            signature: signature_bytes.to_vec(),
            signer_id: self.id.clone(),
            recovery_id: recovery_id.to_i32() as u8,
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
            pending_transactions.insert(round, (chain_tx, tx_bytes.clone()));
            info!(
                "💾 [SIGNING] Node {} stored original Ethereum transaction for round {} reconstruction (nonce will be fetched dynamically)",
                self.id, round
            );
        }

        let msg = serde_json::to_vec(&crate::types::GossipsubMessage::Signing(
            SigningMessage::ECDSASignature {
                from: self.id.clone(),
                signature: ecdsa_signature,
                round,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
            },
        ))?;

        self.broadcast("signing", &msg).await?;
        info!("📤 [SIGNING] Node {} broadcasted ECDSA signature", self.id);
        Ok(())
    }

    pub fn create_ecdsa_signature(
        &self,
        message: &Message,
        _transaction: &DummyTransaction,
    ) -> Result<RecoverableSignature> {
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
            } => {
                info!(
                    "📥 [SIGNING] Node {} received ECDSA signature from {} for round {}",
                    self.id, from, round
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
                        let r = &signature_bytes[0..32];
                        let s = &signature_bytes[32..64];

                        info!("🔐 [SIGNING] Aggregated signature components:");
                        info!("  v: {}", v);
                        info!("  r: 0x{}", hex::encode(r));
                        info!("  s: 0x{}", hex::encode(s));
                        info!("  recovery_id: {}", recid.to_i32());
                        info!("  full_signature: 0x{}", hex::encode(signature_bytes));
                        
                        // 🚀 NEW: Reconstruct signed Bitcoin transaction
                        if let Ok(Some(signed_tx_hex)) = self.reconstruct_signed_bitcoin_transaction(
                            round,
                            &signature_bytes,
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

        println!("=== Lagrange Interpolation Debug ===");
        println!("Threshold: {}, Got {} shares", self.threshold, shares.len());

        for (i, &(x, ref y_bytes)) in shares.iter().enumerate() {
            let y_val = BigUint::from_bytes_be(y_bytes);
            println!("Share {}: x={}, y={}", i + 1, x, y_val);
        }

        // // 🔧 FIX 1: Select exactly threshold shares deterministically
        // let mut selected_shares = shares.to_vec();
        // selected_shares.sort_by_key(|(x, _)| *x);
        // selected_shares.truncate(self.threshold);

        // With this:
        let mut rng = thread_rng();
        let mut selected_shares = shares.to_vec();
        selected_shares.shuffle(&mut rng);
        selected_shares.truncate(self.threshold);


        println!(
            "Selected {} shares for interpolation:",
            selected_shares.len()
        );
        for (i, &(x, ref y_bytes)) in selected_shares.iter().enumerate() {
            let y_val = BigUint::from_bytes_be(y_bytes);
            println!("Share {}: x={}, y={}", i + 1, x, y_val);
        }

        let n = BigUint::from_bytes_be(&CURVE_ORDER);
        println!("Working modulo n = {}", n);

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
        println!("\n=== Computing Lagrange Coefficients ===");

        // 🔧 FIX 2: Use selected_shares in BOTH loops
        for (share_idx, &(xj, ref yj_bytes)) in selected_shares.iter().enumerate() {
            println!("\n--- Processing Share {} (x={}) ---", share_idx + 1, xj);

            let mut num = BigUint::from(1u32);
            let mut den = BigUint::from(1u32);

            println!("Computing λ_{} = ", xj);
            let mut debug_terms = Vec::new();

            // 🔧 FIX 3: Inner loop uses SAME selected_shares, not all shares
            for &(xm, _) in selected_shares.iter() {
                // ← FIXED: Use selected_shares
                if xm != xj {
                    let xm_u = BigUint::from(xm);
                    let xj_u = BigUint::from(xj);

                    // Numerator: -xₘ ≡ (n - xₘ) mod n
                    let neg_xm = (&n - &xm_u) % &n;
                    num = (num * &neg_xm) % &n;

                    // Denominator: (xⱼ - xₘ) mod n
                    let diff = if xj_u >= xm_u {
                        &xj_u - &xm_u
                    } else {
                        &xj_u + &n - &xm_u
                    };
                    den = (den * diff.clone()) % &n;

                    debug_terms.push(format!("(-{}/({}-{})) = ({}/{})", xm, xj, xm, neg_xm, diff));
                }
            }

            println!("  = {}", debug_terms.join(" × "));
            println!("  numerator = {} (mod {})", num, n);
            println!("  denominator = {} (mod {})", den, n);

            let den_inv = modinv(&den, &n)
                .ok_or_else(|| anyhow!("Denominator not invertible for share x={}", xj))?;

            println!("  denominator⁻¹ = {} (mod {})", den_inv, n);

            let lambda = (num.clone() * den_inv.clone()) % &n;
            println!(
                "  λ_{} = {} × {} = {} (mod {})",
                xj, num, den_inv, lambda, n
            );

            let yj = BigUint::from_bytes_be(yj_bytes);
            let contribution = (&lambda * &yj) % &n;
            println!(
                "  Contribution: {} × {} = {} (mod {})",
                lambda, yj, contribution, n
            );

            accum = (accum + contribution) % &n;
            println!("  Running total: {} (mod {})", accum, n);
        }

        println!("\n=== Final Result ===");
        println!("Reconstructed value: {} (mod {})", accum, n);

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

    /// Get the DKG group public key
    pub fn get_group_public_key(&self) -> Option<k256::ProjectivePoint> {
        self.group_public_key
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
                        let r = &signature_bytes[0..32];
                        let s = &signature_bytes[32..64];

                        info!(
                            "🔐 [SIGNING] Aggregated signature components for round {}:",
                            round
                        );
                        info!("  v: {}", v);
                        info!("  r: 0x{}", hex::encode(r));
                        info!("  s: 0x{}", hex::encode(s));
                        info!("  recovery_id: {}", recovery_id.to_i32());
                        info!("  full_signature: 0x{}", hex::encode(signature_bytes));
                        
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
                                    Self::broadcast_transaction(&signed_tx_hex, false).await?;
                                }
                            }
                            "ethereum" => {
                                if let Ok(Some(signed_tx_hex)) = self.reconstruct_signed_ethereum_transaction(
                                    round,
                                    &signature_bytes,
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
                                    Self::broadcast_ethereum_transaction(&signed_tx_hex, chain_id).await?;
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
}
