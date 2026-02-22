use super::SigningNode;
use crate::{
    chain_abstraction::ChainTransaction,
    types::{TransactionNetwork, TransactionType},
};
use tracing::{error, info, warn};

impl SigningNode {
    pub(crate) async fn store_withdraw_transaction_tics(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        solver_address: String,
    ) {
        let mut pending = self
            .pending
            .withdraw_pending_transactions_tics
            .write()
            .await;
        pending.insert(
            round,
            (
                chain_tx,
                tx_bytes,
                Some(vec![solver_address]),
                Some(TransactionType::WithdrawLiquidity),
                None,
                None,
            ),
        );
        info!(
            "💧 [SIGNING] Stored TICS withdraw-liquidity transaction for round {} with solver address",
            round
        );
    }

    /// Store TICS withdraw batch (one EVM tx-id for multiple requests). identifiers are "request_id|solver_address".
    pub(crate) async fn store_withdraw_transaction_tics_batch(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        identifiers: Vec<String>,
    ) {
        if identifiers.is_empty() {
            return;
        }
        let mut pending = self
            .pending
            .withdraw_pending_transactions_tics
            .write()
            .await;
        let count = identifiers.len();
        pending.insert(
            round,
            (
                chain_tx,
                tx_bytes,
                Some(identifiers),
                Some(TransactionType::WithdrawLiquidity),
                None,
                None,
            ),
        );
        let mut withdraw_rounds = self.pending.withdraw_rounds.write().await;
        withdraw_rounds.insert(round);
        info!(
            "💧 [SIGNING] Stored TICS withdraw-liquidity batch for round {} with {} request(s)",
            round, count
        );
    }

    /// Store TICS claim-reward batch (one EVM tx-id for multiple requests); tx-id broadcast stores tx_id on TICS requests and marks done; marks BTC requests done only.
    pub(crate) async fn store_claim_reward_transaction_tics_batch(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        identifiers: Vec<String>,
    ) {
        if identifiers.is_empty() {
            return;
        }
        let count = identifiers.len();
        let mut pending = self
            .pending
            .claim_reward_pending_transactions_tics
            .write()
            .await;
        pending.insert(
            round,
            (
                chain_tx,
                tx_bytes,
                Some(identifiers),
                Some(TransactionType::ClaimReward),
                None,
                None,
            ),
        );
        let mut claim_reward_rounds = self.pending.claim_reward_rounds.write().await;
        claim_reward_rounds.insert(round);
        info!(
            "🎁 [SIGNING] Stored TICS claim-reward batch for round {} with {} request(s)",
            round, count
        );
    }

    pub(crate) async fn store_claim_platform_fee_transaction_tics_batch(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        identifiers: Vec<String>,
    ) {
        if identifiers.is_empty() {
            return;
        }
        let count = identifiers.len();
        let mut pending = self
            .pending
            .claim_platform_fee_pending_transactions_tics
            .write()
            .await;
        pending.insert(
            round,
            (
                chain_tx,
                tx_bytes,
                Some(identifiers),
                Some(TransactionType::ClaimPlatformFee),
                None,
                None,
            ),
        );
        let mut claim_pf_rounds = self.pending.claim_platform_fee_rounds.write().await;
        claim_pf_rounds.insert(round);
        info!(
            "💰 [SIGNING] Stored TICS claim-platform-fee batch for round {} with {} request(s)",
            round, count
        );
    }

    pub(crate) async fn store_withdraw_transaction_btc(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        identifiers: Vec<String>,
        extras: crate::signing::state::BtcRoundExtras,
    ) {
        // For BTC withdraws we repurpose the "intent_hashes" slot in PendingValue
        // to carry the batch context: each entry is encoded as "request_id|solver_address".
        let mut pending = self.pending.withdraw_pending_transactions_btc.write().await;
        pending.insert(
            round,
            (
                chain_tx,
                tx_bytes,
                if identifiers.is_empty() {
                    None
                } else {
                    Some(identifiers)
                },
                Some(TransactionType::WithdrawLiquidity),
                Some(extras),
            ),
        );
        info!(
            "💧 [SIGNING] Stored BTC withdraw-liquidity transaction for round {} with batch metadata",
            round
        );
    }

    pub(crate) async fn store_claim_reward_transaction_btc(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        identifiers: Vec<String>,
        extras: crate::signing::state::BtcRoundExtras,
    ) {
        let mut pending = self
            .pending
            .claim_reward_pending_transactions_btc
            .write()
            .await;
        pending.insert(
            round,
            (
                chain_tx,
                tx_bytes,
                if identifiers.is_empty() {
                    None
                } else {
                    Some(identifiers)
                },
                Some(TransactionType::ClaimReward),
                Some(extras),
            ),
        );
        {
            let mut rounds = self.pending.claim_reward_rounds.write().await;
            rounds.insert(round);
        }
        info!(
            "🎁 [SIGNING] Stored BTC claim-reward transaction for round {} with batch metadata",
            round
        );
    }

    pub(crate) async fn store_claim_platform_fee_transaction_btc(
        &self,
        round: u64,
        chain_tx: ChainTransaction,
        tx_bytes: Vec<u8>,
        identifiers: Vec<String>,
        extras: crate::signing::state::BtcRoundExtras,
    ) {
        let mut pending = self
            .pending
            .claim_platform_fee_pending_transactions_btc
            .write()
            .await;
        pending.insert(
            round,
            (
                chain_tx,
                tx_bytes,
                if identifiers.is_empty() {
                    None
                } else {
                    Some(identifiers)
                },
                Some(TransactionType::ClaimPlatformFee),
                Some(extras),
            ),
        );
        {
            let mut rounds = self.pending.claim_platform_fee_rounds.write().await;
            rounds.insert(round);
        }
        info!(
            "💰 [SIGNING] Stored BTC claim-platform-fee transaction for round {} with batch metadata",
            round
        );
    }

    pub(crate) async fn store_transaction_error_for_round(
        &self,
        round: u64,
        error_message: &str,
        txn_network: TransactionNetwork,
    ) {
        let is_reward_round = {
            let claim_reward_rounds = self.pending.claim_reward_rounds.read().await;
            claim_reward_rounds.contains(&round)
        };

        let is_withdraw_round = {
            let withdraw_rounds = self.pending.withdraw_rounds.read().await;
            withdraw_rounds.contains(&round)
        };

        let is_claim_reward_round = {
            let claim_reward_rounds = self.pending.claim_reward_rounds.read().await;
            claim_reward_rounds.contains(&round)
        };

        let is_claim_platform_fee_round = {
            let claim_pf_rounds = self.pending.claim_platform_fee_rounds.read().await;
            claim_pf_rounds.contains(&round)
        };

        let (intent_hashes, transaction_type, retrieved_solver_address): (
            Vec<String>,
            Option<crate::types::TransactionType>,
            Option<String>,
        ) = match txn_network {
            TransactionNetwork::TICS => {
                if is_reward_round {
                    let claim_reward_pending_tics = self
                        .pending
                        .claim_reward_pending_transactions_tics
                        .read()
                        .await;
                    if let Some((
                        _tx,
                        _tx_bytes,
                        identifiers,
                        transaction_type,
                        _request_id,
                        _original_request,
                    )) = claim_reward_pending_tics.get(&round)
                    {
                        let solver_address: Option<String> =
                            identifiers.as_ref().and_then(|v| v.first()).map(|s| {
                                if let Some((_, solver)) = s.split_once('|') {
                                    solver.to_string()
                                } else {
                                    s.clone()
                                }
                            });
                        (vec![], transaction_type.clone(), solver_address)
                    } else {
                        (vec![], None, None)
                    }
                } else if is_withdraw_round {
                    let withdraw_pending_transactions =
                        self.pending.withdraw_pending_transactions_tics.read().await;
                    if let Some((
                        _tx,
                        _tx_bytes,
                        identifiers,
                        transaction_type,
                        _request_id,
                        _original_request,
                    )) = withdraw_pending_transactions.get(&round)
                    {
                        let solver_address =
                            identifiers.as_ref().and_then(|v| v.first()).map(|s| {
                                if let Some((_, solver)) = s.split_once('|') {
                                    solver.to_string()
                                } else {
                                    s.clone()
                                }
                            });
                        (vec![], transaction_type.clone(), solver_address)
                    } else {
                        (vec![], None, None)
                    }
                } else if is_claim_platform_fee_round {
                    let claim_pf_pending_tics = self
                        .pending
                        .claim_platform_fee_pending_transactions_tics
                        .read()
                        .await;
                    if let Some((
                        _tx,
                        _tx_bytes,
                        identifiers,
                        transaction_type,
                        _request_id,
                        _original_request,
                    )) = claim_pf_pending_tics.get(&round)
                    {
                        let first_id =
                            identifiers.as_ref().and_then(|v| v.first().cloned());
                        (vec![], transaction_type.clone(), first_id)
                    } else {
                        (vec![], None, None)
                    }
                } else {
                    let (from_pending, tx_type) = {
                        let pending = self.pending.pending_transactions.read().await;
                        pending
                            .get(&round)
                            .map(|(_, _, h, t, _, _)| (h.clone(), t.clone()))
                            .unwrap_or((None, None))
                    };
                    let list = {
                        let map = self.pending.intent_hashes_by_round.read().await;
                        map.get(&round)
                            .cloned()
                            .unwrap_or_else(|| from_pending.map(|h| vec![h]).unwrap_or_default())
                    };
                    (list, tx_type, None)
                }
            }
            TransactionNetwork::BTC => {
                if is_claim_reward_round {
                    let claim_reward_pending_btc = self
                        .pending
                        .claim_reward_pending_transactions_btc
                        .read()
                        .await;
                    if let Some((_tx, _tx_bytes, solver_addresses, transaction_type, _extras)) =
                        claim_reward_pending_btc.get(&round)
                    {
                        let solver_address =
                            solver_addresses.as_ref().and_then(|v| v.first().cloned());
                        (vec![], transaction_type.clone(), solver_address)
                    } else {
                        (vec![], None, None)
                    }
                } else if is_claim_platform_fee_round {
                    let claim_pf_pending_btc = self
                        .pending
                        .claim_platform_fee_pending_transactions_btc
                        .read()
                        .await;
                    if let Some((_tx, _tx_bytes, identifiers, transaction_type, _extras)) =
                        claim_pf_pending_btc.get(&round)
                    {
                        let first_id =
                            identifiers.as_ref().and_then(|v| v.first().cloned());
                        (vec![], transaction_type.clone(), first_id)
                    } else {
                        (vec![], None, None)
                    }
                } else if is_withdraw_round {
                    let withdraw_pending_transactions_btc =
                        self.pending.withdraw_pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, solver_addresses, transaction_type, _extras)) =
                        withdraw_pending_transactions_btc.get(&round)
                    {
                        let solver_address =
                            solver_addresses.as_ref().and_then(|v| v.first().cloned());
                        (vec![], transaction_type.clone(), solver_address)
                    } else {
                        (vec![], None, None)
                    }
                } else {
                    let from_pending = {
                        let pending_btc = self.pending.pending_transactions_btc.read().await;
                        pending_btc
                            .get(&round)
                            .and_then(|(_, _, h, _, _)| h.clone())
                            .unwrap_or_default()
                    };
                    let list = {
                        let map = self.pending.intent_hashes_by_round.read().await;
                        map.get(&round).cloned().unwrap_or_else(|| from_pending)
                    };
                    let tx_type = {
                        let pending_btc = self.pending.pending_transactions_btc.read().await;
                        pending_btc
                            .get(&round)
                            .and_then(|(_, _, _, t, _)| t.clone())
                    };
                    (list, tx_type, None)
                }
            }
        };

        // Intent-based batch: store, refund, and broadcast for all intents (batch-aware, like tx-id)
        if !intent_hashes.is_empty() {
            if let Some(user_intent_manager) = &self.user_intent_manager {
                let transaction_type_str = match transaction_type {
                    Some(crate::types::TransactionType::UserToVault) => "user_to_vault",
                    Some(crate::types::TransactionType::NetworkToTarget) => "network_to_target",

                    Some(crate::types::TransactionType::IntentStatusUpdate) => {
                        "intent_status_update"
                    }
                    Some(crate::types::TransactionType::WithdrawLiquidity) => {
                        error!("❌ [SIGNING] WithdrawLiquidity with intent_hashes - invalid");
                        return;
                    }
                    Some(crate::types::TransactionType::ClaimReward) => {
                        error!("❌ [SIGNING] ClaimReward with intent_hashes - invalid");
                        return;
                    }
                    Some(crate::types::TransactionType::ClaimPlatformFee) => {
                        error!("❌ [SIGNING] ClaimPlatformFee with intent_hashes - invalid");
                        return;
                    }
                    Some(crate::types::TransactionType::PeerInvalidation) => "peer_invalidation",
                    None => {
                        // Check if this is an add_liquidity request (request_id starts with "addliq:")
                        if intent_hashes.iter().any(|h| h.starts_with("addliq:")) {
                            "add_liquidity"
                        } else {
                            error!("❌ [SIGNING] Transaction type is None for intent batch and not add_liquidity");
                            return;
                        }
                    }
                };

                for intent_hash in &intent_hashes {
                    if let Err(e) = user_intent_manager
                        .store_transaction_error(intent_hash, error_message, None)
                        .await
                    {
                        error!(
                            "❌ [SIGNING] Failed to store transaction error for intent {}: {}",
                            intent_hash, e
                        );
                    } else {
                        info!(
                            "💥 [SIGNING] Stored transaction error for intent {} (round {}): {}",
                            intent_hash, round, error_message
                        );
                    }
                }

                self.broadcast_transaction_error(
                    Some(intent_hashes.clone()),
                    error_message,
                    transaction_type_str,
                    None,
                )
                .await;
            }
            return;
        }

        // Reward / withdraw: no intent_hashes, use solver_address
        match (&retrieved_solver_address, &self.user_intent_manager) {
            (Some(_), _) | (_, Some(_)) => {}
            (None, None) => {
                info!(
                    "ℹ️ [NETWORK] No user registry available, skipping transaction error storage"
                );
                return;
            }
        }

        match (&retrieved_solver_address, &self.user_intent_manager) {
            (Some(_), _) | (_, Some(_)) => {
                if matches!(
                    transaction_type,
                    Some(crate::types::TransactionType::WithdrawLiquidity)
                ) {
                    if let Some(solver_addr) = retrieved_solver_address.as_deref() {
                        info!(
                            "💥 [SIGNING] Withdraw liquidity transaction error for solver {} (round {}): {}",
                            solver_addr, round, error_message
                        );
                        self.broadcast_transaction_error(
                            None,
                            error_message,
                            "withdraw_liquidity",
                            Some(solver_addr),
                        )
                        .await;
                    } else {
                        warn!(
                            "⚠️ [SIGNING] WithdrawLiquidity requires solver_address in round {}",
                            round
                        );
                    }
                }
            }
            (_, None) => {
                info!(
                    "ℹ️ [NETWORK] No user registry available, skipping transaction error storage"
                );
            }
        }
    }

    pub(crate) async fn store_transaction_id_for_round(
        &mut self,
        round: u64,
        tx_id: &str,
        txn_network: TransactionNetwork,
        intent_hash_override: Option<String>,
    ) {
        info!(
            "💾 [SIGNING] Storing transaction ID for round {} (tx_id={}, txn_network={:?}, intent_override={:?})",
            round, tx_id, txn_network, intent_hash_override
        );
        let is_withdraw_round = {
            let withdraw_rounds = self.pending.withdraw_rounds.read().await;
            withdraw_rounds.contains(&round)
        };
        info!("💾 [SIGNING] Is withdraw round: {}", is_withdraw_round);
        let is_claim_reward_round = {
            let claim_reward_rounds = self.pending.claim_reward_rounds.read().await;
            claim_reward_rounds.contains(&round)
        };
        let is_claim_platform_fee_round = {
            let claim_pf_rounds = self.pending.claim_platform_fee_rounds.read().await;
            claim_pf_rounds.contains(&round)
        };
        info!(
            "💾 [SIGNING] Is claim reward round: {}",
            is_claim_reward_round
        );

        let (intent_hash, transaction_type, retrieved_solver_address) = match txn_network {
            TransactionNetwork::TICS => {
                if is_withdraw_round {
                    let withdraw_pending_transactions =
                        self.pending.withdraw_pending_transactions_tics.read().await;
                    if let Some((
                        _tx,
                        _tx_bytes,
                        identifiers,
                        transaction_type,
                        _request_id,
                        _original_request,
                    )) = withdraw_pending_transactions.get(&round)
                    {
                        let solver_address =
                            identifiers.as_ref().and_then(|v| v.first()).map(|s| {
                                if let Some((_, solver)) = s.split_once('|') {
                                    solver.to_string()
                                } else {
                                    s.clone()
                                }
                            });
                        info!("[store_transaction_id_for_round] [TICS][Withdraw] Found withdraw_pending_transactions_tics entry for round {}: identifiers={}, transaction_type={:?}", round, identifiers.as_ref().map(|v| v.len()).unwrap_or(0), transaction_type);
                        (None, transaction_type.clone(), solver_address)
                    } else {
                        warn!("[store_transaction_id_for_round] [TICS][Withdraw] No entry in withdraw_pending_transactions_tics for round {}", round);
                        (None, None, None)
                    }
                } else if is_claim_reward_round {
                    let claim_reward_pending_tics = self
                        .pending
                        .claim_reward_pending_transactions_tics
                        .read()
                        .await;
                    if let Some((
                        _tx,
                        _tx_bytes,
                        _identifiers,
                        transaction_type,
                        _request_id,
                        _original_request,
                    )) = claim_reward_pending_tics.get(&round)
                    {
                        info!("[store_transaction_id_for_round] [TICS][ClaimReward] Found claim_reward_pending_transactions_tics entry for round {}: transaction_type={:?}", round, transaction_type);
                        (None, transaction_type.clone(), None)
                    } else {
                        warn!("[store_transaction_id_for_round] [TICS][ClaimReward] No entry in claim_reward_pending_transactions_tics for round {}", round);
                        (None, None, None)
                    }
                } else if is_claim_platform_fee_round {
                    let claim_pf_pending_tics = self
                        .pending
                        .claim_platform_fee_pending_transactions_tics
                        .read()
                        .await;
                    if let Some((
                        _tx,
                        _tx_bytes,
                        _identifiers,
                        transaction_type,
                        _request_id,
                        _original_request,
                    )) = claim_pf_pending_tics.get(&round)
                    {
                        info!("[store_transaction_id_for_round] [TICS][ClaimPlatformFee] Found claim_platform_fee_pending_transactions_tics entry for round {}: transaction_type={:?}", round, transaction_type);
                        (None, transaction_type.clone(), None)
                    } else {
                        warn!("[store_transaction_id_for_round] [TICS][ClaimPlatformFee] No entry in claim_platform_fee_pending_transactions_tics for round {}", round);
                        (None, None, None)
                    }
                } else {
                    // TICS UserToVault batch: use intent_hash_override when set
                    if let Some(ref intent_hash) = intent_hash_override {
                        info!("[store_transaction_id_for_round] [TICS][Non-Reward] Using intent_hash_override for round {}: intent_hash={}", round, intent_hash);
                        (Some(intent_hash.clone()), Some(TransactionType::UserToVault), None)
                    } else {
                        let pending_transactions = self.pending.pending_transactions.read().await;
                        if let Some((
                            _tx,
                            _tx_bytes,
                            intent_hash,
                            transaction_type,
                            _request_id,
                            _original_request,
                        )) = pending_transactions.get(&round)
                        {
                            info!("[store_transaction_id_for_round] [TICS][Non-Reward] Found pending_transactions entry for round {}: intent_hash={:?}, transaction_type={:?}", round, intent_hash, transaction_type);
                            (intent_hash.clone(), transaction_type.clone(), None)
                        } else {
                            warn!("[store_transaction_id_for_round] [TICS][Non-Reward] No entry in pending_transactions for round {}", round);
                            (None, None, None)
                        }
                    }
                }
            }
            TransactionNetwork::BTC => {
                if is_claim_reward_round {
                    let claim_reward_pending_btc = self
                        .pending
                        .claim_reward_pending_transactions_btc
                        .read()
                        .await;
                    if let Some((_tx, _tx_bytes, identifiers, transaction_type, _extras)) =
                        claim_reward_pending_btc.get(&round)
                    {
                        let solver_address = identifiers.as_ref().and_then(|v| {
                            v.iter().find_map(|encoded| {
                                encoded
                                    .split_once('|')
                                    .map(|(_, solver)| solver.to_string())
                            })
                        });
                        info!("[store_transaction_id_for_round] [BTC][ClaimReward] Found claim_reward_pending_transactions_btc entry for round {}: transaction_type={:?}", round, transaction_type);
                        (None, transaction_type.clone(), solver_address)
                    } else {
                        warn!("[store_transaction_id_for_round] [BTC][ClaimReward] No entry in claim_reward_pending_transactions_btc for round {}", round);
                        (None, None, None)
                    }
                } else if is_withdraw_round {
                    let withdraw_pending_transactions_btc =
                        self.pending.withdraw_pending_transactions_btc.read().await;
                    if let Some((_tx, _tx_bytes, identifiers, transaction_type, _extras)) =
                        withdraw_pending_transactions_btc.get(&round)
                    {
                        // For BTC withdraws, the "intent_hashes" slot is repurposed to carry
                        // batch metadata encoded as "request_id|solver_address".
                        let solver_address = identifiers.as_ref().and_then(|v| {
                            v.iter().find_map(|encoded| {
                                encoded
                                    .split_once('|')
                                    .map(|(_, solver)| solver.to_string())
                            })
                        });
                        info!("[store_transaction_id_for_round] [BTC][Withdraw] Found withdraw_pending_transactions_btc entry for round {}: solver_address={:?}, transaction_type={:?}", round, solver_address, transaction_type);
                        (None, transaction_type.clone(), solver_address)
                    } else {
                        warn!("[store_transaction_id_for_round] [BTC][Withdraw] No entry in withdraw_pending_transactions_btc for round {}", round);
                        (None, None, None)
                    }
                } else if is_claim_platform_fee_round {
                    let claim_pf_pending_btc = self
                        .pending
                        .claim_platform_fee_pending_transactions_btc
                        .read()
                        .await;
                    if let Some((_tx, _tx_bytes, _identifiers, transaction_type, _extras)) =
                        claim_pf_pending_btc.get(&round)
                    {
                        info!("[store_transaction_id_for_round] [BTC][ClaimPlatformFee] Found claim_platform_fee_pending_transactions_btc entry for round {}: transaction_type={:?}", round, transaction_type);
                        (None, transaction_type.clone(), None)
                    } else {
                        warn!("[store_transaction_id_for_round] [BTC][ClaimPlatformFee] No entry in claim_platform_fee_pending_transactions_btc for round {}", round);
                        (None, None, None)
                    }
                } else {
                    // BTC UserToVault batch: use intent_hash_override when set (same pattern as TICS)
                    if let Some(ref intent_hash) = intent_hash_override {
                        info!("[store_transaction_id_for_round] [BTC][UserToVault] Using intent_hash_override for round {}: intent_hash={}", round, intent_hash);
                        (Some(intent_hash.clone()), Some(TransactionType::UserToVault), None)
                    } else {
                        let pending_transactions_btc =
                            self.pending.pending_transactions_btc.read().await;
                        if let Some((_tx, _tx_bytes, intent_hashes, transaction_type, _extras)) =
                            pending_transactions_btc.get(&round)
                        {
                            let intent_hash = intent_hashes.as_ref().and_then(|v| v.first().cloned());
                            info!("[store_transaction_id_for_round] [BTC][Non-Reward] Found pending_transactions_btc entry for round {}: intent_hash={:?}, transaction_type={:?}", round, intent_hash, transaction_type);
                            (intent_hash, transaction_type.clone(), None)
                        } else {
                            warn!("[store_transaction_id_for_round] [BTC][Non-Reward] No entry in pending_transactions_btc for round {}", round);
                            (None, None, None)
                        }
                    }
                }
            }
        };

        match (intent_hash, &self.user_intent_manager) {
            (Some(ref intent_hash), Some(_user_intent_manager)) => {
                // For UserToVault, NetworkToTarget, and Refund, just broadcast without storing
                // Storage will be handled by handle_transaction_id_storage when the broadcast message is received
                let transaction_type_str = match transaction_type {
                    Some(crate::types::TransactionType::UserToVault) => {
                        if let Some(user_intent_manager) = &self.user_intent_manager {
                            if let Err(e) = user_intent_manager
                                .store_final_solver(intent_hash, self.id.as_str())
                                .await
                            {
                                warn!(
                                    "⚠️ [SIGNING] Failed to store final solver locally for intent {}: {}",
                                    intent_hash, e
                                );
                            }
                        }

                        info!(
                            "📡 [SIGNING] Broadcasting user-to-network transaction ID {} for intent {} (round {}) - storage will be handled by message handler",
                            tx_id, intent_hash, round
                        );
                        "user_to_vault"
                    }
                    Some(crate::types::TransactionType::NetworkToTarget) => {
                        info!(
                            "📡 [SIGNING] Broadcasting network-to-target transaction ID {} for intent {} (round {}) - storage will be handled by message handler",
                            tx_id, intent_hash, round
                        );
                        "network_to_target"
                    }
                    Some(crate::types::TransactionType::IntentStatusUpdate) => {
                        info!(
                            "📡 [SIGNING] Broadcasting intent-status-update transaction ID {} for intent {} (round {}) - will mark intent as Solved",
                            tx_id, intent_hash, round
                        );
                        "intent_status_update"
                    }

                    Some(crate::types::TransactionType::WithdrawLiquidity) => {
                        // Withdraw liquidity transactions should never have an intent_hash
                        error!(
                            "❌ [SIGNING] WithdrawLiquidity transaction type found with intent_hash - this is invalid."
                        );
                        return;
                    }
                    Some(crate::types::TransactionType::ClaimReward) => {
                        // ClaimReward transactions should never have an intent_hash
                        error!(
                            "❌ [SIGNING] ClaimReward transaction type found with intent_hash - this is invalid."
                        );
                        return;
                    }
                    Some(crate::types::TransactionType::ClaimPlatformFee) => {
                        // ClaimPlatformFee transactions should never have an intent_hash
                        error!(
                            "❌ [SIGNING] ClaimPlatformFee transaction type found with intent_hash - this is invalid."
                        );
                        return;
                    }
                    Some(crate::types::TransactionType::PeerInvalidation) => {
                        info!(
                            "📡 [SIGNING] Broadcasting peer_invalidation transaction ID {} for round (intent_hash={}) - storage will be handled by TransactionIdBroadcast handler",
                            tx_id, intent_hash
                        );
                        "peer_invalidation"
                    }
                    None => {
                        // Check if this is an add_liquidity request (request_id starts with "addliq:")
                        if intent_hash.starts_with("addliq:") {
                            info!(
                                "📡 [SIGNING] Broadcasting add_liquidity transaction ID {} for request {} (round {}) - storage will be handled by message handler",
                                tx_id, intent_hash, round
                            );
                            "add_liquidity"
                        } else {
                            // This shouldn't happen if we already handled reward transactions above
                            error!(
                                "❌ [SIGNING] Transaction type is None but no solver address available and not an add_liquidity request"
                            );
                            return;
                        }
                    }
                };

                // For batch transactions (BTC and TICS NetworkToTarget), check if there are multiple intent_hashes
                // stored in intent_hashes_by_round. If so, broadcast with all intent_hashes so each one
                // gets its network_to_target_tx_id updated.
                let intent_hashes_to_broadcast = {
                    let intent_map = self.pending.intent_hashes_by_round.read().await;
                    if let Some(batch_intent_hashes) = intent_map.get(&round) {
                        // If this is a batch transaction with multiple intent_hashes, use all of them
                        if batch_intent_hashes.len() > 1 {
                            info!(
                                "📦 [SIGNING] Detected batch transaction with {} intent hashes for round {}",
                                batch_intent_hashes.len(),
                                round
                            );
                            batch_intent_hashes.clone()
                        } else {
                            // Single intent transaction, use the primary intent_hash
                            vec![intent_hash.to_string()]
                        }
                    } else {
                        // Fallback to single intent_hash if not found in map
                        vec![intent_hash.to_string()]
                    }
                };

                // Broadcast transaction ID for UserToVault, NetworkToTarget, or Refund
                if intent_hashes_to_broadcast.len() > 1 {
                    info!(
                        "📡 [SIGNING] Broadcasting transaction ID {} for batch of {} intents (type: {})",
                        tx_id, intent_hashes_to_broadcast.len(), transaction_type_str
                    );
                } else {
                    info!(
                        "📡 [SIGNING] Broadcasting transaction ID {} for intent {} (type: {})",
                        tx_id, intent_hash, transaction_type_str
                    );
                }

                self.broadcast_transaction_id(
                    intent_hashes_to_broadcast,
                    tx_id,
                    transaction_type_str,
                    None,
                )
                .await;
            }
            (None, Some(_)) => {
                if matches!(
                    transaction_type,
                    Some(crate::types::TransactionType::ClaimReward)
                ) {
                    // ClaimReward: TICS vs BTC determined by which pending store has the round (same as WithdrawLiquidity).
                    let tics_has_round = self
                        .pending
                        .claim_reward_pending_transactions_tics
                        .read()
                        .await
                        .contains_key(&round);
                    if tics_has_round {
                        let claim_reward_pending_tics = self
                            .pending
                            .claim_reward_pending_transactions_tics
                            .read()
                            .await;
                        if let Some((
                            _tx,
                            _tx_bytes,
                            identifiers,
                            _tx_type,
                            _request_id,
                            _original_request,
                        )) = claim_reward_pending_tics.get(&round)
                        {
                            let network_label = crate::types::network::network_type().as_str();
                            let batch_requests: Vec<(String, String)> = identifiers
                                .as_ref()
                                .map(|list| {
                                    list.iter()
                                        .filter_map(|encoded| {
                                            encoded.split_once('|').map(|(req_id, solver)| {
                                                (req_id.to_string(), solver.to_string())
                                            })
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();

                            if !batch_requests.is_empty() {
                                info!(
                                "📡 [SIGNING] Broadcasting TICS claim-reward txid {} for round {} with {} requests via ClaimRewardTxIdBroadcast (batch)",
                                tx_id, round, batch_requests.len()
                            );
                                let msg = crate::types::ChannelMessage::ClaimRewardTxIdBroadcast {
                                    txid: tx_id.to_string(),
                                    network: network_label.to_string(),
                                    batch_id: format!("tics-claim-reward-round-{}", round),
                                    solver_address: None,
                                    requests: batch_requests,
                                    node_id: self.id.clone(),
                                };
                                if let Err(e) = self.message_tx.send(msg).await {
                                    error!(
                                    "❌ [SIGNING] Failed to send ClaimRewardTxIdBroadcast (TICS batch) for round {}: {}",
                                    round, e
                                );
                                }
                            } else if let Some((_req_id, solver_addr)) = identifiers
                                .as_ref()
                                .and_then(|list| list.first())
                                .and_then(|s| {
                                    s.split_once('|')
                                        .map(|(a, b)| (a.to_string(), b.to_string()))
                                })
                            {
                                info!(
                                "📡 [SIGNING] Broadcasting TICS claim-reward txid {} for solver {} (round {}) via ClaimRewardTxIdBroadcast (single)",
                                tx_id, solver_addr, round
                            );
                                let msg = crate::types::ChannelMessage::ClaimRewardTxIdBroadcast {
                                    txid: tx_id.to_string(),
                                    network: network_label.to_string(),
                                    batch_id: format!("tics-claim-reward-round-{}", round),
                                    solver_address: Some(solver_addr),
                                    requests: Vec::new(),
                                    node_id: self.id.clone(),
                                };
                                if let Err(e) = self.message_tx.send(msg).await {
                                    error!(
                                    "❌ [SIGNING] Failed to send ClaimRewardTxIdBroadcast (TICS single) for round {}: {}",
                                    round, e
                                );
                                }
                            } else {
                                warn!(
                                "⚠️ [SIGNING] TICS ClaimReward round {} has no batch identifiers and no single solver; skipping ClaimRewardTxIdBroadcast for tx_id={}",
                                round, tx_id
                            );
                            }
                        } else {
                            warn!(
                                "⚠️ [SIGNING] ClaimReward (TICS) but no claim_reward_pending_transactions_tics entry for round {} (tx_id={})",
                                round, tx_id
                            );
                        }
                    } else {
                        // BTC claim-reward batch: send ClaimRewardTxIdBroadcast (unified) so handlers store tx_id on PendingClaimRewardRequest (do not mark done).
                        let claim_reward_pending_btc = self
                            .pending
                            .claim_reward_pending_transactions_btc
                            .read()
                            .await;
                        if let Some((_tx, _tx_bytes, identifiers, _tx_type, _extras)) =
                            claim_reward_pending_btc.get(&round)
                        {
                            let batch_requests: Vec<(String, String)> = identifiers
                                .as_ref()
                                .map(|list| {
                                    list.iter()
                                        .filter_map(|encoded| {
                                            encoded.split_once('|').map(|(req_id, solver)| {
                                                (req_id.to_string(), solver.to_string())
                                            })
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();

                            if !batch_requests.is_empty() {
                                let network_label = crate::types::network::network_type().as_str();
                                info!(
                                "📡 [SIGNING] Broadcasting BTC claim-reward txid {} for round {} with {} requests via ClaimRewardTxIdBroadcast",
                                tx_id, round, batch_requests.len()
                            );
                                let msg = crate::types::ChannelMessage::ClaimRewardTxIdBroadcast {
                                    txid: tx_id.to_string(),
                                    network: network_label.to_string(),
                                    batch_id: format!("btc-claim-reward-round-{}", round),
                                    solver_address: None,
                                    requests: batch_requests,
                                    node_id: self.id.clone(),
                                };
                                if let Err(e) = self.message_tx.send(msg).await {
                                    error!(
                                    "❌ [SIGNING] Failed to send ClaimRewardTxIdBroadcast (BTC) for round {}: {}",
                                    round, e
                                );
                                }
                            } else {
                                warn!(
                                "⚠️ [SIGNING] BTC ClaimReward round {} has no batch identifiers; skipping ClaimRewardTxIdBroadcast for tx_id={}",
                                round, tx_id
                            );
                            }
                        } else {
                            warn!(
                                "⚠️ [SIGNING] ClaimReward (BTC) but no claim_reward_pending_transactions_btc entry for round {} (tx_id={})",
                                round, tx_id
                            );
                        }
                    }
                } else if matches!(
                    transaction_type,
                    Some(crate::types::TransactionType::ClaimPlatformFee)
                ) {
                    // ClaimPlatformFee: check TICS store first (contract call), then BTC store.
                    // TICS tx-id (0x prefix) → handler marks Completed. BTC tx-id → handler stores tx_id only.
                    let claim_pf_pending_tics = self
                        .pending
                        .claim_platform_fee_pending_transactions_tics
                        .read()
                        .await;
                    let tics_identifiers: Option<Vec<String>> = claim_pf_pending_tics
                        .get(&round)
                        .and_then(|(_, _, identifiers, _, _, _)| identifiers.clone());
                    drop(claim_pf_pending_tics);

                    let batch_identifiers = if let Some(ids) = tics_identifiers {
                        ids
                    } else {
                        // Fallback to BTC store
                        let claim_pf_pending_btc = self
                            .pending
                            .claim_platform_fee_pending_transactions_btc
                            .read()
                            .await;
                        claim_pf_pending_btc
                            .get(&round)
                            .and_then(|(_, _, identifiers, _, _)| identifiers.clone())
                            .unwrap_or_default()
                    };

                    let batch_requests: Vec<(String, String)> = batch_identifiers
                        .iter()
                        .filter_map(|encoded| {
                            encoded.split_once('|').map(|(req_id, admin)| {
                                (req_id.to_string(), admin.to_string())
                            })
                        })
                        .collect();

                    if !batch_requests.is_empty() {
                        let network_label = crate::types::network::network_type().as_str();
                        info!(
                            "📡 [SIGNING] Broadcasting claim-platform-fee txid {} for round {} with {} requests via ClaimPlatformFeeTxIdBroadcast",
                            tx_id, round, batch_requests.len()
                        );
                        let msg =
                            crate::types::ChannelMessage::ClaimPlatformFeeTxIdBroadcast {
                                txid: tx_id.to_string(),
                                network: network_label.to_string(),
                                batch_id: format!("claim-platform-fee-round-{}", round),
                                requests: batch_requests,
                                node_id: self.id.clone(),
                            };
                        if let Err(e) = self.message_tx.send(msg).await {
                            error!(
                                "❌ [SIGNING] Failed to send ClaimPlatformFeeTxIdBroadcast for round {}: {}",
                                round, e
                            );
                        }
                    } else {
                        warn!(
                            "⚠️ [SIGNING] ClaimPlatformFee round {} has no batch identifiers; skipping broadcast for tx_id={}",
                            round, tx_id
                        );
                    }
                } else if matches!(
                    transaction_type,
                    Some(crate::types::TransactionType::WithdrawLiquidity)
                ) {
                    // Withdraw liquidity:
                    // Use a unified WithdrawTxIdBroadcast message that the network layer
                    // interprets for both BTC and TICS withdraws.
                    match txn_network {
                        crate::types::TransactionNetwork::TICS => {
                            let network_label =
                                crate::types::network::network_type().as_str().to_string();
                            let withdraw_pending =
                                self.pending.withdraw_pending_transactions_tics.read().await;
                            let batch_requests: Vec<(String, String)> = withdraw_pending
                                .get(&round)
                                .and_then(|(_, _, identifiers, _, _, _)| identifiers.as_ref())
                                .filter(|v| !v.is_empty())
                                .map(|list| {
                                    list.iter()
                                        .filter_map(|encoded| {
                                            encoded.split_once('|').map(|(req_id, solver)| {
                                                (req_id.to_string(), solver.to_string())
                                            })
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();

                            if !batch_requests.is_empty() {
                                info!(
                                    "📡 [SIGNING] Broadcasting TICS withdraw-liquidity txid {} for {} request(s) (round {}) via WithdrawTxIdBroadcast",
                                    tx_id, batch_requests.len(), round
                                );
                                let msg = crate::types::ChannelMessage::WithdrawTxIdBroadcast {
                                    txid: tx_id.to_string(),
                                    network: network_label,
                                    batch_id: format!("tics-withdraw-round-{}", round),
                                    solver_address: None,
                                    requests: batch_requests,
                                    node_id: self.id.clone(),
                                };
                                if let Err(e) = self.message_tx.send(msg).await {
                                    error!(
                                        "❌ [SIGNING] Failed to send WithdrawTxIdBroadcast (TICS batch) over channel for round {}: {}",
                                        round, e
                                    );
                                }
                            } else if let Some(solver_addr) = retrieved_solver_address.as_ref() {
                                info!(
                                    "📡 [SIGNING] Broadcasting TICS withdraw-liquidity txid {} for solver {} (round {}) via WithdrawTxIdBroadcast",
                                    tx_id, solver_addr, round
                                );
                                let msg = crate::types::ChannelMessage::WithdrawTxIdBroadcast {
                                    txid: tx_id.to_string(),
                                    network: network_label,
                                    batch_id: format!("tics-withdraw-round-{}", round),
                                    solver_address: Some(solver_addr.to_string()),
                                    requests: Vec::new(),
                                    node_id: self.id.clone(),
                                };
                                if let Err(e) = self.message_tx.send(msg).await {
                                    error!(
                                        "❌ [SIGNING] Failed to send WithdrawTxIdBroadcast (TICS) over channel for round {}: {}",
                                        round, e
                                    );
                                }
                            } else {
                                warn!(
                                    "⚠️ [SIGNING] TICS WithdrawLiquidity round {} has no batch identifiers and no solver_address (tx_id={})",
                                    round, tx_id
                                );
                            }
                        }
                        crate::types::TransactionNetwork::BTC => {
                            // BTC withdraw: final node broadcasts txid + full batch mapping so
                            // all nodes can update their PendingWithdrawRequest.tx_id entries.
                            let withdraw_pending_transactions_btc =
                                self.pending.withdraw_pending_transactions_btc.read().await;
                            if let Some((_tx, _raw, identifiers, _tx_type, _extras)) =
                                withdraw_pending_transactions_btc.get(&round)
                            {
                                let batch_requests: Vec<(String, String)> = identifiers
                                    .as_ref()
                                    .map(|list| {
                                        list.iter()
                                            .filter_map(|encoded| {
                                                encoded.split_once('|').map(|(req_id, solver)| {
                                                    (req_id.to_string(), solver.to_string())
                                                })
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default();

                                if batch_requests.is_empty() {
                                    warn!(
                                        "⚠️ [SIGNING] BTC WithdrawLiquidity round {} has no batch identifiers; skipping WithdrawTxIdBroadcast for tx_id={}",
                                        round, tx_id
                                    );
                                    return;
                                }

                                let network_label = crate::types::network::network_type().as_str();

                                info!(
                                    "📡 [SIGNING] Broadcasting BTC withdraw-liquidity txid {} for round {} with {} requests (network={}) via WithdrawTxIdBroadcast",
                                    tx_id,
                                    round,
                                    batch_requests.len(),
                                    network_label
                                );

                                let msg = crate::types::ChannelMessage::WithdrawTxIdBroadcast {
                                    txid: tx_id.to_string(),
                                    network: network_label.to_string(),
                                    batch_id: format!("btc-withdraw-round-{}", round),
                                    // BTC path uses per-request mapping; solver_address is optional
                                    solver_address: None,
                                    requests: batch_requests,
                                    node_id: self.id.clone(),
                                };

                                if let Err(e) = self.message_tx.send(msg).await {
                                    error!(
                                        "❌ [SIGNING] Failed to send WithdrawTxIdBroadcast (BTC) over channel for round {}: {}",
                                        round, e
                                    );
                                }
                            } else {
                                warn!(
                                    "⚠️ [SIGNING] BTC WithdrawLiquidity transaction type but no withdraw_pending_transactions_btc entry for round {} (tx_id={})",
                                    round, tx_id
                                );
                            }
                        }
                    }
                }
            }
            (_, None) => {
                info!("ℹ️ [NETWORK] No user registry available, skipping transaction ID storage");
            }
        }
    }

    pub(crate) async fn broadcast_transaction_id(
        &self,
        intent_hashes: Vec<String>,
        tx_id: &str,
        transaction_type: &str,
        solver_address: Option<&str>,
    ) {
        let channel_message_transaction_id_broadcast =
            crate::types::ChannelMessage::TransactionIdBroadcast {
                intent_hashes: intent_hashes.clone(),
                transaction_id: tx_id.to_string(),
                transaction_type: transaction_type.to_string(),
                solver_address: solver_address.map(|s| s.to_string()),
                node_id: self.id.clone(),
            };

        if let Err(e) = self
            .message_tx
            .send(channel_message_transaction_id_broadcast)
            .await
        {
            error!(
                "❌ [SIGNING] Failed to broadcast transaction ID to other nodes: {}",
                e
            );
        } else {
            if !intent_hashes.is_empty() {
                info!(
                    "📡 [SIGNING] Broadcasted transaction ID {} for intents {:?} (type: {}) to other nodes",
                    tx_id, intent_hashes, transaction_type
                );
            } else if let Some(solver) = solver_address {
                info!(
                    "📡 [SIGNING] Broadcasted reward transaction ID {} for solver {} (type: {}) to other nodes",
                    tx_id, solver, transaction_type
                );
            } else {
                warn!(
                    "⚠️ [SIGNING] Broadcasted transaction ID {} without intent hashes or solver address (type: {})",
                    tx_id, transaction_type
                );
            }
        }
    }

    pub(crate) async fn broadcast_transaction_error(
        &self,
        intent_hashes: Option<Vec<String>>,
        error_message: &str,
        transaction_type: &str,
        solver_address: Option<&str>,
    ) {
        let intent_hashes = intent_hashes.unwrap_or_default();
        let broadcast_message = crate::types::GossipsubMessage::TransactionErrorBroadcast {
            intent_hashes: intent_hashes.clone(),
            error_message: error_message.to_string(),
            transaction_type: transaction_type.to_string(),
            solver_address: solver_address.map(|s| s.to_string()),
            node_id: self.id.clone(),
        };

        let channel_message = crate::types::ChannelMessage::Broadcast {
            topic: "transaction-sync".to_string(),
            data: serde_json::to_vec(&broadcast_message).unwrap_or_default(),
        };

        if let Err(e) = self.message_tx.send(channel_message).await {
            error!(
                "❌ [SIGNING] Failed to broadcast transaction error to other nodes: {}",
                e
            );
        } else {
            match (intent_hashes.is_empty(), solver_address) {
                (false, _) => {
                    info!(
                        "📡 [SIGNING] Broadcasted transaction error for {} intent(s) (type: {}) to other nodes: {}",
                        intent_hashes.len(), transaction_type, error_message
                    );
                }
                (true, Some(solver)) => {
                    info!(
                        "📡 [SIGNING] Broadcasted reward transaction error for solver {} (type: {}) to other nodes: {}",
                        solver, transaction_type, error_message
                    );
                }
                (true, None) => {
                    warn!(
                        "⚠️ [SIGNING] Broadcasted transaction error without intent hashes or solver address (type: {}): {}",
                        transaction_type, error_message
                    );
                }
            }
        }
    }

    /// Broadcast transaction success with request_id for sequencer tracking
    pub(crate) async fn broadcast_transaction_success(
        &self,
        sequencer_request_id: &str,
        blockchain_tx_hash: &str,
        chain_id: u64,
    ) {
        let broadcast_message = crate::types::GossipsubMessage::TransactionBroadcast {
            sequencer_request_id: Some(sequencer_request_id.to_string()),
            blockchain_tx_hash: blockchain_tx_hash.to_string(),
            chain_id,
        };

        let channel_message = crate::types::ChannelMessage::Broadcast {
            topic: "transaction-broadcast".to_string(),
            data: serde_json::to_vec(&broadcast_message).unwrap_or_default(),
        };

        if let Err(e) = self.message_tx.send(channel_message).await {
            error!(
                "❌ [SIGNING] Failed to broadcast transaction success to other nodes: {}",
                e
            );
        } else {
            info!(
                "📡 [SIGNING] Broadcasted transaction success: request_id={}, tx_hash={}, chain_id={}",
                sequencer_request_id, blockchain_tx_hash, chain_id
            );
        }
    }

    /// Broadcast transaction failure with request_id for sequencer retry
    pub(crate) async fn broadcast_transaction_failure(
        &self,
        sequencer_request_id: &str,
        blockchain_tx_hash: &str,
        error: &str,
        original_request: Option<()>,
    ) {
        let channel_message = crate::types::ChannelMessage::TransactionFailure {
            sequencer_request_id: sequencer_request_id.to_string(),
            blockchain_tx_hash: blockchain_tx_hash.to_string(),
            error: error.to_string(),
            original_request,
        };

        if let Err(e) = self.message_tx.send(channel_message).await {
            error!(
                "❌ [SIGNING] Failed to send transaction failure to channel: {}",
                e
            );
        } else {
            warn!(
                "📡 [SIGNING] Sent transaction failure to channel: request_id={}, tx_hash={}, error={}",
                sequencer_request_id, blockchain_tx_hash, error
            );
        }
    }
}
