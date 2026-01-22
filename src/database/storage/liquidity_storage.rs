use crate::database::{key_utils, Database};
use crate::types::intent::TransactionNetwork;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Clone)]
pub struct LiquidityStorage {
    db: Database,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct LiquidityTxnRecord {
    last_tx_id: Option<String>,
    pending_amount: Option<String>,
}

impl LiquidityTxnRecord {
    fn is_empty(&self) -> bool {
        self.last_tx_id.is_none() && self.pending_amount.is_none()
    }
}

impl LiquidityStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    fn key_for_remove(&self, solver_address: &str, network: TransactionNetwork) -> String {
        match network {
            TransactionNetwork::TICS => {
                key_utils::solver_remove_liquidity_tics_txn_key(solver_address)
            }
            TransactionNetwork::BTC => {
                key_utils::solver_remove_liquidity_btc_txn_key(solver_address)
            }
        }
    }

    fn load_record(&self, key: &str) -> Result<LiquidityTxnRecord> {
        if let Some(raw) = self.db.get_string::<String>(key)? {
            Ok(serde_json::from_str(&raw).unwrap_or_default())
        } else {
            Ok(LiquidityTxnRecord::default())
        }
    }

    fn store_record(&self, key: &str, record: &LiquidityTxnRecord) -> Result<()> {
        if record.is_empty() {
            self.db.delete_string(key)?;
        } else {
            let serialized = serde_json::to_string(record)?;
            self.db.put_string(key, &serialized)?;
        }
        Ok(())
    }

    pub async fn set_remove_liquidity_tx_id(
        &self,
        solver_address: &str,
        network: TransactionNetwork,
        tx_id: String,
    ) -> Result<()> {
        let key = self.key_for_remove(solver_address, network);
        let mut record = self.load_record(&key)?;
        record.last_tx_id = Some(tx_id);
        self.store_record(&key, &record)
    }

    pub async fn get_remove_liquidity_tx_id(
        &self,
        solver_address: &str,
        network: TransactionNetwork,
    ) -> Result<Option<String>> {
        let key = self.key_for_remove(solver_address, network);
        Ok(self.load_record(&key)?.last_tx_id)
    }

    pub async fn set_pending_remove_liquidity_amount(
        &self,
        solver_address: &str,
        network: TransactionNetwork,
        amount: String,
    ) -> Result<()> {
        let key = self.key_for_remove(solver_address, network);
        let mut record = self.load_record(&key)?;
        record.pending_amount = Some(amount);
        self.store_record(&key, &record)
    }

    pub async fn take_pending_remove_liquidity_amount(
        &self,
        solver_address: &str,
        network: TransactionNetwork,
    ) -> Result<Option<String>> {
        let key = self.key_for_remove(solver_address, network);
        let mut record = self.load_record(&key)?;
        let pending_amount = record.pending_amount.take();
        self.store_record(&key, &record)?;
        Ok(pending_amount)
    }
}
