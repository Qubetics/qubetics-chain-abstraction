use crate::database::{Database, keys};
use anyhow::Result;

/// Database-backed reward storage
#[derive(Clone)]
pub struct RewardStorage {
    db: Database,
}

impl RewardStorage {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Store total liquidity in tics
    pub async fn set_total_liquidity_tics(&self, tics: u64) -> Result<()> {
        self.db.put_string(keys::TOTAL_LIQUIDITY_TICS, &tics)?;
        Ok(())
    }

    /// Get total liquidity in tics
    pub async fn get_total_liquidity_tics(&self) -> Result<Option<u64>> {
        self.db.get_string(keys::TOTAL_LIQUIDITY_TICS)
    }

    /// Store total liquidity in BTC (as f64)
    pub async fn set_total_liquidity_btc(&self, btc: f64) -> Result<()> {
        self.db.put_string(keys::TOTAL_LIQUIDITY_BTC, &btc.to_string())?;
        Ok(())
    }

    /// Get total liquidity in BTC (as f64)
    pub async fn get_total_liquidity_btc(&self) -> Result<Option<f64>> {
        self.db.get_string(keys::TOTAL_LIQUIDITY_BTC)
    }

    /// Delete total liquidity tics
    pub async fn delete_total_liquidity_tics(&self) -> Result<()> {
        self.db.delete_string(keys::TOTAL_LIQUIDITY_TICS)?;
        Ok(())
    }

    /// Delete total liquidity btc
    pub async fn delete_total_liquidity_btc(&self) -> Result<()> {
        self.db.delete_string(keys::TOTAL_LIQUIDITY_BTC)?;
        Ok(())
    }
}
