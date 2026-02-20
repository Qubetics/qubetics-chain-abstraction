use anyhow::Result;
use std::collections::HashMap;

use crate::chain_abstraction::handlers::{BitcoinChainHandler, ChainHandler, TicsChainHandler};
use crate::types::network as network_cfg;

/// Chain handler factory helpers
pub struct ChainHandlerFactory;

impl ChainHandlerFactory {
    pub fn create_tics_handler(chain_id: u64) -> Box<dyn ChainHandler> {
        Box::new(TicsChainHandler::new(chain_id))
    }

    pub fn create_bitcoin_handler(network: String) -> Box<dyn ChainHandler> {
        Box::new(BitcoinChainHandler::new(network))
    }

    pub fn create_handler_by_type(
        chain_type: &str,
        params: HashMap<String, String>,
    ) -> Result<Box<dyn ChainHandler>> {
        match chain_type {
            "tics" => {
                let chain_id = params
                    .get("chain_id")
                    .ok_or_else(|| anyhow::anyhow!("Missing chain_id parameter for TICS"))?
                    .parse::<u64>()?;
                Ok(Self::create_tics_handler(chain_id))
            }
            "bitcoin" => {
                let network = params.get("network").cloned().unwrap_or_else(|| {
                    network_cfg::network_type()
                        .bitcoin_network_label()
                        .to_string()
                });
                Ok(Self::create_bitcoin_handler(network))
            }
            _ => Err(anyhow::anyhow!("Unsupported chain type: {}", chain_type)),
        }
    }
}
