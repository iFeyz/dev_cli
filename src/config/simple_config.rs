use anyhow::{Result, Context};
use std::env;

use alloy::providers::ProviderBuilder;
use alloy::providers::Provider;
use alloy::network::Network;

#[derive(Debug, Clone)]
pub struct Config {
    pub rpc_url: String,
    pub chain_id: u64,
    pub network_name: String,
    pub gas_limit: u64, 
    pub gas_price: Option<u64>,
}

impl Config {

    pub fn load() -> Result<Self> {
        let rpc_url = env::var("RPC_URL")
            .unwrap_or_else(|_| "http://localhost:8545".to_string());

        let chain_id_str = env::var("CHAIN_ID")
            .unwrap_or_else(|_| "1".to_string());
        let chain_id = chain_id_str.parse::<u64>()
            .context(format!("Invalid CHAIN_ID: '{}'", chain_id_str))?;

        let network_name_result = env::var("NETWORK_NAME");
        println!("DEBUG: NETWORK_NAME env var result: {:?}", network_name_result); // Add this
        let network_name = network_name_result
            .unwrap_or_else(|_| "mainnet".to_string());

        let gas_limit_str = env::var("GAS_LIMIT")
            .unwrap_or_else(|_| "21000".to_string());
        let gas_limit = gas_limit_str.parse::<u64>()
            .context(format!("Invalid GAS_LIMIT: '{}'", gas_limit_str))?;

        let gas_price_result = env::var("GAS_PRICE");
        println!("DEBUG: GAS_PRICE env var result: {:?}", gas_price_result); // Add this
        let gas_price = gas_price_result
            .ok()
            .and_then(|s| s.parse().ok());

        Ok(Self {
            rpc_url,
            chain_id,
            network_name,
            gas_limit,
            gas_price,
        })
    
    }

    /// Configuration par défaut pour Anvil (développement local)
    pub fn default_anvil() -> Self {
        Self {
            rpc_url: "http://localhost:8545".to_string(),
            chain_id: 31337,
            network_name: "anvil".to_string(),
            gas_limit: 21000,
            gas_price: Some(20_000_000_000), // 20 gwei
        }
    }

    /// Configuration pour le mainnet Ethereum
    pub fn mainnet() -> Self {
        Self {
            rpc_url: "https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY".to_string(),
            chain_id: 1,
            network_name: "mainnet".to_string(),
            gas_limit: 21000,
            gas_price: None, // Will use network gas price
        }
    }

    /// Configuration pour le testnet Sepolia
    pub fn sepolia() -> Self {
        Self {
            rpc_url: "https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY".to_string(),
            chain_id: 11155111,
            network_name: "sepolia".to_string(),
            gas_limit: 21000,
            gas_price: None,
        }
    }

    /// Valide la configuration
    pub fn validate(&self) -> Result<()> {
        if self.rpc_url.is_empty() {
            anyhow::bail!("RPC URL cannot be empty");
        }

        if self.chain_id == 0 {
            anyhow::bail!("Chain ID cannot be zero");
        }

        if self.network_name.is_empty() {
            anyhow::bail!("Network name cannot be empty");
        }

        if self.gas_limit == 0 {
            anyhow::bail!("Gas limit cannot be zero");
        }

        Ok(())
    }
}