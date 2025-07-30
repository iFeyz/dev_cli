use alloy::{
    primitives::{Address, U256, utils::parse_ether},
    signers::local::PrivateKeySigner,
    transports::http::{Client, Http},
    providers::{ProviderBuilder, Provider, ext::TraceApi},
    rpc::types::trace::parity::TraceType,
};
use anyhow::{Result, Context};
use std::str::FromStr;

// Import your modules
use crate::config::Config;
use crate::model::interaction::{Transaction, UserCredentials, RequestConfig};

pub struct TransactionExample {
    config: Config,
}

impl TransactionExample {
    pub fn new() -> Result<Self> {
        let config = Config::load()?;
        config.validate()?;
        Ok(Self { config })
    }

    pub async fn send_alice_to_bob(&self) -> Result<()> {
        println!("🚀 Starting Alice to Bob transaction example");
        
        // Setup Alice's credentials (sender)
        // In a real scenario, you'd load this from environment or secure storage
        let alice_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // Anvil account #0
        let alice_signer = PrivateKeySigner::from_str(alice_private_key)
            .context("Failed to create Alice's signer")?;
        let alice_credentials = UserCredentials::new(alice_signer);

        // Bob's address (recipient)
        let bob_address = Address::from_str("0x70997970C51812dc3A010C7d01b50e0d17dc79C8") // Anvil account #1
            .context("Failed to parse Bob's address")?;

        // Amount to send (0.1 ETH)
        let amount = parse_ether("0.1")
            .context("Failed to parse amount")?;

        println!("👤 Alice address: {}", alice_credentials.address());
        println!("👤 Bob address: {}", bob_address);
        println!("💰 Amount: {} ETH", amount);

        // Create request configuration from your network config
        let request_config = RequestConfig {
            gas_limit: U256::from(self.config.gas_limit),
            gas_price: self.config.gas_price
                .map(U256::from)
                .unwrap_or(U256::from(20_000_000_000u64)), // 20 gwei default
            nonce: None, // Let the provider determine the nonce
        };

        // Create the transaction
        let transaction = Transaction::new_eth_transfer(
            bob_address,
            amount,
            alice_credentials,
            Some(request_config),
        );

        // Setup the provider - use connect_http instead of deprecated on_http
        let provider = ProviderBuilder::new()
            .connect_http(self.config.rpc_url.parse()?);

        println!("🌐 Connected to network: {}", self.config.network_name);
        println!("🔗 Chain ID: {}", self.config.chain_id);

        // Check Alice's balance before transaction
        let alice_balance_before = provider
            .get_balance(transaction.user_credentials.address())
            .await
            .context("Failed to get Alice's balance")?;
        
        let bob_balance_before = provider
            .get_balance(bob_address)
            .await
            .context("Failed to get Bob's balance")?;

        println!("\n💼 Balances before transaction:");
        println!("  Alice: {} ETH", alice_balance_before);
        println!("  Bob: {} ETH", bob_balance_before);

        // Execute the transaction with tracing
        println!("\n🔄 Executing transaction...");
        let result = transaction.execute(&provider).await;

        match result {
            result if result.success => {
                println!("✅ Transaction successful!");
                
                if let Some(tx_hash) = &result.transaction_hash {
                    println!("📝 Transaction hash: {}", tx_hash);
                }

                if let Some(data) = &result.data {
                    println!("📊 Transaction details:");
                    println!("  Amount sent: {} ETH", data.amount_sent);
                    println!("  Recipient: {}", data.recipient);
                    println!("  Gas used: {}", data.gas_used);
                }

                if let Some(trace_info) = &result.trace_info {
                    println!("🔍 Trace information:");
                    println!("  Gas used: {}", trace_info.gas_used);
                    println!("  Success: {}", trace_info.success);
                    println!("  Function calls: {}", trace_info.calls.len());
                    println!("  Logs count: {}", trace_info.logs_count);
                }

                // Check balances after transaction
                let alice_balance_after = provider
                    .get_balance(transaction.user_credentials.address())
                    .await
                    .context("Failed to get Alice's balance after transaction")?;
                
                let bob_balance_after = provider
                    .get_balance(bob_address)
                    .await
                    .context("Failed to get Bob's balance after transaction")?;

                println!("\n💼 Balances after transaction:");
                println!("  Alice: {} ETH", alice_balance_after);
                println!("  Bob: {} ETH", bob_balance_after);

                let alice_diff = alice_balance_before.saturating_sub(alice_balance_after);
                let bob_diff = bob_balance_after.saturating_sub(bob_balance_before);

                println!("\n📈 Balance changes:");
                println!("  Alice spent: {} ETH (including gas)", alice_diff);
                println!("  Bob received: {} ETH", bob_diff);
            }
            _ => {
                println!("❌ Transaction failed!");
                
                if let Some(error) = &result.error {
                    println!("💥 Error: {}", error);
                }

                if let Some(trace_info) = &result.trace_info {
                    println!("🔍 Trace information (failed):");
                    println!("  Gas used: {}", trace_info.gas_used);
                    println!("  Success: {}", trace_info.success);
                    if let Some(error) = &trace_info.error {
                        println!("  Error: {}", error);
                    }
                }
            }
        }

        Ok(())
    }

    // Alternative method for token transfers
    pub async fn send_token_alice_to_bob(
        &self,
        token_contract_address: &str,
        amount: &str,
    ) -> Result<()> {
        println!("🪙 Starting token transfer from Alice to Bob");

        // Setup credentials
        let alice_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let alice_signer = PrivateKeySigner::from_str(alice_private_key)
            .context("Failed to create Alice's signer")?;
        let alice_credentials = UserCredentials::new(alice_signer);

        let bob_address = Address::from_str("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
            .context("Failed to parse Bob's address")?;

        let token_address = Address::from_str(token_contract_address)
            .context("Failed to parse token contract address")?;

        let token_amount = U256::from_str(amount)
            .context("Failed to parse token amount")?;

        // Create request configuration
        let request_config = RequestConfig {
            gas_limit: U256::from(100_000), // Higher gas limit for token transfers
            gas_price: self.config.gas_price
                .map(U256::from)
                .unwrap_or(U256::from(20_000_000_000u64)),
            nonce: None,
        };

        // Create token transfer transaction
        let transaction = Transaction::new_token_transfer(
            bob_address,
            token_address,
            token_amount,
            alice_credentials,
            Some(request_config),
        );

        // Setup provider - use connect_http instead of deprecated on_http
        let provider = ProviderBuilder::new()
            .connect_http(self.config.rpc_url.parse()?);

        println!("🪙 Token contract: {}", token_address);
        println!("👤 From: {}", transaction.user_credentials.address());
        println!("👤 To: {}", bob_address);
        println!("💰 Amount: {}", token_amount);

        // Execute the transaction
        let result = transaction.execute(&provider).await;

        match result {
            result if result.success => {
                println!("✅ Token transfer successful!");
                
                if let Some(tx_hash) = &result.transaction_hash {
                    println!("📝 Transaction hash: {}", tx_hash);
                }
            }
            _ => {
                println!("❌ Token transfer failed!");
                if let Some(error) = &result.error {
                    println!("💥 Error: {}", error);
                }
            }
        }

        Ok(())
    }
}

// Usage example in your main function or interactive menu
pub async fn run_transaction_example() -> Result<()> {
    let example = TransactionExample::new()?;
    
    // Send ETH from Alice to Bob
    example.send_alice_to_bob().await?;
    
    // Optional: Send tokens (uncomment and provide token address)
    // example.send_token_alice_to_bob(
    //     "0xA0b86a33E6441e9e9e2C7a7b7b7f9a1a1a1a1a1a", // Example token address
    //     "1000000000000000000" // 1 token (18 decimals)
    // ).await?;
    
    Ok(())
}

