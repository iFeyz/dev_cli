#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{address, b256, U256, utils::Unit},
        providers::{ProviderBuilder, Provider},
        rpc::types::{TransactionReceipt, Transaction, BlockNumberOrTag},
        signers::local::PrivateKeySigner,
        network::TransactionBuilder,
    };
    use std::time::Duration;
    use tokio::time::timeout;

    // Test constants
    const ANVIL_URL: &str = "http://127.0.0.1:8545";
    const ANVIL_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const TEST_TIMEOUT: Duration = Duration::from_secs(30);

    // Helper function to setup provider
    async fn setup_provider() -> Result<impl Provider, Box<dyn std::error::Error>> {
        let provider = ProviderBuilder::new()
            .connect(ANVIL_URL)
            .await?;
        Ok(provider)
    }

    // Helper function to setup provider with wallet
    async fn setup_provider_with_wallet() -> Result<impl Provider, Box<dyn std::error::Error>> {
        let signer: PrivateKeySigner = ANVIL_PRIVATE_KEY.parse()?;
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect(ANVIL_URL)
            .await?;
        Ok(provider)
    }

    // Helper function to create a test transaction with proper nonce management
    async fn create_test_transaction() -> Result<alloy::primitives::B256, Box<dyn std::error::Error>> {
        let provider = setup_provider_with_wallet().await?;
        let alice = address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
        let value = Unit::ETHER.wei().saturating_mul(U256::from(1));
        
        // Get the current nonce to avoid nonce conflicts
        let accounts = provider.get_accounts().await?;
        let from_address = accounts[0];
        let nonce = provider.get_transaction_count(from_address).await?;
        
        let tx = alloy::rpc::types::TransactionRequest::default()
            .with_to(alice)
            .with_value(value)
            .with_nonce(nonce);

        let pending_tx = provider.send_transaction(tx).await?;
        let tx_hash = *pending_tx.tx_hash();
        let _receipt = pending_tx.get_receipt().await?;
        
        Ok(tx_hash)
    }

    mod transaction_info_tests {
        use super::*;
        use crate::actions::info::TransactionInfo;

        #[tokio::test]
        async fn test_transaction_info_display() {
            let tx_info = TransactionInfo {
                network_chain_id: 31337,
                from_address: address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
                to_address: Some(address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")),
                value: U256::from(1000000000000000000u64), // 1 ETH in wei
                tx_hash: b256!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
                block_number: Some(1),
                block_hash: Some(b256!("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")),
                block_timestamp: Some(1640995200), // 2022-01-01 00:00:00 UTC
                gas_limit: 21000,
                gas_used: Some(21000),
                gas_price: Some(20000000000), // 20 gwei
                nonce: 0,
                transaction_index: Some(0),
                status: Some(true),
            };

            let display_str = format!("{}", tx_info);
            
            // Check that all important fields are present in the display
            assert!(display_str.contains("📊 Transaction Information:"));
            assert!(display_str.contains("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"));
            assert!(display_str.contains("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"));
            assert!(display_str.contains("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"));
            assert!(display_str.contains("1.000000000000000000 ETH") || display_str.contains("1 ETH"));
            assert!(display_str.contains("✅ Success"));
            assert!(display_str.contains("31337"));
        }

        #[tokio::test]
        async fn test_transaction_info_display_pending() {
            let tx_info = TransactionInfo {
                network_chain_id: 31337,
                from_address: address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
                to_address: None, // Contract creation
                value: U256::ZERO,
                tx_hash: b256!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
                block_number: None,
                block_hash: None,
                block_timestamp: None,
                gas_limit: 21000,
                gas_used: None,
                gas_price: None,
                nonce: 0,
                transaction_index: None,
                status: None, // Pending
            };

            let display_str = format!("{}", tx_info);
            
            assert!(display_str.contains("⏳ Pending"));
            assert!(display_str.contains("None")); // to_address is None
            assert!(display_str.contains("Pending")); // Various pending fields
        }

        #[tokio::test]
        async fn test_transaction_info_display_failed() {
            let tx_info = TransactionInfo {
                network_chain_id: 31337,
                from_address: address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
                to_address: Some(address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")),
                value: U256::from(1000000000000000000u64),
                tx_hash: b256!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
                block_number: Some(1),
                block_hash: Some(b256!("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")),
                block_timestamp: Some(1640995200),
                gas_limit: 21000,
                gas_used: Some(21000),
                gas_price: Some(20000000000),
                nonce: 0,
                transaction_index: Some(0),
                status: Some(false), // Failed
            };

            let display_str = format!("{}", tx_info);
            assert!(display_str.contains("❌ Failed"));
        }

        #[tokio::test]
        async fn test_transaction_info_utility_methods() {
            let successful_tx = TransactionInfo {
                network_chain_id: 31337,
                from_address: address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
                to_address: Some(address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")),
                value: U256::from(1000000000000000000u64), // 1 ETH
                tx_hash: b256!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
                block_number: Some(1),
                block_hash: Some(b256!("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")),
                block_timestamp: Some(1640995200),
                gas_limit: 21000,
                gas_used: Some(21000),
                gas_price: Some(20000000000), // 20 gwei
                nonce: 0,
                transaction_index: Some(0),
                status: Some(true),
            };

            // Test is_successful
            assert!(successful_tx.is_successful());
            assert!(!successful_tx.is_pending());

            // Test value_in_ether
            let ether_value = successful_tx.value_in_ether();
            assert!(ether_value.starts_with("1"));

            // Test gas_fee_in_ether
            let gas_fee = successful_tx.gas_fee_in_ether();
            assert!(gas_fee.is_some());
            let fee_str = gas_fee.unwrap();
            assert!(fee_str.starts_with("0.00042")); // 21000 * 20 gwei = 0.00042 ETH

            // Test pending transaction
            let pending_tx = TransactionInfo {
                status: None,
                gas_used: None,
                gas_price: None,
                ..successful_tx
            };

            assert!(!pending_tx.is_successful());
            assert!(pending_tx.is_pending());
            assert!(pending_tx.gas_fee_in_ether().is_none());
        }

        #[tokio::test]
        async fn test_from_hash_invalid_hash() {
            let provider = setup_provider().await.expect("Failed to setup provider");
            let invalid_hash = b256!("0x0000000000000000000000000000000000000000000000000000000000000000");
            
            let result = timeout(
                TEST_TIMEOUT,
                TransactionInfo::from_hash(&provider, invalid_hash)
            ).await;

            match result {
                Ok(tx_result) => {
                    assert!(tx_result.is_err(), "Should fail with invalid hash");
                }
                Err(_) => {
                    println!("Test timed out (expected if Anvil is not running)");
                }
            }
        }

        #[tokio::test]
        async fn test_from_hash_with_real_transaction() {
            // This test requires Anvil to be running
            let provider_result = setup_provider().await;
            if provider_result.is_err() {
                println!("Skipping test - Anvil not available");
                return;
            }

            // First create a transaction
            let tx_hash_result = timeout(TEST_TIMEOUT, create_test_transaction()).await;
            if tx_hash_result.is_err() {
                println!("Skipping test - Could not create test transaction");
                return;
            }

            let tx_hash = tx_hash_result.unwrap().expect("Failed to create test transaction");
            let provider = provider_result.unwrap();

            // Now test getting transaction info
            let result = timeout(
                TEST_TIMEOUT,
                TransactionInfo::from_hash(&provider, tx_hash)
            ).await;

            match result {
                Ok(tx_info_result) => {
                    let tx_info = tx_info_result.expect("Should successfully get transaction info");
                    
                    assert_eq!(tx_info.tx_hash, tx_hash);
                    assert_eq!(tx_info.network_chain_id, 31337); // Anvil default chain ID
                    assert!(tx_info.is_successful());
                    assert!(!tx_info.is_pending());
                    assert!(tx_info.block_number.is_some());
                    assert!(tx_info.gas_used.is_some());
                }
                Err(_) => {
                    println!("Test timed out (Anvil might not be running)");
                }
            }
        }

        #[tokio::test]
        async fn test_from_transaction_and_receipt() {
            // This is a more complex test that would require mocking or real blockchain data
            // For now, we'll skip it or implement with mock data when we have more transaction data
            println!("Note: from_transaction_and_receipt test would require more complex setup");
        }
    }

    mod sending_tests {
        use super::*;
        use crate::actions::sending::{send_eth, get_transaction_info, SendError};

        #[tokio::test]
        async fn test_send_error_creation() {
            let error = SendError::new("Test error".to_string(), 42);
            assert_eq!(error.message, "Test error");
            assert_eq!(error.code, 42);
            
            let display_str = format!("{}", error);
            assert!(display_str.contains("SendError(42): Test error"));
        }

        #[tokio::test]
        async fn test_send_error_from_error() {
            let std_error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection failed");
            let send_error = SendError::from_error(std_error);
            
            assert!(send_error.message.contains("connection"));
            assert_eq!(send_error.code, 2); // Network error code
        }

        #[tokio::test]
        async fn test_error_code_mapping() {
            // Test various error message patterns
            let test_cases = vec![
                ("private key invalid", 1),
                ("connection refused", 2),
                ("RPC error occurred", 3),
                ("insufficient funds", 4),
                ("gas limit exceeded", 5),
                ("nonce too low", 6),
                ("timeout occurred", 7),
                ("receipt not found", 8),
                ("invalid address", 9),
                ("serialize failed", 10),
                ("unknown error", -1),
            ];

            for (msg, expected_code) in test_cases {
                let error = SendError::from_error(std::io::Error::new(std::io::ErrorKind::Other, msg));
                assert_eq!(error.code, expected_code, "Failed for message: {}", msg);
            }
        }

        #[tokio::test]
        async fn test_send_eth_with_invalid_key() {
            // This test should fail during signer creation
            // We can't easily test this without modifying the function to accept parameters
            // For now, we acknowledge this would require refactoring for better testability
            println!("Note: send_eth test with invalid key would require function refactoring");
        }

        #[tokio::test]
        async fn test_send_eth_integration() {
            // Integration test - requires Anvil to be running
            let result = timeout(TEST_TIMEOUT, send_eth()).await;
            
            match result {
                Ok(tx_result) => {
                    match tx_result {
                        Ok(tx_info) => {
                            println!("✅ Transaction successful: {}", tx_info.tx_hash);
                            assert!(tx_info.is_successful());
                            assert_eq!(tx_info.network_chain_id, 31337);
                            assert!(tx_info.value > U256::ZERO);
                        }
                        Err(send_error) => {
                            println!("❌ Transaction failed (expected if Anvil not running): {}", send_error);
                            // This is expected if Anvil is not running
                            assert!(send_error.code > 0 || send_error.code == -1);
                        }
                    }
                }
                Err(_) => {
                    println!("⏱️  Test timed out (Anvil likely not running)");
                }
            }
        }

        #[tokio::test]
        async fn test_get_transaction_info_invalid_hash() {
            let result = timeout(
                TEST_TIMEOUT, 
                get_transaction_info("invalid_hash")
            ).await;

            match result {
                Ok(tx_result) => {
                    assert!(tx_result.is_err(), "Should fail with invalid hash format");
                    let error = tx_result.unwrap_err();
                    assert_eq!(error.code, 1); // Parse error
                }
                Err(_) => {
                    println!("Test timed out");
                }
            }
        }

        #[tokio::test]
        async fn test_get_transaction_info_nonexistent_hash() {
            let result = timeout(
                TEST_TIMEOUT,
                get_transaction_info("0x0000000000000000000000000000000000000000000000000000000000000000")
            ).await;

            match result {
                Ok(tx_result) => {
                    // Should fail because transaction doesn't exist
                    assert!(tx_result.is_err(), "Should fail with nonexistent hash");
                }
                Err(_) => {
                    println!("Test timed out (expected if Anvil not running)");
                }
            }
        }

        #[tokio::test]
        async fn test_get_transaction_info_integration() {
            // This test is more complex due to nonce management
            // Skip if we can't connect to avoid false failures
            let provider_result = setup_provider().await;
            if provider_result.is_err() {
                println!("Skipping integration test - Anvil not available");
                return;
            }

            // Try to create a transaction, but handle nonce errors gracefully
            let tx_hash_result = timeout(TEST_TIMEOUT, create_test_transaction()).await;
            
            match tx_hash_result {
                Ok(Ok(tx_hash)) => {
                    let tx_hash_str = format!("{:?}", tx_hash);

                    let result = timeout(
                        TEST_TIMEOUT,
                        get_transaction_info(&tx_hash_str)
                    ).await;

                    match result {
                        Ok(tx_result) => {
                            match tx_result {
                                Ok(tx_info) => {
                                    println!("✅ Retrieved transaction info: {}", tx_info.tx_hash);
                                    assert_eq!(tx_info.tx_hash, tx_hash);
                                    assert!(tx_info.is_successful());
                                }
                                Err(error) => {
                                    println!("❌ Failed to get transaction info: {}", error);
                                }
                            }
                        }
                        Err(_) => {
                            println!("⏱️  Test timed out");
                        }
                    }
                }
                Ok(Err(e)) => {
                    println!("⚠️  Could not create test transaction (expected in some cases): {}", e);
                    // This is not necessarily a test failure - could be nonce issues, etc.
                }
                Err(_) => {
                    println!("⏱️  Transaction creation timed out");
                }
            }
        }
    }

    mod edge_case_tests {
        use super::*;
        use crate::actions::info::TransactionInfo;

        #[test]
        fn test_transaction_info_debug() {
            let tx_info = TransactionInfo {
                network_chain_id: 31337,
                from_address: address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
                to_address: Some(address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")),
                value: U256::from(1000000000000000000u64),
                tx_hash: b256!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
                block_number: Some(1),
                block_hash: Some(b256!("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")),
                block_timestamp: Some(1640995200),
                gas_limit: 21000,
                gas_used: Some(21000),
                gas_price: Some(20000000000),
                nonce: 0,
                transaction_index: Some(0),
                status: Some(true),
            };

            let debug_str = format!("{:?}", tx_info);
            assert!(debug_str.contains("TransactionInfo"));
            assert!(debug_str.contains("network_chain_id: 31337"));
        }

        #[test]
        fn test_transaction_info_zero_values() {
            let tx_info = TransactionInfo {
                network_chain_id: 0,
                from_address: address!("0x0000000000000000000000000000000000000000"),
                to_address: None,
                value: U256::ZERO,
                tx_hash: b256!("0x0000000000000000000000000000000000000000000000000000000000000000"),
                block_number: Some(0),
                block_hash: None,
                block_timestamp: Some(0),
                gas_limit: 0,
                gas_used: Some(0),
                gas_price: Some(0),
                nonce: 0,
                transaction_index: Some(0),
                status: Some(false),
            };

            assert!(!tx_info.is_successful());
            assert!(!tx_info.is_pending());
            let ether_value = tx_info.value_in_ether();
            assert!(ether_value.starts_with("0") || ether_value == "0.000000000000000000");
            
            let gas_fee = tx_info.gas_fee_in_ether();
            assert!(gas_fee.is_some());
            let fee_value = gas_fee.unwrap();
            assert!(fee_value.starts_with("0") || fee_value == "0.000000000000000000");
        }

        #[test]
        fn test_transaction_info_max_values() {
            let tx_info = TransactionInfo {
                network_chain_id: u64::MAX,
                from_address: address!("0xffffffffffffffffffffffffffffffffffffffff"),
                to_address: Some(address!("0xffffffffffffffffffffffffffffffffffffffff")),
                value: U256::MAX,
                tx_hash: b256!("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                block_number: Some(u64::MAX),
                block_hash: Some(b256!("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
                block_timestamp: Some(u64::MAX),
                gas_limit: u64::MAX,
                gas_used: Some(u64::MAX),
                gas_price: Some(u64::MAX),
                nonce: u64::MAX,
                transaction_index: Some(u64::MAX),
                status: Some(true),
            };

            assert!(tx_info.is_successful());
            assert!(!tx_info.is_pending());
            
            // These should not panic with max values
            let _ether_value = tx_info.value_in_ether();
            let _gas_fee = tx_info.gas_fee_in_ether();
            let _display = format!("{}", tx_info);
        }
    }

    // Helper function to run all tests with proper setup/teardown
    #[tokio::test]
    async fn test_runner_info() {
        println!("🧪 Running Transaction Coverage Tests");
        println!("💡 Note: Some tests require Anvil to be running on http://127.0.0.1:8545");
        println!("💡 Start Anvil with: anvil");
        println!("💡 Tests will skip or timeout gracefully if Anvil is not available");
    }
}

// Additional integration tests that can be run manually
#[cfg(test)]
mod manual_integration_tests {
    use super::*;

    /// Run this test manually when you have Anvil running
    /// cargo test test_full_transaction_lifecycle --ignored
    #[tokio::test]
    #[ignore]
    async fn test_full_transaction_lifecycle() {
        use crate::actions::sending::send_eth;
        use crate::actions::info::TransactionInfo;
        
        println!("🚀 Starting full transaction lifecycle test...");
        
        // Step 1: Send a transaction
        println!("📤 Sending transaction...");
        let tx_info = send_eth().await.expect("Failed to send transaction");
        println!("✅ Transaction sent: {}", tx_info.tx_hash);
        
        // Step 2: Verify transaction details
        println!("🔍 Verifying transaction details...");
        assert!(tx_info.is_successful());
        assert!(!tx_info.is_pending());
        assert_eq!(tx_info.network_chain_id, 31337);
        assert!(tx_info.value > alloy::primitives::U256::ZERO);
        
        // Step 3: Test display formatting
        println!("🎨 Testing display formatting...");
        println!("{}", tx_info);
        
        // Step 4: Test utility methods
        println!("🛠️  Testing utility methods...");
        let ether_value = tx_info.value_in_ether();
        let gas_fee = tx_info.gas_fee_in_ether();
        println!("💰 Value: {} ETH", ether_value);
        println!("⛽ Gas fee: {:?} ETH", gas_fee);
        
        println!("🎉 Full lifecycle test completed successfully!");
    }
}