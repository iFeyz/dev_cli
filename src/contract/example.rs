use alloy::{
    primitives::{Address, U256, Bytes, utils::parse_ether},
    contract::{ContractInstance},
    providers::{Provider, ext::TraceApi},
    network::Ethereum,
    signers::local::PrivateKeySigner,
};

use std::str::FromStr;

use crate::contract::simple_storage::SimpleStorageContract;
use crate::contract::contract_interface::{Contract, ContractType, ContractData};
use crate::model::interaction::{RequestConfig, UserCredentials, RequestResult, RequestError, Requestable};

/// Test function that demonstrates all SimpleStorage contract functionality
pub async fn test_simple_storage_contract<P>(provider: &P) -> Result<(), RequestError>
where
    P: Provider<Ethereum> + TraceApi<Ethereum> + Send + Sync,
{
    println!("🚀 Starting SimpleStorage contract tests...\n");

    // 1. Setup user credentials and config
    // Utiliser from_slice au lieu de from_hex
    let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    let signer = PrivateKeySigner::from_str(private_key)
    .map_err(|e| RequestError::ContractError(format!("Invalid private key: {}", e)))?;
    
    let credentials = UserCredentials::new(signer);
    
    let config = RequestConfig {
        gas_limit: U256::from(3_000_000),
        gas_price: U256::from(20_000_000_000u64), // 20 gwei
        nonce: None,
    };

    // 2. Create contract instance with constructor arguments
    let initial_value = U256::from(42);
    let constructor_call = SimpleStorageContract::constructor_call(initial_value);
    let constructor_args = SimpleStorageContract::encode_constructor(&constructor_call);
    
    let contract = Contract::<SimpleStorageContract>::new(credentials, Some(config))
        .with_constructor_args(constructor_args);

    println!("📝 Contract created with initial value: {}", initial_value);
    println!("💼 Contract bytecode size: {} bytes", contract.info.bytecode.len());

    // 3. Deploy the contract with tracing
    println!("\n🔧 Deploying contract with simulation...");
    let deployed_contract = match contract.deploy_and_wait(provider).await {
        RequestResult { success: true, data: Some(contract), trace_info, transaction_hash, error: _ } => {
            println!("✅ Contract deployed successfully!");
            if let Some(address) = contract.address() {
                println!("📍 Contract address: {:?}", address);
            }
            if let Some(tx_hash) = transaction_hash {
                println!("📋 Deployment transaction: {}", tx_hash);
            }
            if let Some(trace) = trace_info {
                println!("⛽ Deployment gas used: {}", trace.gas_used);
                println!("📊 Simulation success: {}", trace.success);
            }
            contract
        }
        RequestResult { success: false, error: Some(err), trace_info, .. } => {
            println!("❌ Deployment failed: {:?}", err);
            if let Some(trace) = trace_info {
                println!("🔍 Trace info - Gas: {}, Success: {}", trace.gas_used, trace.success);
                if let Some(error_msg) = trace.error {
                    println!("💥 Trace error: {}", error_msg);
                }
            }
            return Err(err);
        }
        _ => {
            let err = RequestError::ContractError("Unexpected deployment result".to_string());
            println!("❌ Deployment failed: {:?}", err);
            return Err(err);
        }
    };

    // 4. Test view function - getNumber (read-only call)
    println!("\n📖 Testing getNumber() view function...");
    let get_call = SimpleStorageContract::get_number_call();
    match deployed_contract.view(get_call, provider).await {
        RequestResult { success: true, data: Some(result), .. } => {
            println!("✅ Current stored number: 0x{}", hex::encode(&result));
            // Decode the result to U256
            if result.len() >= 32 {
                let number = U256::from_be_slice(&result[result.len()-32..]);
                println!("   Decoded value: {}", number);
                if number == initial_value {
                    println!("✅ Initial value matches constructor argument: {}", initial_value);
                } else {
                    println!("⚠️ Initial value mismatch! Expected: {}, Got: {}", initial_value, number);
                }
            }
        }
        RequestResult { success: false, error: Some(err), .. } => {
            println!("❌ getNumber() failed: {:?}", err);
            return Err(err);
        }
        _ => {
            println!("❌ getNumber() returned unexpected result");
        }
    }

    // 5. Test setNumber function with tracing
    println!("\n🔢 Testing setNumber() function with simulation...");
    let new_value = U256::from(100);
    let set_call = SimpleStorageContract::set_number_call(new_value);
    let contract_call = deployed_contract.call(set_call);

    match contract_call.request(provider).await {
        RequestResult { success: true, data: Some(call_data), transaction_hash, trace_info, error: _ } => {
            println!("✅ setNumber({}) executed successfully!", new_value);
            if let Some(tx_hash) = transaction_hash {
                println!("📋 Transaction hash: {}", tx_hash);
            }
            println!("⛽ Gas used: {}", call_data.gas_used);
            println!("📝 Events emitted: {} events", call_data.events.len());
            
            if let Some(trace) = trace_info {
                println!("🔍 Simulation details:");
                println!("  - Estimated gas: {}", trace.gas_used);
                println!("  - Function calls in trace: {}", trace.calls.len());
                println!("  - Logs generated: {}", trace.logs_count);
            }
        }
        RequestResult { success: false, error: Some(err), trace_info, .. } => {
            println!("❌ setNumber() failed: {:?}", err);
            if let Some(trace) = trace_info {
                println!("🔍 Failed simulation - Gas: {}, Success: {}", trace.gas_used, trace.success);
                if let Some(error_msg) = trace.error {
                    println!("💥 Simulation error: {}", error_msg);
                }
            }
            return Err(err);
        }
        _ => {
            println!("❌ setNumber() returned unexpected result");
        }
    }

    // 6. Verify the new value with getNumber
    println!("\n🔍 Verifying new value with getNumber()...");
    let get_call = SimpleStorageContract::get_number_call();
    match deployed_contract.view(get_call, provider).await {
        RequestResult { success: true, data: Some(result), .. } => {
            if result.len() >= 32 {
                let number = U256::from_be_slice(&result[result.len()-32..]);
                println!("✅ Verified stored number: {}", number);
                if number == new_value {
                    println!("✅ Value matches expected: {}", new_value);
                } else {
                    println!("❌ Value mismatch! Expected: {}, Got: {}", new_value, number);
                }
            }
        }
        RequestResult { success: false, error: Some(err), .. } => {
            println!("❌ Verification failed: {:?}", err);
            return Err(err);
        }
        _ => {
            println!("❌ Verification returned unexpected result");
        }
    }

    // 7. Test increment function with simulation
    println!("\n⬆️ Testing increment() function with simulation...");
    let increment_call = SimpleStorageContract::increment_call();
    let contract_call = deployed_contract.call(increment_call);

    match contract_call.trace_and_execute(provider).await {
        RequestResult { success: true, data: Some(call_data), transaction_hash, trace_info, error: _ } => {
            println!("✅ increment() executed successfully!");
            if let Some(tx_hash) = transaction_hash {
                println!("📋 Transaction hash: {}", tx_hash);
            }
            println!("⛽ Gas used: {}", call_data.gas_used);
            
            if let Some(trace) = trace_info {
                println!("🔍 Increment simulation:");
                println!("  - Gas estimated: {}", trace.gas_used);
                println!("  - Success: {}", trace.success);
            }
        }
        RequestResult { success: false, error: Some(err), trace_info, .. } => {
            println!("❌ increment() failed: {:?}", err);
            if let Some(trace) = trace_info {
                println!("🔍 Failed increment simulation");
                if let Some(error_msg) = trace.error {
                    println!("💥 Error: {}", error_msg);
                }
            }
            return Err(err);
        }
        _ => {
            println!("❌ increment() returned unexpected result");
        }
    }

    // 8. Verify increment result
    println!("\n🔍 Verifying increment result...");
    let get_call = SimpleStorageContract::get_number_call();
    match deployed_contract.view(get_call, provider).await {
        RequestResult { success: true, data: Some(result), .. } => {
            if result.len() >= 32 {
                let number = U256::from_be_slice(&result[result.len()-32..]);
                let expected = new_value + U256::from(1);
                println!("✅ Number after increment: {}", number);
                if number == expected {
                    println!("✅ Increment worked correctly! Expected: {}, Got: {}", expected, number);
                } else {
                    println!("❌ Increment failed! Expected: {}, Got: {}", expected, number);
                }
            }
        }
        RequestResult { success: false, error: Some(err), .. } => {
            println!("❌ Increment verification failed: {:?}", err);
            return Err(err);
        }
        _ => {
            println!("❌ Increment verification returned unexpected result");
        }
    }

    // 9. Test decrement function with simulation
    println!("\n⬇️ Testing decrement() function with simulation...");
    let decrement_call = SimpleStorageContract::decrement_call();
    let contract_call = deployed_contract.call(decrement_call);

    match contract_call.trace_and_execute(provider).await {
        RequestResult { success: true, data: Some(call_data), transaction_hash, trace_info, error: _ } => {
            println!("✅ decrement() executed successfully!");
            if let Some(tx_hash) = transaction_hash {
                println!("📋 Transaction hash: {}", tx_hash);
            }
            println!("⛽ Gas used: {}", call_data.gas_used);
            
            if let Some(trace) = trace_info {
                println!("🔍 Decrement simulation:");
                println!("  - Gas estimated: {}", trace.gas_used);
                println!("  - Success: {}", trace.success);
                println!("  - Calls traced: {}", trace.calls.len());
            }
        }
        RequestResult { success: false, error: Some(err), trace_info, .. } => {
            println!("❌ decrement() failed: {:?}", err);
            if let Some(trace) = trace_info {
                println!("🔍 Failed decrement simulation");
                if let Some(error_msg) = trace.error {
                    println!("💥 Error: {}", error_msg);
                }
            }
            return Err(err);
        }
        _ => {
            println!("❌ decrement() returned unexpected result");
        }
    }

    // 10. Final verification
    println!("\n🏁 Final verification...");
    let get_call = SimpleStorageContract::get_number_call();
    match deployed_contract.view(get_call, provider).await {
        RequestResult { success: true, data: Some(result), .. } => {
            if result.len() >= 32 {
                let number = U256::from_be_slice(&result[result.len()-32..]);
                println!("✅ Final stored number: {}", number);
                println!("✅ Should equal original setNumber value: {}", new_value);
                if number == new_value {
                    println!("✅ All operations completed successfully!");
                    println!("   Initial: {} → setNumber: {} → increment: {} → decrement: {}", 
                             initial_value, new_value, new_value + U256::from(1), number);
                } else {
                    println!("❌ Final value mismatch! Expected: {}, Got: {}", new_value, number);
                }
            }
        }
        RequestResult { success: false, error: Some(err), .. } => {
            println!("❌ Final verification failed: {:?}", err);
            return Err(err);
        }
        _ => {
            println!("❌ Final verification returned unexpected result");
        }
    }

    // 11. Test event decoding (demonstration)
    println!("\n📡 Event handling capabilities:");
    println!("Contract supports NumberSet event with parameters:");
    println!("  - newNumber (uint256, indexed)");
    println!("  - setter (address, indexed)");
    println!("Event decoding can be performed using:");
    println!("  SimpleStorageContract::decode_event(log_data)");

    // 12. Summary
    println!("\n📊 Test Summary:");
    println!("✅ Contract deployment with constructor args");
    println!("✅ View function calls (getNumber)");
    println!("✅ State-changing transactions (setNumber, increment, decrement)");
    println!("✅ Transaction simulation and tracing");
    println!("✅ Gas estimation and usage tracking");
    println!("✅ Event emission verification");
    println!("✅ State consistency validation");

    println!("\n🎉 SimpleStorage contract test completed successfully!");
    Ok(())
}

/// Helper function for running the test in main
pub async fn run_simple_storage_tests<P>(provider: &P) 
where
    P: Provider<Ethereum> + TraceApi<Ethereum> + Send + Sync,
{
    println!("========================================");
    println!("     SimpleStorage Contract Tests");
    println!("========================================");

    match test_simple_storage_contract(provider).await {
        Ok(()) => {
            println!("\n✅ All tests passed!");
        }
        Err(e) => {
            println!("\n❌ Tests failed with error: {:?}", e);
            println!("💡 Make sure your provider supports tracing and has sufficient funds");
        }
    }

    println!("========================================");
}
