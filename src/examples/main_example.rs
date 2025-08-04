use alloy::{
    contract::{ContractInstance, Interface},
    dyn_abi::DynSolValue,
    network::{Ethereum, EthereumWallet},
    primitives::{Address, Bytes, U256, hex},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolConstructor },


};
use alloy_json_abi::{Function, JsonAbi};

use alloy_sol_types::{sol_data::*, SolType, SolValue, SolCall};

use anyhow::Result;
use std::sync::Arc;
use std::str::FromStr;
use alloy::transports::http::reqwest::Url;




use crate::config::*;
use crate::model::interaction::*;
use crate::contract::contract_builder::*;
use crate::contract::contract_factory::*;


sol!(
    contract SimpleStorage {
        uint256 public storedValue;
        address public owner;
        
        event ValueChanged(uint256 oldValue, uint256 newValue);
        event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
        
        modifier onlyOwner() {
            require(msg.sender == owner, "Not the owner");
            _;
        }
        
        constructor(uint256 _initialValue) {
            storedValue = _initialValue;
            owner = msg.sender;
        }
        
        function setValue(uint256 _newValue) public onlyOwner {
            uint256 oldValue = storedValue;
            storedValue = _newValue;
            emit ValueChanged(oldValue, _newValue);
        }
        
        function getValue() public view returns (uint256) {
            return storedValue;
        }
        
        function transferOwnership(address _newOwner) public onlyOwner {
            require(_newOwner != address(0), "Invalid address");
            address oldOwner = owner;
            owner = _newOwner;
            emit OwnershipTransferred(oldOwner, _newOwner);
        }
    }
);



pub async fn example_deployment_and_interaction() -> Result<()> {

    fn get_simple_storage_abi() -> Interface {
        // ABI simulé
        let abi_json =r#"[{"inputs":[{"internalType":"uint256","name":"_initialValue","type":"uint256"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"oldValue","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"newValue","type":"uint256"}],"name":"ValueChanged","type":"event"},{"inputs":[],"name":"getValue","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"_newValue","type":"uint256"}],"name":"setValue","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"storedValue","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"}]"#;
        let json_abi: JsonAbi = serde_json::from_str(abi_json).unwrap();
        Interface::new(json_abi)
    }

    println!("Deploy with Contract Builder and interact with it");

    let private_key: PrivateKeySigner = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    .parse().unwrap();
    let credentials = UserCredentials::new(private_key);

    let config = Config::load().unwrap();

    let provider = Arc::new(ProviderBuilder::new().connect_http(config.rpc_url.parse::<Url>().unwrap()));

    let bytecode =  Bytes::from(hex::decode("6080604052348015600e575f5ffd5b506040516107063803806107068339818101604052810190602e919060ab565b805f819055503360015f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505060d1565b5f5ffd5b5f819050919050565b608d81607d565b81146096575f5ffd5b50565b5f8151905060a5816086565b92915050565b5f6020828403121560bd5760bc6079565b5b5f60c8848285016099565b91505092915050565b610628806100de5f395ff3fe608060405234801561000f575f5ffd5b5060043610610055575f3560e01c8063209652551461005957806355241077146100775780636d619daa146100935780638da5cb5b146100b1578063f2fde38b146100cf575b5f5ffd5b6100616100eb565b60405161006e91906103cc565b60405180910390f35b610091600480360381019061008c9190610413565b6100f3565b005b61009b6101ca565b6040516100a891906103cc565b60405180910390f35b6100b96101cf565b6040516100c6919061047d565b60405180910390f35b6100e960048036038101906100e491906104c0565b6101f4565b005b5f5f54905090565b60015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610182576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161017990610545565b60405180910390fd5b5f5f549050815f819055507f2db947ef788961acc438340dbcb4e242f80d026b621b7c98ee3061995039038281836040516101be929190610563565b60405180910390a15050565b5f5481565b60015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610283576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161027a90610545565b60405180910390fd5b5f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16036102f1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102e8906105d4565b60405180910390fd5b5f60015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690508160015f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b5f819050919050565b6103c6816103b4565b82525050565b5f6020820190506103df5f8301846103bd565b92915050565b5f5ffd5b6103f2816103b4565b81146103fc575f5ffd5b50565b5f8135905061040d816103e9565b92915050565b5f60208284031215610428576104276103e5565b5b5f610435848285016103ff565b91505092915050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6104678261043e565b9050919050565b6104778161045d565b82525050565b5f6020820190506104905f83018461046e565b92915050565b61049f8161045d565b81146104a9575f5ffd5b50565b5f813590506104ba81610496565b92915050565b5f602082840312156104d5576104d46103e5565b5b5f6104e2848285016104ac565b91505092915050565b5f82825260208201905092915050565b7f4e6f7420746865206f776e6572000000000000000000000000000000000000005f82015250565b5f61052f600d836104eb565b915061053a826104fb565b602082019050919050565b5f6020820190508181035f83015261055c81610523565b9050919050565b5f6040820190506105765f8301856103bd565b61058360208301846103bd565b9392505050565b7f496e76616c6964206164647265737300000000000000000000000000000000005f82015250565b5f6105be600f836104eb565b91506105c98261058a565b602082019050919050565b5f6020820190508181035f8301526105eb816105b2565b905091905056fea2646970667358221220c5d1d392d0335366820f5bcacb60ef4af59c76e32908e507da3bb050afcf440b64736f6c634300081e0033").unwrap());

    let constructor_args = SimpleStorage::constructorCall {
        _initialValue: U256::from(42),
    }.abi_encode();

    let builder = ContractBuilder::<String, _, Ethereum>::new(provider.clone())
    .with_bytecode(bytecode)
    .with_constructor_args(constructor_args.into())
    .with_credentials(credentials.clone())
    .with_execution_mode(ExecutionMode::TraceAndExecute);

    let deploy_result = builder.deploy().await;


    match deploy_result {
        RequestResult { 
            success: true, 
            data: Some(deployed),
            trace_info: Some(trace),
            transaction_hash: Some(tx_hash),
            .. 
        } => {
            println!("✅ Contract deployed successfully!");
            println!("  📍 Address: {}", deployed.address());
            println!("  📝 Transaction: {}", tx_hash);
            println!("  ⛽ Gas used: {}", trace.gas_used);
            println!("  📊 Trace calls: {}", trace.calls.len());
            
            let instance = deployed.instance(get_simple_storage_abi());
            
            let set_value_data = SimpleStorage::setValueCall {
                _newValue: U256::from(100),
            }.abi_encode();
            
            let interaction_result = instance.call_function(
                "setValue",
                set_value_data.into(),
                credentials,
                None,
                ExecutionMode::Direct,
            ).await;
            
            match interaction_result {
                RequestResult { success: true, data: Some(data), .. } => {
                    println!("\n✅ setValue executed successfully!");
                    println!("  ⛽ Gas used: {}", data.gas_used);
                }
                _ => println!("❌ setValue failed"),
            }
        }
        RequestResult { success: false, error: Some(e), .. } => {
            println!("❌ Deployment failed: {}", e);
        }
        _ => {}
    }
    
    Ok(())


}


// More simpler apporch with the ContractFactory 
// More example needed here 


sol!(
    contract ERC20Token {
        function name() public view returns (string);
        function symbol() public view returns (string);
        function decimals() public view returns (uint8);
        function totalSupply() public view returns (uint256);
        function balanceOf(address account) public view returns (uint256);
    }
);

sol!(PoolFactory, "contract/aaam_factory/build/PoolFactory.json");


pub async fn example_aam_factory_deploy_and_interact() -> Result<()> {
    println!("🚀 Starting AMM Factory deployment example...\n");

    // Utility function to read contract binary
    fn read_contract_bin<P: AsRef<std::path::Path>>(path: P) -> Result<Bytes> {
        let hex_str = std::fs::read_to_string(path)?.trim().to_string();
        let bytes = hex::decode(hex_str).map_err(|_| anyhow::anyhow!("Failed to decode hex string"))?;
        Ok(bytes.into())
    }

    // Utility function to load ABI from JSON file
    fn get_abi_from_json(path: &str) -> Interface {
        let json_str = std::fs::read_to_string(path).unwrap();
        let json_abi: JsonAbi = serde_json::from_str(&json_str).unwrap();
        Interface::new(json_abi)
    }

    // Setup
    let private_key: PrivateKeySigner = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        .parse().unwrap();
    let credentials = UserCredentials::new(private_key);
    let config = Config::load().unwrap();
    let provider = Arc::new(ProviderBuilder::new().connect_http(config.rpc_url.parse::<Url>().unwrap()));

    // ========== STEP 1: Deploy BNB Token ==========
    println!("📦 Step 1: Deploying BNB Token...");
    
    let bnb_bytecode = read_contract_bin("contract/aaam_factory/build/BNB.bin").unwrap_or_else(|_| panic!("Failed to read BNB bytecode"));
    let bnb_builder = ContractBuilder::<String, _, Ethereum>::new(provider.clone())
        .with_bytecode(bnb_bytecode)
        .with_credentials(credentials.clone())
        .with_execution_mode(ExecutionMode::Direct)
        .with_constructor_args(Bytes::from(vec![0u8; 32]));
    
    let bnb_deploy_result = bnb_builder.deploy().await;
    
    let bnb_address = match bnb_deploy_result {
        RequestResult { 
            success: true, 
            data: Some(deployed),
            transaction_hash: Some(tx_hash),
            .. 
        } => {
            println!("✅ BNB Token deployed successfully!");
            println!("  📍 Address: {}", deployed.address());
            println!("  📝 Transaction: {}", tx_hash);
            deployed.address()
        }
        RequestResult { success: false, error: Some(e), .. } => {
            println!("❌ BNB deployment failed: {}", e);
            return Err(anyhow::anyhow!("BNB deployment failed"));
        }
        _ => return Err(anyhow::anyhow!("Unexpected BNB deployment result")),
    };

    // ========== STEP 2: Deploy ChainLink Token ==========
    println!("\n📦 Step 2: Deploying ChainLink Token...");
    
    let link_bytecode = read_contract_bin("contract/aaam_factory/build/ChainLink.bin").unwrap_or_else(|_| panic!("Failed to read ChainLink bytecode"));
    let link_builder = ContractBuilder::<String, _, Ethereum>::new(provider.clone())
        .with_bytecode(link_bytecode)
        .with_credentials(credentials.clone())
        .with_execution_mode(ExecutionMode::Direct)
        .with_constructor_args(Bytes::from(vec![0u8; 32]));


    
    let link_deploy_result = link_builder.deploy().await;
    
    let link_address = match link_deploy_result {
        RequestResult { 
            success: true, 
            data: Some(deployed),
            transaction_hash: Some(tx_hash),
            .. 
        } => {
            println!("✅ ChainLink Token deployed successfully!");
            println!("  📍 Address: {}", deployed.address());
            println!("  📝 Transaction: {}", tx_hash);
            deployed.address()
        }
        RequestResult { success: false, error: Some(e), .. } => {
            println!("❌ ChainLink deployment failed: {}", e);
            return Err(anyhow::anyhow!("ChainLink deployment failed"));
        }
        _ => return Err(anyhow::anyhow!("Unexpected ChainLink deployment result")),
    };

    // Verify token deployments by checking their symbols
    println!("\n🔍 Verifying token deployments...");
    
    // You can add verification calls here using the token ABIs if needed
    
    // ========== STEP 3: Deploy Pool Factory ==========
    println!("\n📦 Step 3: Deploying Pool Factory...");
    
    let factory_bytecode = read_contract_bin("contract/aaam_factory/build/PoolFactory.bin")?;
    let factory_builder = ContractBuilder::<String, _, Ethereum>::new(provider.clone())
        .with_bytecode(factory_bytecode)
        .with_credentials(credentials.clone())
        .with_execution_mode(ExecutionMode::Direct);
  
    
    let factory_deploy_result = factory_builder.deploy().await;
    
    let factory_contract = match factory_deploy_result {
        RequestResult { 
            success: true, 
            data: Some(deployed),
            transaction_hash: Some(tx_hash),
            .. 
        } => {
            println!("✅ Pool Factory deployed successfully!");
            println!("  📍 Address: {}", deployed.address());
            println!("  📝 Transaction: {}", tx_hash);
            deployed
        }
        RequestResult { success: false, error: Some(e), .. } => {
            println!("❌ Factory deployment failed: {}", e);
            return Err(anyhow::anyhow!("Factory deployment failed"));
        }
        _ => return Err(anyhow::anyhow!("Unexpected factory deployment result")),
    };

    // ========== STEP 4: Create Pool with Deployed Tokens ==========
    println!("\n📦 Step 4: Creating pool with deployed tokens...");
    
    // Ensure correct token ordering (token0 < token1)
    let (token0, token1) = if bnb_address < link_address {
        (bnb_address, link_address)
    } else {
        (link_address, bnb_address)
    };
    
    println!("  Token0: {} ({})", token0, if token0 == bnb_address { "BNB" } else { "LINK" });
    println!("  Token1: {} ({})", token1, if token1 == bnb_address { "BNB" } else { "LINK" });
    println!("  Fee: 3000 (0.3%)");
    
    // Load factory ABI and create instance
    let factory_interface = get_abi_from_json("contract/aaam_factory/build/PoolFactory.json");
    let factory_address = factory_contract.address(); // Save this first
    let factory_instance = factory_contract.instance(factory_interface);
    
    // Encode createPool call
    let create_pool_data = PoolFactory::createPoolCall {
        token0,
        token1,
        fee: 30 as u8, // 0.3% fee tier (common for most AMMs)
    }.abi_encode();
    
    // Execute createPool
    let pool_result = factory_instance.call_function(
        "createPool",
        create_pool_data.into(),
        credentials.clone(),
        None,
        ExecutionMode::Direct,
    ).await;
    
    match pool_result {
        RequestResult { 
            success: true, 
            data: Some(data), 
            transaction_hash: Some(tx_hash),
            .. 
        } => {
            println!("\n✅ Pool created successfully!");
            println!("  📝 Transaction: {}", tx_hash);
            println!("  ⛽ Gas used: {}", data.gas_used);
            
            // The pool address should be in the logs or we need to query it
            // Try to get pool address using getPool function if available
            println!("\n🔍 Retrieving pool address...");

            let token0 : Address = bnb_address;
            let token1 : Address = link_address;
            
            // Encode getPool call (if the factory has this function)
            let get_pool_selector = &alloy::primitives::keccak256("getPool(address,address,uint8)")[..4];
            let mut calldata = get_pool_selector.to_vec();
            calldata.extend_from_slice(&token0.as_slice());
            calldata.extend_from_slice(&token1.as_slice());
            let mut fee_bytes = [0u8; 32];
            fee_bytes[31] = 30;
            calldata.extend_from_slice(&fee_bytes); // 32 bytes
                
            // Try to call getPool
            match provider.call(
                alloy::rpc::types::TransactionRequest::default()
                    .to(factory_address)
                    .input(calldata.into()),
            ).await {
                Ok(result) if result.len() >= 32 => {
                    let pool_address = Address::from_slice(&result[12..32]);
                    if pool_address != Address::ZERO {
                        println!("  📍 Pool address: {}", pool_address);
                        println!("\n🎉 AMM Pool successfully created between BNB and ChainLink tokens!");
                    }
                }
                _ => {
                    println!("  ⚠️ Could not retrieve pool address (might need to check logs)");
                }
            }
        }
        RequestResult { success: false, error: Some(e), .. } => {
            println!("\n❌ Pool creation failed: {}", e);
            
            // Common issues and solutions
            println!("\n💡 Troubleshooting tips:");
            println!("  - Ensure the fee tier (3000) is supported by the factory");
            println!("  - Check if a pool already exists for this token pair");
            println!("  - Verify token addresses are valid ERC20 contracts");
            println!("  - Ensure tokens are properly ordered (token0 < token1)");
        }
        _ => println!("\n❌ Pool creation failed with unknown error"),
    }
    
    println!("\n✨ Deployment summary:");
    println!("  BNB Token:     {}", bnb_address);
    println!("  ChainLink Token: {}", link_address);
    println!("  Pool Factory:  {}", factory_address);
    
    Ok(())
}