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