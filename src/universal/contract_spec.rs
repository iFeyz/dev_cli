use alloy::{contract::Interface, primitives::{Address, Bytes, U256}};
use serde::{Serialize, Deserialize};
use alloy_json_abi::JsonAbi;

#[derive(Debug, Clone)]
pub struct DeploymentConfig {
    pub gas_limit: U256,
    pub gas_price: U256,
    pub dependencies: Vec<String>,
    pub constructor_params: Vec<ConstructorParam>,
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            gas_limit: U256::from(300_000_00),
            gas_price: U256::from(20_000_000_000u64),
            dependencies: vec![],
            constructor_params: vec![],
        }
    }
}

//TODO TRY MAKE PRIVATE FIELDS WHEN GETTER AND SETTER FULLY IMPLEMENTED
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructorParam {
    pub name: String,
    pub param_type: String,
    pub value: serde_json::Value,
}
// Getters
pub trait ContractSpec {
    fn get_name(&self) -> &str;
    fn get_abi(&self) -> &Interface;
    fn get_bytecode(&self) -> &Bytes;
    fn get_constructor_args(&self) -> Option<Bytes>;
    fn get_deployment_config(&self) -> &DeploymentConfig;    
}

#[derive(Debug, Clone)]
pub struct ContractGeneric {
    pub name: String,
    pub abi: Interface,
    pub bytecode: Bytes,
    pub constructor_args: Option<Bytes>,
    pub config: DeploymentConfig,
}
// Impl of getters for generic type contract
impl ContractSpec for ContractGeneric {
    
    fn get_name(&self) -> &str { &self.name }
    fn get_abi(&self) -> &Interface { &self.abi }
    fn get_bytecode(&self) -> &Bytes { &self.bytecode }
    fn get_constructor_args(&self) -> Option<Bytes> { self.constructor_args.clone() }
    fn get_deployment_config(&self) -> &DeploymentConfig { &self.config }
}

