use alloy::{
    contract::Interface,
    network::{Network, Ethereum},
    primitives::{Address, Bytes, U256},
    providers::Provider,
};
use anyhow::Result;
use alloy_json_abi::{Function, JsonAbi};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::marker::PhantomData;

use crate::model::interaction::*;
use crate::contract::contract_builder::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct ContractArtifact {
    pub abi: serde_json::Value,
    pub bytecode: String,
    pub deployed_bytecode: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

impl ContractArtifact {

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }

    pub fn bytecode_bytes(&self) -> Result<Bytes> {
        let bytecode = self.bytecode.trim_start_matches("0x");
        Ok(Bytes::from(hex::decode(bytecode)?))
    }

    pub fn interface(&self) -> Result<Interface> {
        let abi_str = serde_json::to_string(&self.abi)?;
        Ok(Interface::new(JsonAbi::from_json_str(&abi_str)?))
    }
}

pub struct ContractFactory<P, N>
where
    P: Provider<N>,
    N: Network,
{
    provider: Arc<P>,
    artifact: ContractArtifact,
    credentials: Option<UserCredentials>,
    config: RequestConfig,
    execution_mode: ExecutionMode,
    _phantom: PhantomData<N>,
}

impl<P, N> ContractFactory<P, N>
where
    P: Provider<N> + Clone,
    N: Network,
{

    pub fn new(provider: Arc<P>, artifact: ContractArtifact) -> Self {
        Self { 
            provider, 
            artifact,
            credentials: None,
            config: RequestConfig::default(),
            execution_mode: ExecutionMode::Direct,
            _phantom: PhantomData,
        }
    }

    pub fn from_artifact_file<Pa: AsRef<Path>>(
        provider: P,
        path: Pa,
    ) -> Result<Self> {
        let artifact = ContractArtifact::from_file(path)?;
        Ok(Self::new(Arc::new(provider), artifact))
    }

    pub fn with_credentials(mut self, credentials: UserCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    pub fn with_config(mut self, config: RequestConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_execution_mode(mut self, mode: ExecutionMode) -> Self {
        self.execution_mode = mode;
        self
    }

    pub async fn deploy(&self, constructor_args: Option<Bytes>) -> RequestResult<DeployedContractInfo> {
        let credentials = match &self.credentials {
            Some(c) => c.clone(),
            None => return RequestResult::error(
                RequestError::SigningError("Credentials not set".to_string())
            ),
        };

        let bytecode = match self.artifact.bytecode_bytes() {
            Ok(b) => b,
            Err(e) => return RequestResult::error(
                RequestError::ContractError(format!("Failed to parse bytecode: {}", e))
            ),
        };

        let builder = ContractBuilder::<(), P, N>::new(self.provider.clone())
            .with_bytecode(bytecode)
            .with_credentials(credentials)
            .with_config(self.config.clone())
            .with_execution_mode(self.execution_mode);

        let builder = if let Some(args) = constructor_args {
            builder.with_constructor_args(args)
        } else {
            builder
        };

        let result = builder.deploy().await;

        match result {
            RequestResult { 
                success: true, 
                data: Some(deployed),
                transaction_hash: Some(tx_hash),
                trace_info,
                .. 
            } => {
                let info = DeployedContractInfo {
                    address: deployed.address,
                    transaction_hash: tx_hash.clone(),
                    gas_used: trace_info.as_ref()
                        .map(|t| t.gas_used)
                        .unwrap_or(U256::ZERO),
                    trace_info: trace_info.clone(),
                };
                
                RequestResult::success(info, Some(tx_hash), trace_info)
            }
            RequestResult { success: false, error, trace_info, .. } => {
                RequestResult { success: false, error, data: None, transaction_hash: None, trace_info }
            }
            _ => unreachable!(),
        }
    }

    pub fn at(&self, address: Address) -> Result<ContractInstanceWrapper<P, N>> {
        let interface = self.artifact.interface()?;
        Ok(ContractInstanceWrapper {
            inner: alloy::contract::ContractInstance::new(
                address,
                self.provider.clone(),
                interface.clone(),
            ),
            address: address.clone(),
            provider: self.provider.clone(),
        })
    }

    pub async fn deploy_and_instance(
        &self,
        constructor_args: Option<Bytes>,
    ) -> RequestResult<(DeployedContractInfo, ContractInstanceWrapper<P, N>)> {
        let deploy_result = self.deploy(constructor_args).await;
        
        match deploy_result {
            RequestResult { success: true, data: Some(info), transaction_hash, trace_info, .. } => {
                match self.at(info.address) {
                    Ok(instance) => {
                        RequestResult::success((info, instance), transaction_hash, trace_info)
                    }
                    Err(e) => RequestResult::error(
                        RequestError::ContractError(format!("Failed to create instance: {}", e))
                    ),
                }
            }
            RequestResult { success: false, error, trace_info, .. } => {
                RequestResult { success: false, error, data: None, transaction_hash: None, trace_info }
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeployedContractInfo {
    pub address: Address,
    pub transaction_hash: String,
    pub gas_used: U256,
    pub trace_info: Option<TraceInfo>,
}

pub mod network_factories {
    use super::*;
    use alloy::network::Ethereum;

    pub fn ethereum_factory<P>(provider: Arc<P>, artifact: ContractArtifact) -> ContractFactory<P, Ethereum>
    where
        P: Provider<Ethereum> + Clone,
    {
        ContractFactory::new(provider, artifact)
            .with_config(RequestConfig {
                gas_limit: U256::from(3_000_000),
                gas_price: U256::from(30_000_000_000u64), // 30 Gwei
                nonce: None,
            })
    }

    // TODO ADD ALL THE OTHER NETWORKS
}






