use alloy::{
    primitives::{Address, U256, Bytes, FixedBytes, LogData, B256},
    signers::local::PrivateKeySigner,
    rpc::types::TransactionRequest,
    providers::{Provider, ext::TraceApi},
    network::{Network, TransactionBuilder, Ethereum, ReceiptResponse},
    sol_types::{SolValue, SolCall, SolEvent},
};

use async_trait::async_trait;
use std::marker::PhantomData;
use std::collections::HashMap;

use crate::model::interaction::{RequestError, RequestResult, RequestConfig, UserCredentials, Requestable, TraceInfo};
use crate::contract::contract_deployer::{ContractDeployment, DeployedContract};

// Trait plus flexible - les types peuvent être n'importe quoi
pub trait ContractData : Send + Sync + 'static {
    type Calls : Send + Sync ;  // Pas de contrainte SolCall
    type Events : Send + Sync ; // Pas de contrainte SolEvent
    type ConstructorCall : Send + Sync ; // Pas de contrainte SolCall

    const NAME: &'static str;
    const BYTECODE : &'static [u8];
    const ABI : &'static str;
    
    // Méthodes pour encoder/décoder quand nécessaire
    fn encode_call(call: &Self::Calls) -> Bytes;
    fn decode_event(log_data: &LogData) -> Result<Self::Events, RequestError>;
    fn encode_constructor(constructor: &Self::ConstructorCall) -> Bytes;
}

pub trait ContractType: Send + Sync + 'static {
    type CallData: Send + Sync ;
    type EventData: Send + Sync ;
    
    fn contract_name() -> &'static str;
    fn bytecode() -> Bytes;
    fn abi() -> &'static str;
    fn encode_call_data(call: &Self::CallData) -> Bytes;
    fn decode_event_data(log_data: &LogData) -> Result<Self::EventData, RequestError>;
}

impl<T : ContractData> ContractType for T {
    type CallData = T::Calls;
    type EventData = T::Events;

    fn contract_name() -> &'static str {
        T::NAME
    }

    fn bytecode() -> Bytes {
        Bytes::from_static(T::BYTECODE)
    }
    
    fn abi() -> &'static str {
        T::ABI
    }
    
    fn encode_call_data(call: &Self::CallData) -> Bytes {
        T::encode_call(call)
    }
    
    fn decode_event_data(log_data: &LogData) -> Result<Self::EventData, RequestError> {
        T::decode_event(log_data)
    }
}

#[derive(Debug, Clone)]
pub struct ContractInfo {
    pub address: Option<Address>,
    pub bytecode: Bytes,
    pub deployed_bytecode: Option<Bytes>,
    pub abi: String,
    pub constructor_args: Option<Bytes>,
    pub deployment_tx: Option<String>,
    pub deployment_block: Option<u64>,
    pub creator: Option<Address>,
}

impl ContractInfo {
    pub fn new(bytecode: Bytes, abi: String) -> Self {
        Self {
            address: None,
            bytecode,
            deployed_bytecode: None,
            abi,
            constructor_args: None,
            deployment_tx: None,
            deployment_block: None,
            creator: None,
        }
    }

    pub fn with_constructor_args(mut self, args: Bytes) -> Self {
        self.constructor_args = Some(args);
        self
    }

    pub fn is_deployed(&self) -> bool {
        self.address.is_some()
    }

    pub fn get_deployment_bytecode(&self) -> Bytes {
        if let Some(args) = &self.constructor_args {
            let mut combined = self.bytecode.clone();
           // combined.extend_from_slice(&args);
            combined
        } else {
            self.bytecode.clone()
        }
    }
}

pub struct Contract<T: ContractType> {
    pub info: ContractInfo,
    pub config: RequestConfig,
    pub user_credentials: UserCredentials,
    _phantom: PhantomData<T>,
}

impl<T: ContractType> Clone for Contract<T> {
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            config: self.config.clone(),
            user_credentials: self.user_credentials.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<T: ContractType> Contract<T> {
    pub fn new(
        credentials: UserCredentials,
        config: Option<RequestConfig>,
    ) -> Self {
        let info = ContractInfo::new(T::bytecode(), T::abi().to_string());
        
        Self {
            info,
            config: config.unwrap_or_default(),
            user_credentials: credentials,
            _phantom: PhantomData,
        }
    }

    pub fn from_deployed(
        address: Address,
        credentials: UserCredentials,
        config: Option<RequestConfig>,
    ) -> Self {
        let mut info = ContractInfo::new(T::bytecode(), T::abi().to_string());
        info.address = Some(address);
        
        Self {
            info,
            config: config.unwrap_or_default(),
            user_credentials: credentials,
            _phantom: PhantomData,
        }
    }

    pub fn with_constructor_args(mut self, args: Bytes) -> Self {
        self.info = self.info.with_constructor_args(args);
        self
    }

    pub fn address(&self) -> Option<Address> {
        self.info.address
    }

    pub fn is_deployed(&self) -> bool {
        self.info.is_deployed()
    }

    pub fn call(&self, function_data: T::CallData) -> ContractCall<T> {
        ContractCall::new(self.clone(), function_data)
    }

    pub async fn view<P>(&self, function_data: T::CallData, provider: &P) -> RequestResult<Bytes>
    where 
        P: Provider<Ethereum> + Send + Sync,
    {
        let Some(address) = self.address() else {
            return RequestResult::error(RequestError::ContractError("Contract not deployed".to_string()));
        };

        let call_data = T::encode_call_data(&function_data);
        let tx_request = TransactionRequest::default()
            .with_to(address)
            .with_input(call_data);

        match provider.call(tx_request).await {
            Ok(result) => RequestResult::success(result, None, None),
            Err(e) => RequestResult::error(RequestError::ContractError(e.to_string())),
        }
    }

    pub fn decode_event(&self, log_data: &LogData) -> Result<T::EventData, RequestError> {
        T::decode_event_data(log_data)
    }
}

#[derive(Debug)]
pub struct ContractCallData {
    pub contract_address: Address,
    pub function_called: String,
    pub return_data: Bytes,
    pub gas_used: U256,
    pub events: Vec<Bytes>,
}

#[derive(Clone)]
pub struct ContractCall<T: ContractType> {
    pub contract: Contract<T>,
    pub function_data: T::CallData,
    pub value: U256,
}

impl<T: ContractType> ContractCall<T> {
    pub fn new(contract: Contract<T>, function_data: T::CallData) -> Self {
        Self {
            contract,
            function_data,
            value: U256::ZERO,
        }
    }

    pub fn with_value(mut self, value: U256) -> Self {
        self.value = value;
        self
    }

    pub fn function_name(&self) -> String {
        let encoded = T::encode_call_data(&self.function_data);
        format!("0x{}", hex::encode(&encoded[0..4]))
    }
}

#[async_trait]
impl<T: ContractType> Requestable<ContractCallData> for ContractCall<T> {
    fn build_transaction_request(&self) -> TransactionRequest {
        let address = self.contract.address()
            .expect("Contract must be deployed before calling functions");
        
        TransactionRequest::default()
            .with_from(self.contract.user_credentials.address())
            .with_to(address)
            .with_value(self.value)
            .with_input(T::encode_call_data(&self.function_data))
            .with_gas_limit(self.contract.config.gas_limit.to::<u64>())
            .with_gas_price(self.contract.config.gas_price.to::<u128>())
    }

    async fn request<P>(&self, provider: &P) -> RequestResult<ContractCallData>
    where
        P: Provider<Ethereum> + TraceApi<Ethereum> + Send + Sync,
    {
        let tx_request = self.build_transaction_request();

        match provider.send_transaction(tx_request).await {
            Ok(pending_tx) => {
                let tx_hash = format!("{:?}", pending_tx.tx_hash());
                
                match pending_tx.get_receipt().await {
                    Ok(receipt) => {
                        let events: Vec<Bytes> = receipt.inner
                            .logs()
                            .iter()
                            .map(|log| log.data().data.clone())
                            .collect();

                        let data = ContractCallData {
                            contract_address: self.contract.address().unwrap(),
                            function_called: self.function_name(),
                            return_data: events.first().cloned().unwrap_or_default(),
                            gas_used: U256::from(receipt.gas_used()),
                            events,
                        };

                        RequestResult::success(data, Some(tx_hash), None)
                    }
                    Err(e) => RequestResult::error(RequestError::ContractError(e.to_string())),
                }
            }
            Err(e) => RequestResult::error(RequestError::ContractError(e.to_string())),
        }
    }

    fn validate(&self) -> Result<(), RequestError> {
        if !self.contract.is_deployed() {
            return Err(RequestError::ContractError("Contract not deployed".to_string()));
        }
        Ok(())
    }
}

impl<T: ContractType> Contract<T> {
    pub async fn deploy_and_wait<P>(
        mut self,
        provider: &P,
    ) -> RequestResult<Contract<T>>
    where
        P: Provider<Ethereum> + TraceApi<Ethereum> + Send + Sync,
    {
        let deployment = ContractDeployment::new(self.clone());
        
        match deployment.request(provider).await {
            RequestResult { success: true, data: Some(deployment_data), .. } => {
                self.info.address = Some(deployment_data.contract_address);
                self.info.deployment_tx = Some(deployment_data.deployment_tx);
                self.info.deployment_block = deployment_data.block_number;
                self.info.creator = Some(self.user_credentials.address());
                
                RequestResult::success(self, None, None)
            }
            RequestResult { success: false, error, trace_info, .. } => {
                RequestResult {
                    success: false,
                    error,
                    data: None,
                    transaction_hash: None,
                    trace_info,
                }
            }
            _ => RequestResult::error(RequestError::ContractError("Unexpected deployment result".to_string())),
        }


    }
}