use alloy::{
    primitives::{Address, U256, Bytes},
    signers::local::PrivateKeySigner,
    rpc::types::{TransactionRequest, trace::parity::TraceType},
    providers::{Provider, ext::TraceApi},
    network::{Network, TransactionBuilder, Ethereum, ReceiptResponse},
};

use async_trait::async_trait;
use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
pub enum RequestError {
    NetworkError(String),
    InsufficientFunds,
    InvalidAddress,
    ContractError(String),
    SigningError(String),
    TraceError(String),
    SimulationFailed(String),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RequestError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            RequestError::InsufficientFunds => write!(f, "Insufficient funds"),
            RequestError::InvalidAddress => write!(f, "Invalid address"),
            RequestError::ContractError(msg) => write!(f, "Contract error: {}", msg),
            RequestError::SigningError(msg) => write!(f, "Signing error: {}", msg),
            RequestError::TraceError(msg) => write!(f, "Trace error: {}", msg),
            RequestError::SimulationFailed(msg) => write!(f, "Simulation failed: {}", msg),
        }
    }
}

impl StdError for RequestError {}

#[derive(Debug, Clone)]
pub struct TraceInfo {
    pub gas_used: U256,
    pub success: bool,
    pub return_value: Option<Bytes>,
    pub error: Option<String>,
    pub calls: Vec<String>,
    pub logs_count: usize,
}

impl TraceInfo {
    pub fn from_trace_results(results: &alloy::rpc::types::trace::parity::TraceResults) -> Self {
        let mut calls = Vec::new();
        let mut gas_used = U256::ZERO;
        let mut success = true;
        let mut return_value = None;
        let mut error = None;
        let logs_count = 0;

        // Process trace results - TraceResults from parity trace API
        // results.trace is a Vec<TransactionTrace>, not Option<Vec<TransactionTrace>>
        for trace_item in &results.trace {
            calls.push(format!("{:?}", trace_item));
            
            // Extract gas usage if available
            if let Some(result) = &trace_item.result {
                let gas = result.gas_used();
                gas_used = U256::from(gas);
                
                // Get return value if available
                let output = result.output();
                return_value = Some(output.clone());
            }
            
            
            // Check for execution errors in the trace
            if let Some(ref trace_error) = trace_item.error {
                success = false;
                error = Some(trace_error.clone());
            }
        }

        // Check vm_trace for additional information if available
        if let Some(ref _vm_trace) = results.vm_trace {
            // VM trace processing can be added here if needed
        }

        // results.output is a Bytes, not Option<Bytes>
        // Use it as return value if we haven't found one yet
        if return_value.is_none() {
            return_value = Some(results.output.clone());
        }

        Self {
            gas_used,
            success,
            return_value,
            error,
            calls,
            logs_count,
        }
    }
}

#[derive(Clone)]
pub struct RequestConfig {
    pub gas_limit: U256,
    pub gas_price: U256,
    pub nonce: Option<U256>,
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self {
            gas_limit: U256::from(21_000),
            gas_price: U256::from(20_000_000_000u64), 
            nonce: None,
        }
    }
}

#[derive(Clone)]
pub struct UserCredentials {
    private_key: PrivateKeySigner,
    public_key: Address,
}

impl UserCredentials {
    pub fn new(private_key: PrivateKeySigner) -> Self {
        let public_key = private_key.address();
        Self {
            private_key,
            public_key,
        }
    }

    pub fn address(&self) -> Address {
        self.public_key
    }

    pub fn signer(&self) -> &PrivateKeySigner {
        &self.private_key
    }
}

#[derive(Debug)]
pub struct RequestResult<T> {
    pub success: bool,
    pub error: Option<RequestError>,
    pub data: Option<T>,
    pub transaction_hash: Option<String>,
    pub trace_info: Option<TraceInfo>, 
}

impl<T> RequestResult<T> {
    pub fn success(data: T, tx_hash: Option<String>, trace_info: Option<TraceInfo>) -> Self {
        Self {
            success: true,
            error: None,
            data: Some(data),
            transaction_hash: tx_hash,
            trace_info,
        }
    }

    pub fn error(error: RequestError) -> Self {
        Self {
            success: false,
            error: Some(error),
            data: None,
            transaction_hash: None,
            trace_info: None,
        }
    }

    pub fn simulation_failed(trace_info: TraceInfo, error: String) -> Self {
        Self {
            success: false,
            error: Some(RequestError::SimulationFailed(error)),
            data: None,
            transaction_hash: None,
            trace_info: Some(trace_info),
        }
    }
}

#[async_trait]
pub trait Requestable<T> {
    async fn request<P>(&self, provider: &P) -> RequestResult<T>
    where
        P: Provider<Ethereum> + TraceApi<Ethereum> + Send + Sync ;
    
    fn validate(&self) -> Result<(), RequestError>;
    
    fn build_transaction_request(&self) -> TransactionRequest;
    
    async fn trace_and_execute<P>(&self, provider: &P) -> RequestResult<T> 
    where
        P: Provider<Ethereum> + TraceApi<Ethereum> + Send + Sync ,
    {
        if let Err(e) = self.validate() {
            return RequestResult::error(e);
        }

        let tx_request = self.build_transaction_request();

        println!("🔍 Simulating transaction...");
        
        // Use the correct Alloy tracing method with proper types
        let trace_result = match provider.trace_call(&tx_request).await {
            Ok(result) => result,
            Err(e) => {
                return RequestResult::error(RequestError::TraceError(e.to_string()));
            }
        };

        let trace_info = TraceInfo::from_trace_results(&trace_result);
        
        println!("📊 Simulation results:");
        println!("  - Gas estimated: {}", trace_info.gas_used);
        println!("  - Success: {}", trace_info.success);
        println!("  - Function calls: {}", trace_info.calls.len());
        println!("  - Logs generated: {}", trace_info.logs_count);

        if !trace_info.success {
            let error_msg = trace_info.error
                .clone()
                .unwrap_or_else(|| "Transaction would fail".to_string());
            return RequestResult::simulation_failed(trace_info, error_msg);
        }

        println!("✅ Simulation successful, executing transaction...");
        let mut result = self.request(provider).await;
        
        // Update trace info in result
        result.trace_info = Some(trace_info);

        result
    }
}

#[derive(Debug)]
pub struct TransactionData {
    pub amount_sent: U256,
    pub recipient: Address,
    pub gas_used: U256,
}

pub struct Transaction {
    pub to: Address,
    pub value: U256,
    pub data: Option<Bytes>, 
    pub config: RequestConfig,
    pub user_credentials: UserCredentials,
}

impl Transaction {
    pub fn new_eth_transfer(
        to: Address,
        value: U256,
        credentials: UserCredentials,
        config: Option<RequestConfig>,
    ) -> Self {
        Self {
            to,
            value,
            data: None,
            config: config.unwrap_or_default(),
            user_credentials: credentials,
        }
    }

    pub fn new_token_transfer(
        to: Address,
        token_contract: Address,
        amount: U256,
        credentials: UserCredentials,
        config: Option<RequestConfig>,
    ) -> Self {
        // ERC-20 transfer function signature: transfer(address,uint256)
        let transfer_call = format!(
            "a9059cbb{:0>64}{:0>64}",
            hex::encode(to.as_slice()),
            format!("{:064x}", amount)
        );
        
        Self {
            to: token_contract,
            value: U256::ZERO,
            data: Some(Bytes::from(hex::decode(&transfer_call).unwrap())),
            config: config.unwrap_or_default(),
            user_credentials: credentials,
        }
    }
}

#[async_trait]
impl Requestable<TransactionData> for Transaction {
    fn build_transaction_request(&self) -> TransactionRequest {
        TransactionRequest::default()
            .with_from(self.user_credentials.address())
            .with_to(self.to)
            .with_value(self.value)
            .with_gas_limit(self.config.gas_limit.to::<u64>())
            .with_gas_price(self.config.gas_price.to::<u128>())
            .with_input(self.data.clone().unwrap_or_default())
    }

    async fn request<P>(&self, provider: &P) -> RequestResult<TransactionData>
    where
        P: Provider<Ethereum> + TraceApi<Ethereum> + Send + Sync ,
    {
        let tx_request = self.build_transaction_request();

        match provider.send_transaction(tx_request).await {
            Ok(pending_tx) => {
                let tx_hash = format!("{:?}", pending_tx.tx_hash());
                
                // Use get_receipt() to get the receipt
                match pending_tx.get_receipt().await {
                    Ok(receipt) => {
                        let data = TransactionData {
                            amount_sent: self.value,
                            recipient: self.to,
                            gas_used: U256::from(receipt.gas_used()),
                        };
                        RequestResult::success(data, Some(tx_hash), None)
                    }
                    Err(e) => RequestResult::error(RequestError::NetworkError(e.to_string())),
                }
            }
            Err(e) => RequestResult::error(RequestError::NetworkError(e.to_string())),
        }
    }

    fn validate(&self) -> Result<(), RequestError> {
        if self.to == Address::ZERO {
            return Err(RequestError::InvalidAddress);
        }
        if self.config.gas_limit == U256::ZERO {
            return Err(RequestError::NetworkError("Gas limit cannot be zero".to_string()));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct InteractionData {
    pub contract_address: Address,
    pub function_called: String,
    pub return_data: Bytes,
    pub gas_used: U256,
}

pub struct Interaction {
    pub contract_address: Address,
    pub function_data: Bytes, 
    pub function_name: String,
    pub value: U256, 
    pub config: RequestConfig,
    pub user_credentials: UserCredentials,
}

impl Interaction {
    pub fn new(
        contract_address: Address,
        function_data: Bytes,
        function_name: String,
        credentials: UserCredentials,
        config: Option<RequestConfig>,
    ) -> Self {
        Self {
            contract_address,
            function_data,
            function_name,
            value: U256::ZERO,
            config: config.unwrap_or_default(),
            user_credentials: credentials,
        }
    }

    pub fn with_value(mut self, value: U256) -> Self {
        self.value = value;
        self
    }
}

#[async_trait]
impl Requestable<InteractionData> for Interaction {
    fn build_transaction_request(&self) -> TransactionRequest {
        TransactionRequest::default()
            .with_from(self.user_credentials.address())
            .with_to(self.contract_address)
            .with_value(self.value)
            .with_input(self.function_data.clone())
            .with_gas_limit(self.config.gas_limit.to::<u64>())
            .with_gas_price(self.config.gas_price.to::<u128>())
    }

    async fn request<P>(&self, provider: &P) -> RequestResult<InteractionData>
    where
        P: Provider<Ethereum> + TraceApi<Ethereum> + Send + Sync ,
    {
        let tx_request = self.build_transaction_request();

        match provider.send_transaction(tx_request).await {
            Ok(pending_tx) => {
                let tx_hash = format!("{:?}", pending_tx.tx_hash());
                
                // Use get_receipt() to get the receipt
                match pending_tx.get_receipt().await {
                    Ok(receipt) => {
                        let data = InteractionData {
                            contract_address: self.contract_address,
                            function_called: self.function_name.clone(),
                            return_data: receipt.inner
                                .logs()
                                .first()
                                .map(|log| log.data().data.clone())
                                .unwrap_or_default(),
                            gas_used: U256::from(receipt.gas_used()),
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
        if self.contract_address == Address::ZERO {
            return Err(RequestError::InvalidAddress);
        }
        if self.function_data.is_empty() {
            return Err(RequestError::ContractError("Function data cannot be empty".to_string()));
        }
        Ok(())
    }
}