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
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub enum RequestError {
    NetworkError(String),
    InsufficientFunds,
    InvalidAddress,
    ContractError(String),
    SigningError(String),
    TraceError(String),
    SimulationFailed(String),
    TraceNotSupported,
    MissingBytecode,
    MissingCredentials,
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
            RequestError::TraceNotSupported => write!(f, "Trace not supported on this network"),
            RequestError::MissingBytecode => write!(f, "Bytecode is missing"),
            RequestError::MissingCredentials => write!(f, "Credentials are missing"),
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

        for trace_item in &results.trace {
            calls.push(format!("{:?}", trace_item));
            
            if let Some(result) = &trace_item.result {
                let gas = result.gas_used();
                gas_used = U256::from(gas);
                let output = result.output();
                return_value = Some(output.clone());
            }
            
            if let Some(ref trace_error) = trace_item.error {
                success = false;
                error = Some(trace_error.clone());
            }
        }

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
            gas_limit: U256::from(300_000),
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

/// Modes d'exécution pour les interactions
#[derive(Debug, Clone, Copy)]
pub enum ExecutionMode {
    /// Exécuter directement sans traçage
    Direct,
    /// Tracer seulement (simulation)
    TraceOnly,
    /// Tracer puis exécuter si succès
    TraceAndExecute,
}

// ============= TRANSACTION (pour les transferts wallet-à-wallet) =============

#[derive(Debug)]
pub struct TransactionData {
    pub amount_sent: U256,
    pub recipient: Address,
    pub gas_used: U256,
}

pub struct Transaction<N: Network> {
    pub to: Address,
    pub value: U256,
    pub data: Option<Bytes>, 
    pub config: RequestConfig,
    pub user_credentials: UserCredentials,
    pub execution_mode: ExecutionMode,
    _phantom: PhantomData<N>,
}

impl<N: Network> Transaction<N> {
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
            execution_mode: ExecutionMode::Direct,
            _phantom: PhantomData,
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
            execution_mode: ExecutionMode::Direct,
            _phantom: PhantomData,
        }
    }

    pub fn with_execution_mode(mut self, mode: ExecutionMode) -> Self {
        self.execution_mode = mode;
        self
    }

    fn build_transaction_request(&self) -> <N as Network>::TransactionRequest {
        let mut tx = <N as Network>::TransactionRequest::default()
            .with_from(self.user_credentials.address())
            .with_to(self.to)
            .with_value(self.value)
            .with_gas_limit(self.config.gas_limit.to::<u64>())
            .with_gas_price(self.config.gas_price.to::<u128>());

        if let Some(ref data) = self.data {
            tx = tx.with_input(data.clone());
        }
        tx
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

    pub async fn execute<P>(&self, provider: &P) -> RequestResult<TransactionData>
    where
        P: Provider<N> + Send + Sync,
    {
        match self.execution_mode {
            ExecutionMode::Direct => self.execute_direct(provider).await,
            ExecutionMode::TraceOnly => self.trace_only(provider).await,
            ExecutionMode::TraceAndExecute => self.trace_and_execute(provider).await,
        }
    }

    async fn execute_direct<P>(&self, provider: &P) -> RequestResult<TransactionData>
    where
        P: Provider<N> + Send + Sync,
    {
        if let Err(e) = self.validate() {
            return RequestResult::error(e);
        }

        let tx_request = self.build_transaction_request();

        match provider.send_transaction(tx_request).await {
            Ok(pending_tx) => {
                let tx_hash = format!("{:?}", pending_tx.tx_hash());
                
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

    async fn trace_only<P>(&self, provider: &P) -> RequestResult<TransactionData>
    where
        P: Provider<N> + Send + Sync,
    {
        // Similaire à Interaction mais pour Transaction
        RequestResult::error(RequestError::TraceNotSupported)
    }

    async fn trace_and_execute<P>(&self, provider: &P) -> RequestResult<TransactionData>
    where
        P: Provider<N> + Send + Sync,
    {
        // Pour l'instant, exécuter directement
        self.execute_direct(provider).await
    }
}

// ============= INTERACTION (pour les smart contracts) =============

#[derive(Debug)]
pub struct InteractionData {
    pub contract_address: Address,
    pub function_called: String,
    pub return_data: Bytes,
    pub gas_used: U256,
}

pub struct Interaction<N: Network = Ethereum> {
    pub contract_address: Address,
    pub function_data: Bytes,
    pub function_name: String,
    pub value: U256,
    pub config: RequestConfig,
    pub user_credentials: UserCredentials,
    pub execution_mode: ExecutionMode,
    _phantom: PhantomData<N>,
}

impl<N: Network> Interaction<N> {
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
            execution_mode: ExecutionMode::Direct,
            _phantom: PhantomData,
        }
    }

    pub fn with_value(mut self, value: U256) -> Self {
        self.value = value;
        self
    }

    pub fn with_execution_mode(mut self, mode: ExecutionMode) -> Self {
        self.execution_mode = mode;
        self
    }

    fn build_transaction_request(&self) -> <N as Network>::TransactionRequest {
        <N as Network>::TransactionRequest::default()
            .with_from(self.user_credentials.address())
            .with_to(self.contract_address)
            .with_value(self.value)
            .with_input(self.function_data.clone())
            .with_gas_limit(self.config.gas_limit.to::<u64>())
            .with_gas_price(self.config.gas_price.to::<u128>())
    }

    fn validate(&self) -> Result<(), RequestError> {
  
        if self.function_data.is_empty() {
            return Err(RequestError::ContractError("Function data cannot be empty".to_string()));
        }
        Ok(())
    }

    pub async fn execute<P>(&self, provider: &P) -> RequestResult<InteractionData>
    where
        P: Provider<N> + Send + Sync,
    {
        match self.execution_mode {
            ExecutionMode::Direct => self.execute_direct(provider).await,
            ExecutionMode::TraceOnly => self.trace_only(provider).await,
            ExecutionMode::TraceAndExecute => self.trace_and_execute(provider).await,
        }
    }

    async fn execute_direct<P>(&self, provider: &P) -> RequestResult<InteractionData>
    where
        P: Provider<N> + Send + Sync,
    {
        if let Err(e) = self.validate() {
            return RequestResult::error(e);
        }

        println!("🚀 Executing contract interaction directly...");
        let tx_request = self.build_transaction_request();

        match provider.send_transaction(tx_request).await {
            Ok(pending_tx) => {
                let tx_hash = format!("{:?}", pending_tx.tx_hash());
                println!("📝 Transaction sent: {}", tx_hash);
                
                match pending_tx.get_receipt().await {
                    Ok(receipt) => {
                        let data = InteractionData {
                            contract_address: self.contract_address,
                            function_called: self.function_name.clone(),
                            return_data: Bytes::new(),
                            //return_data: receipt
                            //    .logs()
                            //    .first()
                            //    .map(|log| log.data().data.clone())
                            //    .unwrap_or_default(),
                            gas_used: U256::from(receipt.gas_used()),
                        };
                        
                        println!("✅ Transaction confirmed");
                        println!("⛽ Gas used: {}", data.gas_used);
                        
                        RequestResult::success(data, Some(tx_hash), None)
                    }
                    Err(e) => RequestResult::error(RequestError::ContractError(e.to_string())),
                }
            }
            Err(e) => RequestResult::error(RequestError::ContractError(e.to_string())),
        }
    }

    async fn trace_only<P>(&self, provider: &P) -> RequestResult<InteractionData>
    where
        P: Provider<N> + Send + Sync,
    {
        if let Err(e) = self.validate() {
            return RequestResult::error(e);
        }

        println!("🔍 Simulating contract interaction...");

        // Pour l'instant, utiliser l'estimation de gas comme fallback
        self.estimate_gas_fallback(provider).await
    }

    async fn trace_and_execute<P>(&self, provider: &P) -> RequestResult<InteractionData>
    where
        P: Provider<N> + Send + Sync,
    {
        let trace_result = self.trace_only(provider).await;
        
        match trace_result {
            RequestResult { success: true, trace_info, .. } => {
                println!("✅ Simulation successful, executing transaction...");
                
                let mut execution_result = self.execute_direct(provider).await;
                execution_result.trace_info = trace_info;
                execution_result
            }
            result => result,
        }
    }

    async fn estimate_gas_fallback<P>(&self, provider: &P) -> RequestResult<InteractionData>
    where
        P: Provider<N> + Send + Sync,
    {
        let tx_request = self.build_transaction_request();
        
        match provider.estimate_gas(tx_request).await {
            Ok(gas_estimate) => {
                println!("⛽ Estimated gas: {}", gas_estimate);
                
                let trace_info = TraceInfo {
                    gas_used: U256::from(gas_estimate),
                    success: true,
                    return_value: None,
                    error: None,
                    calls: vec!["Gas estimation only".to_string()],
                    logs_count: 0,
                };
                
                let data = InteractionData {
                    contract_address: self.contract_address,
                    function_called: self.function_name.clone(),
                    return_data: Bytes::new(),
                    gas_used: U256::from(gas_estimate),
                };
                
                RequestResult::success(data, None, Some(trace_info))
            }
            Err(e) => RequestResult::error(RequestError::NetworkError(
                format!("Gas estimation failed: {}", e)
            )),
        }
    }
}

// Builder pour Interaction
pub struct InteractionBuilder<N: Network = Ethereum> {
    contract_address: Option<Address>,
    function_data: Option<Bytes>,
    function_name: Option<String>,
    value: U256,
    config: RequestConfig,
    credentials: Option<UserCredentials>,
    execution_mode: ExecutionMode,
    _phantom: PhantomData<N>,
}

impl<N: Network> InteractionBuilder<N> {
    pub fn new() -> Self {
        Self {
            contract_address: None,
            function_data: None,
            function_name: None,
            value: U256::ZERO,
            config: RequestConfig::default(),
            credentials: None,
            execution_mode: ExecutionMode::Direct,
            _phantom: PhantomData,
        }
    }

    pub fn with_contract(mut self, address: Address) -> Self {
        self.contract_address = Some(address);
        self
    }

    pub fn with_function(mut self, name: String, data: Bytes) -> Self {
        self.function_name = Some(name);
        self.function_data = Some(data);
        self
    }

    pub fn with_value(mut self, value: U256) -> Self {
        self.value = value;
        self
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

    pub fn build(self) -> Result<Interaction<N>, RequestError> {
        let contract_address = self.contract_address
            .ok_or(RequestError::InvalidAddress)?;
        let function_data = self.function_data
            .ok_or(RequestError::ContractError("Function data not set".to_string()))?;
        let function_name = self.function_name
            .ok_or(RequestError::ContractError("Function name not set".to_string()))?;
        let credentials = self.credentials
            .ok_or(RequestError::SigningError("Credentials not set".to_string()))?;

        Ok(Interaction {
            contract_address,
            function_data,
            function_name,
            value: self.value,
            config: self.config,
            user_credentials: credentials,
            execution_mode: self.execution_mode,
            _phantom: PhantomData,
        })
    }
}