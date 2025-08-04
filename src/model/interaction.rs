use alloy::{
    primitives::{Address, U256, Bytes, B256, Log, LogData},
    signers::local::PrivateKeySigner,
    rpc::types::{TransactionRequest, trace::parity::TraceType, Filter},
    providers::{Provider, ext::TraceApi},
    network::{Network, TransactionBuilder, Ethereum, ReceiptResponse},
};
use async_trait::async_trait;
use std::error::Error as StdError;
use std::fmt;
use std::marker::PhantomData;
use alloy::primitives::{keccak256};
use alloy_rlp::{RlpEncodable, RlpDecodable, Decodable, Encodable};
use alloy::{providers::ProviderBuilder, sol};
use alloy::sol_types::SolEvent;

// CORRECTED EVENT DEFINITIONS TO MATCH YOUR ACTUAL CONTRACTS
sol! {
    // Your actual PoolFactory event
    event PoolCreated(
        uint256 indexed id,
        address indexed token0,
        address indexed token1,
        uint8 fee,
        address poolAddress
    );
    
    // Keep this for compatibility with other factories
    event PairCreated(
        address indexed token0,
        address indexed token1,
        address pair,
        uint256
    );
}

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
            gas_limit: U256::from(300_000_00),
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
    pub contract_address: Option<Address>,
    pub function_data: Bytes,
    pub function_name: String,
    pub value: U256,
    pub config: RequestConfig,
    pub user_credentials: UserCredentials,
    pub execution_mode: ExecutionMode,
    _phantom: PhantomData<N>,
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq)]
pub struct EncodedData {
    pub a: u64,
    pub b: Vec<u8>,
}

impl<N: Network> Interaction<N> {
    pub fn new(
        contract_address: Option<Address>,
        function_data: Bytes,
        function_name: String,
        credentials: UserCredentials,
        config: Option<RequestConfig>,
    ) -> Self {
        if contract_address.is_none() {
            return Self {
                contract_address: None,
                function_data,
                function_name,
                value: U256::ZERO,
                config: config.unwrap_or_default(),
                user_credentials: credentials,
                execution_mode: ExecutionMode::Direct,
                _phantom: PhantomData,
            };
        }

        Self {
            contract_address: Some(contract_address.unwrap()),  
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

    fn build_transaction_request(&self, is_deployment: bool) -> <N as Network>::TransactionRequest {
        if is_deployment {
            return <N as Network>::TransactionRequest::default()
                .with_from(self.user_credentials.address())
                .with_value(self.value)
                .with_input(self.function_data.clone())
                .with_gas_limit(self.config.gas_limit.to::<u64>())
                .with_gas_price(self.config.gas_price.to::<u128>());
        }
        <N as Network>::TransactionRequest::default()
            .with_from(self.user_credentials.address())
            .with_to(self.contract_address.unwrap())
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

    pub fn calculate_contract_address(deployer: Address, nonce: u64) -> Address {
        let encoded_data = EncodedData {
            a: nonce,
            b: deployer.as_slice().to_vec(),
        };
        
        // Create a buffer to hold the encoded data
        let mut buf = Vec::new();
        
        // Encode into the buffer
        encoded_data.encode(&mut buf);
        
        // Now use the buffer which contains the encoded bytes
        let hash = keccak256(&buf);
        
        Address::from_slice(&hash[12..])
    }

    async fn execute_direct<P>(&self, provider: &P) -> RequestResult<InteractionData>
    where
        P: Provider<N> + Send + Sync,
    {
        if let Err(e) = self.validate() {
            return RequestResult::error(e);
        }
    
        println!("🚀 Executing contract interaction directly...");
        
        let is_deployment = self.contract_address.is_none();
        let is_pool_creation = self.function_name.contains("createPool") || 
                              self.function_name.contains("createPair") ||
                              self.function_name.contains("deploy");
        
        let nonce = if is_deployment {
            match provider.get_transaction_count(self.user_credentials.address()).await {
                Ok(n) => Some(n),
                Err(e) => {
                    println!("⚠️ Could not get nonce: {}", e);
                    None
                }
            }
        } else {
            None
        };
        
        let tx_request = self.build_transaction_request(is_deployment);
    
        match provider.send_transaction(tx_request).await {
            Ok(pending_tx) => {
                // Extract all needed values BEFORE any async operations
                let tx_hash = *pending_tx.tx_hash(); // Dereference to get owned B256
                let tx_hash_string = format!("{:?}", tx_hash);
                
                println!("📝 Transaction sent: {}", tx_hash_string);
                
                // Wait for receipt
                match pending_tx.get_receipt().await {
                    Ok(receipt) => {
                        // Get and print all logs from the transaction
                        println!("\n📋 Fetching transaction logs...");
                        
                        // Get logs using eth_getLogs
                        if let Ok(Some(full_receipt)) = provider.get_transaction_receipt(tx_hash).await {
                            // Get the block number from receipt
                            if let Some(block_number) = full_receipt.block_number() {
                                let filter = Filter::new()
                                    .from_block(0)
                                    .to_block(1000000000000000000);
                                
                                if let Ok(logs) = provider.get_logs(&filter).await {
                                    let tx_logs: Vec<_> = logs.into_iter()
                                        .filter(|log| log.transaction_hash == Some(tx_hash))
                                        .collect();
                                    
                                    println!("📋 Found {} logs in transaction", tx_logs.len());
                                    
                                    // Variable to store found pool address
                                    let mut found_pool_address: Option<Address> = None;
                                    
                                    for (i, log) in tx_logs.iter().enumerate() {
                                        println!("\n🔍 Log #{}:", i);
                                        println!("  📍 Contract: {}", log.inner.address);
                                        println!("  📑 Topics:");
                                        for (j, topic) in log.topics().iter().enumerate() {
                                            println!("    [{}]: {}", j, topic);
                                        }
                                        println!("  📦 Data: 0x{}", hex::encode(&log.inner.data.data));
                                        
                                        // Try to decode known events
                                        let primitives_log = alloy::primitives::Log {
                                            address: log.inner.address,
                                            data: LogData::new_unchecked(
                                                log.inner.topics().to_vec(),
                                                log.inner.data.data.clone(),
                                            ),
                                        };
                                        
                                        // Try to identify the event
                                        if log.topics().len() > 0 {
                                            let event_sig = &log.topics()[0];
                                            
                                            // Check for your PoolCreated event
                                            if *event_sig == keccak256("PoolCreated(uint256,address,address,uint8,address)") {
                                                println!("  ✨ Event: PoolCreated");
                                                if let Ok(decoded) = PoolCreated::decode_log(&primitives_log) {
                                                    println!("    - ID: {}", decoded.id);
                                                    println!("    - Token0: {}", decoded.token0);
                                                    println!("    - Token1: {}", decoded.token1);
                                                    println!("    - Fee: {}", decoded.fee);
                                                    println!("    - Pool: {}", decoded.poolAddress);
                                                    found_pool_address = Some(decoded.poolAddress);
                                                }
                                            } else if *event_sig == keccak256("PairCreated(address,address,address,uint256)") {
                                                println!("  ✨ Event: PairCreated");
                                                if let Ok(decoded) = PairCreated::decode_log(&primitives_log) {
                                                    println!("    - Token0: {}", decoded.token0);
                                                    println!("    - Token1: {}", decoded.token1);
                                                    println!("    - Pair: {}", decoded.pair);
                                                    found_pool_address = Some(decoded.pair);
                                                }
                                            } else {
                                                println!("  ❓ Unknown event signature");
                                            }
                                        }
                                    }
                                    
                                    // Update contract address if pool was found
                                    if is_pool_creation && found_pool_address.is_some() {
                                        let pool_addr = found_pool_address.unwrap();
                                        println!("\n🎉 Pool successfully created at: {}", pool_addr);
                                        
                                        let data = InteractionData {
                                            contract_address: pool_addr,
                                            function_called: self.function_name.clone(),
                                            return_data: Bytes::new(),
                                            gas_used: U256::from(receipt.gas_used()),
                                        };
                                        
                                        return RequestResult::success(data, Some(tx_hash_string), None);
                                    }
                                }
                            }
                        }
                        
                        // Default handling if no pool address found
                        let contract_address = if is_deployment {
                            if let Some(addr) = receipt.contract_address() {
                                addr
                            } else if let Some(n) = nonce {
                                Self::calculate_contract_address(self.user_credentials.address(), n)
                            } else {
                                return RequestResult::error(RequestError::ContractError("No contract address found".to_string()));
                            }
                        } else {
                            self.contract_address.unwrap()
                        };
        
                        let data = InteractionData {
                            contract_address,
                            function_called: self.function_name.clone(),
                            return_data: Bytes::new(),
                            gas_used: U256::from(receipt.gas_used()),
                        };
                        
                        println!("\n✅ Transaction confirmed");
                        println!("📍 Contract address: {}", contract_address);
                        println!("⛽ Gas used: {}", data.gas_used);
                        
                        RequestResult::success(data, Some(tx_hash_string), None)
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
        let tx_request = self.build_transaction_request(false);
        
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
                    contract_address: self.contract_address.unwrap(),
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
            contract_address: Some(contract_address),
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

async fn extract_pool_address_from_receipt<P, N>(
    provider: &P,
    tx_hash: B256,
) -> Option<Address>
where
    P: Provider<N> + Send + Sync,
    N: Network,
{
    // Use eth_getLogs to get logs for this transaction
    let filter = alloy::rpc::types::Filter::new()
        .from_block(0u64)
        .to_block(u64::MAX)
        .event_signature(vec![
            // Your actual PoolCreated event signature
            keccak256("PoolCreated(uint256,address,address,uint8,address)"),
            // Keep PairCreated for compatibility
            keccak256("PairCreated(address,address,address,uint256)"),
        ]);
    
    match provider.get_logs(&filter).await {
        Ok(logs) => {
            for log in logs {
                if log.transaction_hash == Some(tx_hash) {
                    // Convert RPC log to primitives log for decoding
                    let primitives_log = alloy::primitives::Log {
                        address: log.inner.address,
                        data: LogData::new_unchecked(
                            log.inner.topics().to_vec(),
                            log.inner.data.data.clone(),
                        ),
                    };
                    
                    let pool_addr = try_decode_pool_address(&primitives_log);
                    if pool_addr.is_some() {
                        return pool_addr;
                    }
                }
            }
        }
        Err(e) => println!("Failed to get logs: {}", e),
    }
    
    None
}

fn try_decode_pool_address(log: &Log) -> Option<Address> {
    println!("🔍 Trying to decode pool address from log: {:?}", log);
    // Try to decode as PoolCreated
    if let Ok(decoded) = PoolCreated::decode_log(log) {
        println!("✅ Found PoolCreated event: pool at {}", decoded.poolAddress);
        return Some(decoded.poolAddress);
    }
    
    // Try to decode as PairCreated
    if let Ok(decoded) = PairCreated::decode_log(log) {
        println!("✅ Found PairCreated event: pair at {}", decoded.pair);
        return Some(decoded.pair);
    }
    
    // Manual extraction as fallback
    if log.topics().len() >= 1 && log.data.data.len() >= 32 {
        // Many factories put pool address as last parameter in data
        let start = log.data.data.len() - 32;
        let addr_bytes = &log.data.data[start..];
        
        // Check if bytes 0-12 are zeros (indicating an address)
        if addr_bytes[..12].iter().all(|&b| b == 0) {
            let pool_address = Address::from_slice(&addr_bytes[12..32]);
            if pool_address != Address::ZERO {
                println!("📍 Extracted pool address from data: {}", pool_address);
                return Some(pool_address);
            }
        }
    }
    
    None
}
