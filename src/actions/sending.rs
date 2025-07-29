use alloy::{
    network::TransactionBuilder,
    primitives::{
        address,
        utils::Unit,
        U256,
    },
    providers::{Provider, ProviderBuilder, ext::TraceApi},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};

use std::{error::Error, fmt::Display};
use super::info::TransactionInfo;

use crate::config::simple_config::Config;

#[derive(Debug)]
pub struct SendError {
    pub message: String,
    pub code: i8,
}

pub struct SendTransactionRequest {
    pub to: String,
    pub value: U256,
    pub gas_limit: U256,
    pub gas_price: U256,
    pub trace_call : bool,
    pub private_key: PrivateKeySigner,
}

impl Error for SendError {}

impl Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SendError({}): {}", self.code, self.message)
    }
}

// Function to map errors to specific codes
fn map_error_to_code(error_msg: &str) -> i8 {
    match error_msg {
        // Parsing private key error
        msg if msg.contains("private key") || msg.contains("parse") => 1,
        
        // Network connection error
        msg if msg.contains("connection") || msg.contains("connect") || msg.contains("network") => 2,
        
        // RPC error
        msg if msg.contains("rpc") || msg.contains("RPC") => 3,
        
        // Transaction error (insufficient funds, gas, etc.)
        msg if msg.contains("insufficient") || msg.contains("funds") => 4,
        msg if msg.contains("gas") || msg.contains("Gas") => 5,
        msg if msg.contains("nonce") => 6,
        
        // Timeout error
        msg if msg.contains("timeout") || msg.contains("Timeout") => 7,
        
        // Receipt/confirmation error
        msg if msg.contains("receipt") || msg.contains("block") => 8,
        
        // Invalid address error
        msg if msg.contains("address") || msg.contains("Address") => 9,
        
        // Serialization/deserialization error
        msg if msg.contains("serialize") || msg.contains("deserialize") => 10,
        
        // Erreur générique
        _ => -1,
    }
}

impl SendError {
    pub fn from_error<T: Error>(err: T) -> Self {
        let message = err.to_string();
        let code = map_error_to_code(&message);
        SendError { message, code }
    }
    
    pub fn new(message: String, code: i8) -> Self {
        SendError { message, code }
    }
}


// Fonction pour récupérer les infos d'une transaction existante
pub async fn get_transaction_info(tx_hash: &str) -> Result<TransactionInfo, SendError> {
    let provider = ProviderBuilder::new()
        .connect("http://127.0.0.1:8545")
        .await
        .map_err(|e| SendError::new(format!("Failed to connect: {}", e), 2))?;

    let hash = tx_hash.parse()
        .map_err(|e| SendError::new(format!("Invalid transaction hash: {}", e), 1))?;

    TransactionInfo::from_hash(&provider, hash)
        .await
        .map_err(|e| SendError::new(format!("Failed to get transaction info: {}", e), -1))
}   