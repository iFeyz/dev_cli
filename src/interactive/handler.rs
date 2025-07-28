use anyhow::Result;
use crate::actions::{
    info::TransactionInfo,
    sending::{SendError, send_eth, get_transaction_info as get_tx_info, SendTransactionRequest},
};
use alloy::primitives::{U256};
use alloy::signers::local::PrivateKeySigner;


pub struct MenuHandlers;

impl MenuHandlers {
    pub fn new() -> Self {
        Self
    }

    pub async fn send_transaction(
        &self,
        _to_address: &str,
        _amount: &str,
        _private_key: &str,
    ) -> Result<TransactionInfo, SendError> {

        let transaction_request = SendTransactionRequest {
            to: _to_address.to_string(),    
            value: _amount.parse::<U256>().unwrap(),
            gas_limit: U256::from(21000),
            gas_price: U256::from(1000000000),
            trace_call: true,
            private_key: _private_key.parse::<PrivateKeySigner>().unwrap(),
        };
        send_eth(transaction_request).await
    }

    pub async fn get_transaction_info(&self, tx_hash: &str) -> Result<TransactionInfo, SendError> {
        get_tx_info(tx_hash).await
    }
}