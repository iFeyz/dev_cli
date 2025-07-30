use anyhow::Result;
use crate::actions::{
    info::TransactionInfo,
    sending::{SendError, get_transaction_info as get_tx_info, SendTransactionRequest},
};
use alloy::primitives::{U256, Address};
use alloy::signers::local::PrivateKeySigner;
use alloy::providers::ProviderBuilder;
use alloy::transports::http::reqwest::Url;


use crate::config::simple_config::Config;
use crate::model::interaction::{Transaction, UserCredentials, RequestConfig, RequestResult, TransactionData};

pub struct MenuHandlers;

impl MenuHandlers {
    pub fn new() -> Self {
        Self
    }

    pub async fn get_transaction_info(&self, tx_hash: &str) -> Result<TransactionInfo, SendError> {
        get_tx_info(tx_hash).await
    }

    pub async fn send_transaction_with_trace(&self, _to_address : &str, _amount : &str, _private_key : &str) -> RequestResult<TransactionData> {
        let config = Config::load().unwrap();
        let provider = ProviderBuilder::new().connect_http(config.rpc_url.parse::<Url>().unwrap());
        let transaction = Transaction::new_eth_transfer(
            _to_address.parse::<Address>().unwrap(),
            _amount.parse::<U256>().unwrap(),
            UserCredentials::new(_private_key.parse::<PrivateKeySigner>().unwrap()),
            Some(RequestConfig::default()),
        );
        //Get a config provider
        let result = transaction.execute(&provider).await;
        result
    }

    pub async fn send_transaction_without_trace(&self, _to_address : &str, _amount : &str, _private_key : &str) -> RequestResult<TransactionData> {
        let config = Config::load().unwrap();
        let provider = ProviderBuilder::new().connect_http(config.rpc_url.parse::<Url>().unwrap());
        let transaction = Transaction::new_eth_transfer(
            _to_address.parse::<Address>().unwrap(),
            _amount.parse::<U256>().unwrap(),
            UserCredentials::new(_private_key.parse::<PrivateKeySigner>().unwrap()),
            Some(RequestConfig::default()),
        );
        let result = transaction.execute(&provider).await;
        result
    }



}