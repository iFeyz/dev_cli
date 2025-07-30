mod actions;
mod interactive;
mod config;
mod model;
mod contract;

use model::exemple::run_transaction_example;
use interactive::menu::InteractiveMenu;
use dotenvy::dotenv;
use anyhow::Result;
use contract::example::{run_simple_storage_tests};

use alloy::{
    providers::{ProviderBuilder, ext::TraceApi},
    network::Ethereum,
    signers::local::PrivateKeySigner,
};
use alloy::transports::http::reqwest::Url;


use crate::config::simple_config::Config;
 

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let config = Config::load().unwrap();

    
    let rpc_url = "http://localhost:8545"; // or your testnet/mainnet RPC
    
    let provider = ProviderBuilder::new().connect_http(config.rpc_url.parse::<Url>().unwrap());

    //let mut menu = InteractiveMenu::new()?;
    //menu.run().await?;
    run_simple_storage_tests(&provider).await;
    
    Ok(())
}