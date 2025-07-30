mod actions;
mod interactive;
mod config;
mod model;
mod contract;

use interactive::menu::InteractiveMenu;
use dotenvy::dotenv;
use anyhow::Result;
use contract::contract_builder::test_contract_deployment;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    test_contract_deployment().await;
    //let mut menu = InteractiveMenu::new()?;
    //menu.run().await?;
    
    Ok(())
}