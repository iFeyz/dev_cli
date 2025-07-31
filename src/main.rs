mod actions;
mod interactive;
mod config;
mod model;
mod contract;
mod examples;

use interactive::menu::InteractiveMenu;
use dotenvy::dotenv;
use anyhow::Result;
use examples::main_example::example_deployment_and_interaction;
use contract::contract_builder::test_contract_deployment;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    example_deployment_and_interaction().await;
    //test_contract_deployment().await;
    //let mut menu = InteractiveMenu::new()?;
    //menu.run().await?;
    
    Ok(())
}