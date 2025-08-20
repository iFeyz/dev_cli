mod actions;
mod interactive;
mod config;
mod model;
mod contract;
mod examples;
mod universal;

use interactive::menu::InteractiveMenu;
use dotenvy::dotenv;
use anyhow::Result;
use examples::main_example::{example_deployment_and_interaction, example_aam_factory_deploy_and_interact};
use contract::contract_builder::test_contract_deployment;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    example_aam_factory_deploy_and_interact().await;
    //example_deployment_and_interaction().await;
    //test_contract_deployment().await;
    //let mut menu = InteractiveMenu::new()?;
    //menu.run().await?;
    
    Ok(())
}