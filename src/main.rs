mod actions;
mod interactive;
mod config;

use interactive::menu::InteractiveMenu;
use dotenvy::dotenv;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    
    let mut menu = InteractiveMenu::new()?;
    menu.run().await?;
    
    Ok(())
}