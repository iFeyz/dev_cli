use anyhow::{Result, Context};
use crossterm::{
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    execute,
};
use std::io;
use tokio::time::{sleep, Duration};

use crate::interactive::{
    state::{MenuState, MenuType, MenuItem},
    display::DisplayManager,
    handler::MenuHandlers,  
    prompt::PromptManager,  
};
use crate::config::{simple_config::Config, manager::ConfigManager};

pub struct InteractiveMenu {
    state: MenuState,
    display: DisplayManager,
    handlers: MenuHandlers,
    prompts: PromptManager,
    config: Config,
    should_exit: bool,
}

impl InteractiveMenu {
    // Create a new interactive menu
    pub fn new() -> Result<Self> {
        let state = MenuState::new();
        let display = DisplayManager::new();
        let handlers = MenuHandlers::new();
        let config_manager = ConfigManager::new()?;
        let config = config_manager.config().clone();
        let prompts = PromptManager::new();
        
        Ok(Self {
            state,
            display,
            handlers,
            prompts,
            config,
            should_exit: false,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        self.setup_terminal()?;
        self.show_welcome_screen().await?;
        
        while !self.should_exit {
            match self.run_current_menu().await {
                Ok(_) => {}
                Err(e) => {
                    self.display.show_error(&format!("Error: {}", e))?;
                    self.wait_for_key().await?;
                }
            }
        }
        
        self.cleanup_terminal()?;
        Ok(())
    }

    /// ===============================
    ///     MENU LOGIC
    /// ===============================

    async fn run_current_menu(&mut self) -> Result<()> {
        match &self.state.current_menu {
            MenuType::Main => self.run_main_menu().await,
            MenuType::Send => self.run_send_menu().await,
            MenuType::ViewTransactions => self.run_view_transactions_menu().await,
            MenuType::Back => {
                self.state.navigate_to(MenuType::Main);
                Ok(())
            }
        }
    }

    async fn run_main_menu(&mut self) -> Result<()> {
        let menu_items = vec![
            MenuItem::new(1, "Send", "Send ETH to another address"),
            MenuItem::new(2, "View Transactions", "View transaction details"),
            MenuItem::new(0, "Exit", "Exit the application"),
        ];

        self.display.clear_screen()?;
        self.display.show_header("Main Menu")?;
        self.display.show_menu(&menu_items)?;
        
        let status_info = self.get_status_info().await;
        self.display.show_status_bar(&status_info)?;
        
        let choice = self.prompts.get_menu_choice(0, 2).await?;
        match choice {
            1 => self.state.navigate_to(MenuType::Send),
            2 => self.state.navigate_to(MenuType::ViewTransactions),
            0 => self.should_exit = true,
            _ => unreachable!(),
        }
        Ok(())
    }

    async fn run_send_menu(&mut self) -> Result<()> {
        let menu_items = vec![
            MenuItem::new(1, "Send ETH", "Send ETH to an address"),
            MenuItem::new(2, "Back", "Return to main menu"),
        ];

        //self.display.clear_screen()?;
        self.display.show_header("Send Menu")?;
        self.display.show_menu(&menu_items)?;
        
        let status_info = self.get_status_info().await;
        self.display.show_status_bar(&status_info)?;

        let choice = self.prompts.get_menu_choice(1, 2).await?;
        match choice {
            1 => self.handle_send_eth().await?,
            2 => self.state.go_back(),
            _ => unreachable!(),
        }
        Ok(())
    }

    async fn run_view_transactions_menu(&mut self) -> Result<()> {
        let menu_items = vec![
            MenuItem::new(1, "View Transaction", "View transaction by hash"),
            MenuItem::new(2, "Back", "Return to main menu"),
        ];

        //self.display.clear_screen()?;
        self.display.show_header("View Transactions")?;
        self.display.show_menu(&menu_items)?;
        
        let status_info = self.get_status_info().await;
        self.display.show_status_bar(&status_info)?;

        let choice = self.prompts.get_menu_choice(1, 2).await?;
        match choice {
            1 => self.handle_view_transaction_from_hash().await?,
            2 => self.state.go_back(),
            _ => unreachable!(),
        }
        Ok(())
    }

    /// ===============================
    ///     UTILITY FUNCTIONS
    /// ===============================

    async fn handle_send_eth(&mut self) -> Result<()> {
        //self.display.clear_screen()?;
        self.display.show_header("Send ETH")?;

        let to_address = self.prompts.get_ethereum_address("Enter recipient address").await?;
        let amount = self.prompts.get_amount("Enter amount to send (ETH)").await?;
        let private_key = self.prompts.get_private_key_secure().await?;

        self.display.show_transaction_preview(&to_address, &amount, "ETH", &self.config.network_name)?;

        if !self.prompts.confirm("Confirm transaction").await? {
            self.display.show_info("Transaction cancelled")?;
            self.wait_for_key().await?;
            return Ok(());
        }

        self.display.show_progress("Sending transaction")?;
    
        match self.handlers.send_transaction(&to_address, &amount, &private_key).await {
            Ok(tx_hash) => {
                self.display.show_success("Transaction sent successfully!")?;
                self.display.show_transaction_result(&tx_hash.to_string())?;
            }
            Err(e) => {
                self.display.show_error(&format!("Transaction failed: {}", e))?;
            }
        }

        self.wait_for_key().await?;
        Ok(())
    }

    async fn handle_view_transaction_from_hash(&mut self) -> Result<()> {
        //self.display.clear_screen()?;
        self.display.show_header("View Transaction")?;

        let tx_hash = self.prompts.get_transaction_hash().await?;

        self.display.show_progress("Fetching transaction")?;    

        match self.handlers.get_transaction_info(&tx_hash).await {
            Ok(tx_info) => {
                self.display.show_transaction_details(&tx_info)?;
            }
            Err(e) => {
                self.display.show_error(&format!("Failed to fetch transaction: {}", e))?;
            }
        }

        self.wait_for_key().await?;
        Ok(())
    }

    async fn show_welcome_screen(&mut self) -> Result<()> {
        //self.display.clear_screen()?;
        self.display.show_welcome_banner()?;
        sleep(Duration::from_secs(2)).await;
        Ok(())
    }

    async fn wait_for_key(&mut self) -> Result<()> {
        self.display.show_info("Press any key to continue...")?;
        self.prompts.wait_for_any_key().await?;
        Ok(())
    }

    async fn get_status_info(&self) -> String {
        format!(
            "Running on: {} | Chain ID: {} | Network: {} | Version: {}",
            self.config.rpc_url,
            self.config.chain_id,
            self.config.network_name,
            env!("CARGO_PKG_VERSION"),
        )
    }

    fn setup_terminal(&mut self) -> Result<()> {
        enable_raw_mode().context("Failed to enable raw mode")?;
        execute!(io::stdout(), EnterAlternateScreen).context("Failed to enter alternate screen")?;
        Ok(())
    }

    fn cleanup_terminal(&mut self) -> Result<()> {
        disable_raw_mode().context("Failed to disable raw mode")?;
        execute!(io::stdout(), LeaveAlternateScreen).context("Failed to leave alternate screen")?;
        Ok(())
    }
}