
pub mod actions;
pub mod interactive;
pub mod config;

// Re-exports pour faciliter l'usage externe
pub use actions::{
    info::TransactionInfo,
    sending::{send_eth, get_transaction_info, SendError},
};

pub use interactive::menu::InteractiveMenu;

pub use config::{
    simple_config::Config,
    manager::ConfigManager,
};