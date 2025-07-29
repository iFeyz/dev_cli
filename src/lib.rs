
pub mod actions;
pub mod interactive;
pub mod config;
pub mod model;

// Re-exports pour faciliter l'usage externe
pub use actions::{
    info::TransactionInfo,
    sending::{get_transaction_info, SendError},
};

pub use interactive::menu::InteractiveMenu;

pub use config::{
    simple_config::Config,
    manager::ConfigManager,
};