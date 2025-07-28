use super::simple_config::Config;
use anyhow::Result;

/// Gestionnaire simple de configuration
pub struct ConfigManager {
    config: Config,
}

impl ConfigManager {
    /// Charge la configuration
    pub fn new() -> Result<Self> {
        let config = Config::load()?;
        config.validate()?;
        
        Ok(Self { config })
    }

    /// Retourne la configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Met à jour la configuration
    pub fn update_config(&mut self, new_config: Config) -> Result<()> {
        new_config.validate()?;
        self.config = new_config;
        Ok(())
    }

    /// Charge une configuration prédéfinie
    pub fn load_preset(&mut self, preset: &str) -> Result<()> {
        let config = match preset {
            "anvil" | "local" => Config::default_anvil(),
                "mainnet" => Config::mainnet(),
                "sepolia" => Config::sepolia(),
            _ => anyhow::bail!("Unknown preset: {}", preset),
        };

        self.update_config(config)
    }
}