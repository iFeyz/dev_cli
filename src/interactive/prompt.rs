use anyhow::{Result, bail};
use crossterm::event::{self, Event, KeyCode, KeyEvent};
use rpassword::read_password;
use std::io::{self, Write};
use colored::*;

pub struct PromptManager {
    use_colors: bool,
}

impl PromptManager {
    pub fn new() -> Self {
        Self {
            use_colors: true, // TODO: get from config
        }
    }

    pub async fn get_menu_choice(&self, min: usize, max: usize) -> Result<usize> {
        loop {
            if self.use_colors {
                print!("🎯 Votre choix [{}..{}]: ", min.to_string().yellow(), max.to_string().yellow());
            } else {
                print!("Votre choix [{}..{}]: ", min, max);
            }
            io::stdout().flush()?;

            let input = self.read_line().await?;
            
            match input.trim().parse::<usize>() {
                Ok(choice) if choice >= min && choice <= max => return Ok(choice),
                Ok(choice) => {
                    if self.use_colors {
                        println!("❌ Choix invalide: {}. Veuillez choisir entre {} et {}.", 
                            choice.to_string().red(), min, max);
                    } else {
                        println!("Choix invalide: {}. Veuillez choisir entre {} et {}.", choice, min, max);
                    }
                }
                Err(_) => {
                    if self.use_colors {
                        println!("❌ Entrée invalide. Veuillez entrer un nombre.");
                    } else {
                        println!("Entrée invalide. Veuillez entrer un nombre.");
                    }
                }
            }
        }
    }

    pub async fn get_ethereum_address(&self, prompt: &str) -> Result<String> {
        loop {
            if self.use_colors {
                print!("🏷️  {}: ", prompt.cyan());
            } else {
                print!("{}: ", prompt);
            }
            io::stdout().flush()?;

            let input = self.read_line().await?;
            let address = input.trim();

            if self.validate_ethereum_address(address) {
                return Ok(address.to_string());
            } else {
                if self.use_colors {
                    println!("❌ Adresse Ethereum invalide. Format attendu: 0x... (42 caractères)");
                } else {
                    println!("Adresse Ethereum invalide. Format attendu: 0x... (42 caractères)");
                }
            }
        }
    }

    pub async fn get_amount(&self, prompt: &str) -> Result<String> {
        loop {
            if self.use_colors {
                print!("💰 {}: ", prompt.cyan());
            } else {
                print!("{}: ", prompt);
            }
            io::stdout().flush()?;

            let input = self.read_line().await?;
            let amount = input.trim();

            if self.validate_amount(amount) {
                return Ok(amount.to_string());
            } else {
                if self.use_colors {
                    println!("❌ Montant invalide. Utilisez des décimales (ex: 1.5, 0.01)");
                } else {
                    println!("Montant invalide. Utilisez des décimales (ex: 1.5, 0.01)");
                }
            }
        }
    }

    pub async fn get_private_key_secure(&self) -> Result<String> {
        if self.use_colors {
            print!("🔑 Clé privée (saisie masquée): ");
        } else {
            print!("Clé privée (saisie masquée): ");
        }
        io::stdout().flush()?;

        crossterm::terminal::disable_raw_mode()?;
        
        let private_key = read_password()
            .map_err(|e| anyhow::anyhow!("Erreur lors de la saisie: {}", e))?;
            
        crossterm::terminal::enable_raw_mode()?;

        if self.validate_private_key(&private_key) {
            Ok(private_key)
        } else {
            bail!("Clé privée invalide. Format attendu: 0x... (64 caractères hex)")
        }
    }

    pub async fn get_transaction_hash(&self) -> Result<String> {
        loop {
            if self.use_colors {
                print!("🔍 Hash de transaction: ");
            } else {
                print!("Hash de transaction: ");
            }
            io::stdout().flush()?;

            let input = self.read_line().await?;
            let hash = input.trim();

            if self.validate_transaction_hash(hash) {
                return Ok(hash.to_string());
            } else {
                if self.use_colors {
                    println!("❌ Hash invalide. Format attendu: 0x... (66 caractères)");
                } else {
                    println!("Hash invalide. Format attendu: 0x... (66 caractères)");
                }
            }
        }
    }

    pub async fn confirm(&self, message: &str) -> Result<bool> {
        loop {
            if self.use_colors {
                print!("❓ {} [o/N]: ", message.yellow());
            } else {
                print!("{} [o/N]: ", message);
            }
            io::stdout().flush()?;

            let input = self.read_line().await?;
            
            match input.trim().to_lowercase().as_str() {
                "o" | "oui" | "y" | "yes" => return Ok(true),
                "n" | "non" | "no" | "" => return Ok(false),
                _ => {
                    if self.use_colors {
                        println!("❌ Veuillez répondre par 'o' (oui) ou 'n' (non)");
                    } else {
                        println!("Veuillez répondre par 'o' (oui) ou 'n' (non)");
                    }
                }
            }
        }
    }

    pub async fn select_from_list(&self, prompt: &str, items: &[String]) -> Result<String> {
        if self.use_colors {
            println!("📋 {}", prompt.cyan().bold());
        } else {
            println!("{}", prompt);
        }

        for (i, item) in items.iter().enumerate() {
            if self.use_colors {
                println!("  {}. {}", (i + 1).to_string().yellow(), item.white());
            } else {
                println!("  {}. {}", i + 1, item);
            }
        }

        loop {
            if self.use_colors {
                print!("🎯 Choix [1..{}]: ", items.len().to_string().yellow());
            } else {
                print!("Choix [1..{}]: ", items.len());
            }
            io::stdout().flush()?;

            let input = self.read_line().await?;
            
            match input.trim().parse::<usize>() {
                Ok(choice) if choice >= 1 && choice <= items.len() => {
                    return Ok(items[choice - 1].clone());
                }
                Ok(choice) => {
                    if self.use_colors {
                        println!("❌ Choix invalide: {}. Choisissez entre 1 et {}.", 
                            choice.to_string().red(), items.len());
                    } else {
                        println!("Choix invalide: {}. Choisissez entre 1 et {}.", choice, items.len());
                    }
                }
                Err(_) => {
                    if self.use_colors {
                        println!("❌ Entrée invalide. Veuillez entrer un nombre.");
                    } else {
                        println!("Entrée invalide. Veuillez entrer un nombre.");
                    }
                }
            }
        }
    }

    pub async fn wait_for_any_key(&self) -> Result<()> {
        loop {
            if let Event::Key(KeyEvent { code, .. }) = event::read()? {
                match code {
                    KeyCode::Enter | KeyCode::Esc | KeyCode::Char(' ') => break,
                    _ => continue,
                }
            }
        }
        Ok(())
    }

    async fn read_line(&self) -> Result<String> {
        let mut input = String::new();
        
        loop {
            if let Event::Key(KeyEvent { code, modifiers, .. }) = event::read()? {
                match code {
                    KeyCode::Enter => break,
                    KeyCode::Char(c) => {
                        if modifiers.contains(crossterm::event::KeyModifiers::CONTROL) && c == 'c' {
                            bail!("Opération annulée par l'utilisateur");
                        }
                        input.push(c);
                        print!("{}", c);
                        io::stdout().flush()?;
                    }
                    KeyCode::Backspace => {
                        if !input.is_empty() {
                            input.pop();
                            print!("\x08 \x08");
                            io::stdout().flush()?;
                        }
                    }
                    KeyCode::Esc => {
                        bail!("Opération annulée");
                    }
                    _ => {}
                }
            }
        }
        
        println!(); 
        Ok(input)
    }

    // ========================================================================
    // MÉTHODES DE VALIDATION
    // ========================================================================

    fn validate_ethereum_address(&self, address: &str) -> bool {
        address.starts_with("0x") && 
        address.len() == 42 && 
        address[2..].chars().all(|c| c.is_ascii_hexdigit())
    }

    fn validate_amount(&self, amount: &str) -> bool {
        amount.parse::<f64>().map(|n| n > 0.0).unwrap_or(false)
    }

    fn validate_private_key(&self, key: &str) -> bool {
        (key.starts_with("0x") && key.len() == 66 || key.len() == 64) &&
        key.trim_start_matches("0x").chars().all(|c| c.is_ascii_hexdigit())
    }

    fn validate_transaction_hash(&self, hash: &str) -> bool {
        hash.starts_with("0x") && 
        hash.len() == 66 && 
        hash[2..].chars().all(|c| c.is_ascii_hexdigit())
    }
}