use anyhow::Result;
use colored::*;
use std::io::{self, Write};

use crate::actions::info::TransactionInfo;
use crate::interactive::state::MenuItem;

pub struct DisplayManager {
    use_colors: bool,
    terminal_width: usize,
}

impl DisplayManager {
    pub fn new() -> Self {
        let terminal_width = match terminal_size::terminal_size() {
            Some((terminal_size::Width(width), _)) => std::cmp::max(width as usize, 70),
            None => 80,
        };

        Self {
            use_colors: atty::is(atty::Stream::Stdout),
            terminal_width,
        }
    }

    pub fn clear_screen(&self) -> Result<()> {
        print!("\x1B[2J\x1B[1;1H");
        //io::stdout().flush()?;
        Ok(())
    }

    pub fn show_header(&self, title: &str) -> Result<()> {
        let border = "═".repeat(self.terminal_width.saturating_sub(4));
        
        if self.use_colors {
            println!("╔{}╗", border);
            println!("║ {} ║", title.cyan().bold().to_string().pad_to_width(self.terminal_width.saturating_sub(6)));
            println!("╚{}╝", border);
        } else {
            println!("┌{}┐", border);
            println!("│ {} │", title.pad_to_width(self.terminal_width.saturating_sub(6)));
            println!("└{}┘", border);
        }
        
        println!();
        Ok(())
    }

    pub fn show_menu(&self, items: &[MenuItem]) -> Result<()> {
        for item in items {
            let status = if item.enabled { "" } else { " (Désactivé)" };
            
            if self.use_colors {
                if item.enabled {
                    println!("  📋 {}. {} - {}{}", 
                        item.id.to_string().yellow().bold(),
                        item.title.green().bold(),
                        item.description.white(),
                        status.red()
                    );
                } else {
                    println!("  📋 {}. {} - {}{}", 
                        item.id.to_string().dimmed(),
                        item.title.dimmed(),
                        item.description.dimmed(),
                        status.red()
                    );
                }
            } else {
                println!("  * {}. {} - {}{}", 
                    item.id, item.title, item.description, status);
            }
        }
        
        println!();
        Ok(())
    }

    pub fn show_status_bar(&self, status: &str) -> Result<()> {
        let border = "─".repeat(self.terminal_width);
        println!("{}", border);
        
        if self.use_colors {
            println!("📊 {}", status.blue());
        } else {
            println!("Status: {}", status);
        }
        
        println!("{}", border);
        println!();
        Ok(())
    }

    pub fn show_success(&self, message: &str) -> Result<()> {
        if self.use_colors {
            println!("✅ {}", message.green().bold());
        } else {
            println!("✓ {}", message);
        }
        Ok(())
    }

    pub fn show_error(&self, message: &str) -> Result<()> {
        if self.use_colors {
            println!("❌ {}", message.red().bold());
        } else {
            println!("✗ {}", message);
        }
        Ok(())
    }

    pub fn show_info(&self, message: &str) -> Result<()> {
        if self.use_colors {
            println!("ℹ️  {}", message.blue());
        } else {
            println!("Info: {}", message);
        }
        Ok(())
    }

    pub fn show_progress(&self, message: &str) -> Result<()> {
        if self.use_colors {
            print!("⏳ {}... ", message.yellow());
        } else {
            print!("En cours: {}... ", message);
        }
        //io::stdout().flush()?;
        Ok(())
    }

    pub fn show_welcome_banner(&self) -> Result<()> {
        let banner_lines = vec![
            "╔══════════════════════════════════════════════════════════╗",
            "║                                                          ║",
            "║                      CLI WALLET                          ║",
            "║                                                          ║",
            "║                 Welcome to your wallet!                  ║",
            "╚══════════════════════════════════════════════════════════╝",
        ];
    
        for line in banner_lines {
            if self.use_colors {
                println!("{}", line.cyan().bold());
            } else {
                println!("{}", line);
            }
        }
    
        Ok(())
    }

    pub fn show_transaction_preview(&self, to: &str, amount: &str, currency: &str, network: &str) -> Result<()> {
        println!("┌─────────────── TRANSACTION PREVIEW ───────────────┐");
        
        if self.use_colors {
            println!("│ Recipient: {}                    │", to.green());
            println!("│ Amount:      {} {}                      │", amount.yellow().bold(), currency.yellow());
            println!("│ Network:       {}                       │", "Ethereum".blue());
        } else {
            println!("│ Recipient: {}                    │", to);
            println!("│ Amount:      {} {}                      │", amount, currency);
            println!("│ Network:       {}                       │", network);
        }
        
        println!("└─────────────────────────────────────────────────────────┘");
        println!();
        Ok(())
    }

    pub fn show_transaction_result(&self, tx_hash: &str) -> Result<()> {
        if self.use_colors {
            println!("🎉 Hash of transaction: {}", tx_hash.green().bold());
        } else {
            println!("Hash of transaction: {}", tx_hash);
        }
        Ok(())
    }

    pub fn show_transaction_details(&self, tx_info: &TransactionInfo) -> Result<()> {
        println!("{}", tx_info);
        Ok(())
    }
}

trait StringPadding {
    fn pad_to_width(&self, width: usize) -> String;
}

impl StringPadding for str {
    fn pad_to_width(&self, width: usize) -> String {
        let len = self.len();
        if len >= width {
            self.to_string()
        } else {
            format!("{}{}", self, " ".repeat(width - len))
        }
    }
}