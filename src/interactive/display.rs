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
        io::stdout().flush()?; // FIX: Uncommented flush
        Ok(())
    }

    pub fn show_header(&self, title: &str) -> Result<()> {
        let content_width = self.terminal_width.saturating_sub(4);
        let border = if self.use_colors { "═" } else { "─" };
        let border_line = border.repeat(content_width);
        
        if self.use_colors {
            println!("╔{}╗", border_line);
            let padded_title = self.pad_center(title, content_width.saturating_sub(2));
            println!("║ {} ║", padded_title.cyan().bold());
            println!("╚{}╝", border_line);
        } else {
            println!("┌{}┐", border_line);
            println!("│ {} │", self.pad_center(title, content_width.saturating_sub(2)));
            println!("└{}┘", border_line);
        }
        
        println!();
        io::stdout().flush()?; // FIX: Added flush
        Ok(())
    }

    pub fn show_menu(&self, items: &[MenuItem]) -> Result<()> {
        for item in items {
            let status = if item.enabled { "" } else { " (Désactivé)" };
            let prefix = if self.use_colors { "📋" } else { "*" };
            
            if self.use_colors {
                if item.enabled {
                    println!("  {} {}. {} - {}{}", 
                        prefix,
                        item.id.to_string().yellow().bold(),
                        item.title.green().bold(),
                        item.description.white(),
                        status.red()
                    );
                } else {
                    println!("  {} {}. {} - {}{}", 
                        prefix,
                        item.id.to_string().dimmed(),
                        item.title.dimmed(),
                        item.description.dimmed(),
                        status.red()
                    );
                }
            } else {
                println!("  {} {}. {} - {}{}", 
                    prefix, item.id, item.title, item.description, status);
            }
        }
        
        println!();
        io::stdout().flush()?; // FIX: Added flush
        Ok(())
    }

    pub fn show_status_bar(&self, status: &str) -> Result<()> {
        let border = "─".repeat(self.terminal_width);
        println!("{}", border);
        
        let prefix = if self.use_colors { "📊" } else { "Status:" };
        if self.use_colors {
            println!("{} {}", prefix, status.blue());
        } else {
            println!("{} {}", prefix, status);
        }
        
        println!("{}", border);
        println!();
        io::stdout().flush()?; // FIX: Added flush
        Ok(())
    }

    pub fn show_success(&self, message: &str) -> Result<()> {
        let prefix = if self.use_colors { "✅" } else { "✓" };
        if self.use_colors {
            println!("{} {}", prefix, message.green().bold());
        } else {
            println!("{} {}", prefix, message);
        }
        io::stdout().flush()?; // FIX: Added flush
        Ok(())
    }

    pub fn show_error(&self, message: &str) -> Result<()> {
        let prefix = if self.use_colors { "❌" } else { "✗" };
        if self.use_colors {
            eprintln!("{} {}", prefix, message.red().bold()); // FIX: Use eprintln for errors
        } else {
            eprintln!("{} {}", prefix, message);
        }
        io::stderr().flush()?; // FIX: Flush stderr
        Ok(())
    }

    pub fn show_info(&self, message: &str) -> Result<()> {
        let prefix = if self.use_colors { "ℹ️" } else { "Info:" };
        if self.use_colors {
            println!("{} {}", prefix, message.blue());
        } else {
            println!("{} {}", prefix, message);
        }
        io::stdout().flush()?; // FIX: Added flush
        Ok(())
    }

    pub fn show_progress(&self, message: &str) -> Result<()> {
        let prefix = if self.use_colors { "⏳" } else { "En cours:" };
        if self.use_colors {
            print!("{} {}... ", prefix, message.yellow());
        } else {
            print!("{} {}... ", prefix, message);
        }
        io::stdout().flush()?; // FIX: Uncommented flush
        Ok(())
    }

    pub fn show_welcome_banner(&self) -> Result<()> {
        let width = std::cmp::min(self.terminal_width, 60);
        let content_width = width.saturating_sub(4);
        
        let top_border = if self.use_colors { "╔" } else { "┌" };
        let bottom_border = if self.use_colors { "╚" } else { "└" };
        let side = if self.use_colors { "║" } else { "│" };
        let horizontal = if self.use_colors { "═" } else { "─" };
        let end_top = if self.use_colors { "╗" } else { "┐" };
        let end_bottom = if self.use_colors { "╝" } else { "┘" };
        
        let border_line = horizontal.repeat(width.saturating_sub(2));
        
        let empty_line = format!("{} {} {}", side, " ".repeat(content_width), side);
        let title_line = format!("{} {} {}", side, self.pad_center("CLI WALLET", content_width), side);
        let welcome_line = format!("{} {} {}", side, self.pad_center("Welcome to your wallet!", content_width), side);
        
        println!("{}{}{}", top_border, border_line, end_top);
        println!("{}", empty_line);
        if self.use_colors {
            println!("{}", title_line.cyan().bold());
        } else {
            println!("{}", title_line);
        }
        println!("{}", empty_line);
        if self.use_colors {
            println!("{}", welcome_line.cyan());
        } else {
            println!("{}", welcome_line);
        }
        println!("{}", empty_line);
        println!("{}{}{}", bottom_border, border_line, end_bottom);
        
        println!();
        io::stdout().flush()?; // FIX: Added flush
        Ok(())
    }

    pub fn show_transaction_preview(&self, to: &str, amount: &str, currency: &str, network: &str) -> Result<()> {
        let max_width = std::cmp::min(self.terminal_width, 60);
        let title = " TRANSACTION PREVIEW ";
        let title_line = format!("┌{}{}{}┐", 
            "─".repeat((max_width.saturating_sub(title.len() + 2)) / 2),
            title,
            "─".repeat((max_width.saturating_sub(title.len() + 2) + 1) / 2)
        );
        
        println!("{}", title_line);
        
        // FIX: Dynamic formatting based on content length
        let to_display = if to.len() > 25 { 
            format!("{}...", &to[..22])
        } else { 
            to.to_string() 
        };
        
        let field_width = max_width.saturating_sub(16); // Leave space for "│ Recipient: " and " │"
        
        if self.use_colors {
            let padded_to = self.pad_right(&to_display, field_width);
            let amount_str = format!("{} {}", amount, currency);
            let padded_amount = self.pad_right(&amount_str, field_width);
            let padded_network = self.pad_right(network, field_width);
            
            println!("│ Recipient: {} │", padded_to.green());
            println!("│ Amount:    {} │", padded_amount.yellow().bold());
            println!("│ Network:   {} │", padded_network.blue());
        } else {
            println!("│ Recipient: {} │", self.pad_right(&to_display, field_width));
            println!("│ Amount:    {} │", self.pad_right(&format!("{} {}", amount, currency), field_width));
            println!("│ Network:   {} │", self.pad_right(network, field_width));
        }
        
        println!("{}", "└".to_string() + &"─".repeat(max_width.saturating_sub(2)) + "┘");
        println!();
        io::stdout().flush()?; // FIX: Added flush
        Ok(())
    }

    pub fn show_transaction_result(&self, tx_hash: &str) -> Result<()> {
        let prefix = if self.use_colors { "🎉" } else { "✓" };
        
        // FIX: Truncate long hashes for display
        let hash_display = if tx_hash.len() > 20 {
            format!("{}...{}", &tx_hash[..10], &tx_hash[tx_hash.len()-10..])
        } else {
            tx_hash.to_string()
        };
        
        if self.use_colors {
            println!("{} Hash of transaction: {}", prefix, hash_display.green().bold());
        } else {
            println!("{} Hash of transaction: {}", prefix, hash_display);
        }
        io::stdout().flush()?; // FIX: Added flush
        Ok(())
    }

    pub fn show_transaction_details(&self, tx_info: &TransactionInfo) -> Result<()> {
        println!("{}", tx_info);
        io::stdout().flush()?; // FIX: Added flush
        Ok(())
    }

    // Helper methods for consistent padding
    fn pad_center(&self, text: &str, width: usize) -> String {
        let text_len = text.chars().count(); // FIX: Use char count for Unicode
        if text_len >= width {
            text.to_string()
        } else {
            let padding = width - text_len;
            let left_pad = padding / 2;
            let right_pad = padding - left_pad;
            format!("{}{}{}", " ".repeat(left_pad), text, " ".repeat(right_pad))
        }
    }

    fn pad_right(&self, text: &str, width: usize) -> String {
        let text_len = text.chars().count(); // FIX: Use char count for Unicode
        if text_len >= width {
            text.to_string()
        } else {
            format!("{}{}", text, " ".repeat(width - text_len))
        }
    }
}

// FIX: Removed the StringPadding trait as it's replaced by helper methods