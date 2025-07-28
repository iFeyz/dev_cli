use std::collections::VecDeque;
use serde_json;


#[derive(Debug, Clone)]
pub struct MenuState {
    pub current_menu: MenuType,
    pub menu_history: VecDeque<MenuType>,
    pub selected_index: usize,
    pub context_data: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MenuType {
    Main,
    Send,
    ViewTransactions,
    Back,
}

#[derive(Debug, Clone)]
pub struct MenuItem {
    pub id: usize,
    pub title: String,
    pub description: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub enum MenuAction {
    Navigate(MenuType), 
    Execute(String),
    Back,
    Exit,
}

impl MenuState {
    pub fn new() -> Self {
        Self {
            current_menu: MenuType::Main,
            menu_history: VecDeque::new(),
            selected_index: 0,
            context_data: std::collections::HashMap::new(),
        }
    }

    pub fn navigate_to(&mut self, menu: MenuType) {
        self.menu_history.push_back(self.current_menu.clone());
        self.current_menu = menu;
        self.selected_index = 0;
    }

    pub fn go_back(&mut self) {
        if let Some(prev_menu) = self.menu_history.pop_back() {
            self.current_menu = prev_menu;
            self.selected_index = 0;
        }
    }

    pub fn set_context_data(&mut self, key: String, value: serde_json::Value) {
        self.context_data.insert(key, value);
    }

    pub fn get_context_data(&self, key: &str) -> Option<&serde_json::Value> {
        self.context_data.get(key)
    }

}

impl MenuItem {

    pub fn new(id: usize, title: &str, description : &str) -> Self {
        Self {
            id,
            title: title.to_string(),
            description: description.to_string(),
            enabled: true,
        }
    }

    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }

}