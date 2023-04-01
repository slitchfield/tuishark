use core::fmt;
use tui::style::{Color, Style};
use tui_tree_widget::TreeItem;

#[derive(Clone, Debug)]
pub struct Ethernet {}

#[allow(dead_code)]
impl Ethernet {
    pub fn new() -> Self {
        Ethernet {}
    }

    pub fn to_tree_item<'a, 'b>(&'a self) -> TreeItem<'b> {
        TreeItem::new_leaf(self.to_string()).style(Style::default().bg(Color::LightYellow))
    }
}

impl fmt::Display for Ethernet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ethernet Data [Starts: XX, Len: XX]",)
    }
}
