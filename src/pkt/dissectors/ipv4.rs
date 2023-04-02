use core::fmt;
use tui::style::{Color, Style};
use tui_tree_widget::TreeItem;

#[derive(Clone, Debug)]
pub struct IPv4 {}

#[allow(dead_code)]
impl IPv4 {
    pub fn new() -> Self {
        IPv4 {}
    }

    #[allow(dead_code)]
    pub fn to_tree_item_verbose<'a, 'b>(&'a self) -> TreeItem<'b> {
        TreeItem::new(self.to_string(), vec![])
            .style(Style::default().fg(Color::Black).bg(Color::LightYellow))
    }

    pub fn to_tree_item<'a, 'b>(&'a self) -> TreeItem<'b> {
        TreeItem::new_leaf(self.to_string())
            .style(Style::default().fg(Color::Black).bg(Color::LightYellow))
    }

    pub fn from_bytes(_next_byte: usize, _bytes: &[u8]) -> (Self, usize) {
        let ip_layer = IPv4 {};

        let next_byte = _next_byte;

        (ip_layer, next_byte)
    }
}

impl fmt::Display for IPv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IPv4 Data [Destination: XX | Source: XX]",)
    }
}
