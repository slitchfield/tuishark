use core::fmt;
use tui::style::{Color, Style};
use tui_tree_widget::TreeItem;

use crate::pkt::LayerHint;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Tcp {}

#[allow(dead_code)]
impl Tcp {
    pub fn new() -> Self {
        Tcp {}
    }

    #[allow(dead_code)]
    pub fn to_tree_item_verbose<'a, 'b>(&'a self) -> TreeItem<'b> {
        TreeItem::new(self.to_string(), vec![])
            .style(Style::default().fg(Color::Black).bg(Color::LightYellow))
    }

    pub fn to_tree_item<'a, 'b>(&'a self) -> TreeItem<'b> {
        //TreeItem::new_leaf(self.to_string())
        //    .style(Style::default().fg(Color::Black).bg(Color::LightYellow))
        TreeItem::new(self.to_string(), vec![])
            .style(Style::default().fg(Color::Black).bg(Color::LightYellow))
    }

    pub fn from_bytes(next_byte: usize, _bytes: &[u8]) -> (Self, usize, LayerHint) {
        let tcp_layer = Tcp {};

        let ret_next_byte = next_byte;
        let layer_hint = LayerHint::Undecoded;

        (tcp_layer, ret_next_byte, layer_hint)
    }
}

impl fmt::Display for Tcp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP Data",)
    }
}
