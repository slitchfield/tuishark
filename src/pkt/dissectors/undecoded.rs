use core::fmt;
use tui::style::{Color, Style};
use tui_tree_widget::TreeItem;

use crate::pkt::LayerHint;

#[derive(Clone, Debug)]
pub struct Undecoded {
    pub start_offset: usize,
    pub length: usize,
}

#[allow(dead_code)]
impl Undecoded {
    pub fn new() -> Self {
        Undecoded {
            start_offset: 0,
            length: 0,
        }
    }

    pub fn to_tree_item<'a, 'b>(&'a self) -> TreeItem<'b> {
        TreeItem::new_leaf(self.to_string()).style(Style::default().bg(Color::LightRed))
    }

    pub fn from_bytes(next_byte: usize, bytes: &[u8]) -> (Self, usize, LayerHint) {
        (
            Undecoded {
                start_offset: next_byte,
                length: bytes.len(),
            },
            next_byte + bytes.len(),
            LayerHint::Undecoded,
        )
    }
}

impl fmt::Display for Undecoded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Undecoded Data [Starts: {}, Len: {}]",
            self.start_offset, self.length
        )
    }
}
