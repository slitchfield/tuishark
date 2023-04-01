use core::fmt;
use tui::style::{Color, Style};
use tui_tree_widget::TreeItem;

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
