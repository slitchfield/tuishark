use core::fmt;
use tui::style::{Color, Style};
use tui_tree_widget::TreeItem;

use crate::pkt::dissectors::util;
use crate::pkt::LayerHint;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Tcp {
    source_port: u16,
    dest_port: u16,
    sequence_num: u32,
    ack_num: u32,
    header_len: u8,
    resrv_0: u8,
    flags: u8,
    window_size: u16,
    tcp_xsum: u16,
    urg_ptr: u16,
}

#[allow(dead_code)]
impl Tcp {
    pub fn new() -> Self {
        Tcp {
            source_port: 0,
            dest_port: 0,
            sequence_num: 0,
            ack_num: 0,
            header_len: 0,
            resrv_0: 0,
            flags: 0,
            window_size: 0,
            tcp_xsum: 0,
            urg_ptr: 0,
        }
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

    pub fn from_bytes(next_byte: usize, bytes: &[u8]) -> (Self, usize, LayerHint) {
        assert!(bytes.len() >= 20);
        let source_port = util::two_bytes_to_u16(&bytes[0..2]);
        let dest_port = util::two_bytes_to_u16(&bytes[2..4]);
        let sequence_num = util::four_bytes_to_u32(&bytes[4..8]);
        let ack_num = util::four_bytes_to_u32(&bytes[8..12]);

        let header_len = (bytes[12] & 0xf0u8) >> 4;
        let resrv_0 = bytes[12] & 0x0fu8;

        let flags = bytes[13];
        let window_size = util::two_bytes_to_u16(&bytes[14..16]);
        let tcp_xsum = util::two_bytes_to_u16(&bytes[16..18]);
        let urg_ptr = util::two_bytes_to_u16(&bytes[18..20]);

        // TODO: Parse options:
        let tcp_layer = Tcp {
            source_port,
            dest_port,
            sequence_num,
            ack_num,
            header_len,
            resrv_0,
            flags,
            window_size,
            tcp_xsum,
            urg_ptr,
        };

        let calculated_header_len = tcp_layer.header_len * 4;
        let ret_next_byte = next_byte + calculated_header_len as usize;
        let layer_hint = LayerHint::Undecoded;

        (tcp_layer, ret_next_byte, layer_hint)
    }
}

impl fmt::Display for Tcp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Transmission Control Protocol, Src Port: {}, Dst Port: {}, Seq: {}, Ack: {}, Len: xx",
            self.source_port, self.dest_port, self.sequence_num, self.ack_num,
        )
    }
}
