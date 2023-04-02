use core::fmt;
use tui::style::{Color, Style};
use tui_tree_widget::TreeItem;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct IPv4 {
    version: u8,
    header_len: u8,
    diffserv: u8,
    congestion_notification: u8,
    total_length: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    header_xsum: u16,
    source_addr: [u8; 4],
    dest_addr: [u8; 4],
}

fn ipaddr_to_string(bytes: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

#[allow(dead_code)]
impl IPv4 {
    pub fn new() -> Self {
        IPv4 {
            version: 0,
            header_len: 0,
            diffserv: 0,
            congestion_notification: 0,
            total_length: 0,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 0,
            protocol: 0,
            header_xsum: 0,
            source_addr: [0; 4],
            dest_addr: [0; 4],
        }
    }

    #[allow(dead_code)]
    pub fn to_tree_item_verbose<'a, 'b>(&'a self) -> TreeItem<'b> {
        TreeItem::new(
            self.to_string(),
            vec![
                TreeItem::new_leaf(format!("Version: {}", self.version)),
                TreeItem::new_leaf(format!(
                    "Header Length: {} bytes ({})",
                    4 * self.header_len,
                    self.header_len
                )),
            ],
        )
        .style(Style::default().fg(Color::Black).bg(Color::LightYellow))
    }

    pub fn to_tree_item<'a, 'b>(&'a self) -> TreeItem<'b> {
        //TreeItem::new_leaf(self.to_string())
        //    .style(Style::default().fg(Color::Black).bg(Color::LightYellow))
        TreeItem::new(
            self.to_string(),
            vec![
                TreeItem::new_leaf(format!("Version: {}", self.version)),
                TreeItem::new_leaf(format!(
                    "Header Length: {} bytes ({})",
                    4 * self.header_len,
                    self.header_len
                )),
                TreeItem::new_leaf(format!(
                    "Differentiated Services Field: {:#04X}",
                    self.diffserv
                )),
                TreeItem::new_leaf(format!("Total Length: {}", self.total_length)),
                TreeItem::new_leaf(format!("Identification: {:#06x}", self.identification)),
                TreeItem::new_leaf(format!("Flags: {:#06x}", self.flags)),
                TreeItem::new_leaf(format!("Time to live: {}", self.ttl)),
                TreeItem::new_leaf(format!("Protocol: {}", self.protocol)),
                TreeItem::new_leaf(format!("Header checksum: {:#06x}", self.header_xsum)),
                TreeItem::new_leaf(format!("Source: {}", ipaddr_to_string(&self.source_addr))),
                TreeItem::new_leaf(format!("Destination: {}", ipaddr_to_string(&self.dest_addr))),

            ],
        )
        .style(Style::default().fg(Color::Black).bg(Color::LightYellow))
    }

    pub fn from_bytes(next_byte: usize, bytes: &[u8]) -> (Self, usize) {
        assert!(bytes.len() >= 20);
        let version = (bytes[0] >> 4) & 0x0f;
        let header_len = bytes[0] & 0x0f;
        let diffserv = (bytes[1] >> 2) & 0x3f;
        let congestion_notification = bytes[1] & 0x03;
        let total_length = (256u16 * bytes[2] as u16) + bytes[3] as u16;
        let identification = (256u16 * bytes[4] as u16) + bytes[5] as u16;
        let flags = (bytes[6] >> 5) & 0x07;
        let fragment_offset = (256u16 * (bytes[6] & 0x1f) as u16) + bytes[7] as u16;
        let ttl = bytes[8];
        let protocol = bytes[9];
        let header_xsum = (256u16 * bytes[10] as u16) + bytes[11] as u16;
        let mut source_addr: [u8; 4] = [0; 4];
        source_addr.clone_from_slice(&bytes[12..16]);
        let mut dest_addr: [u8; 4] = [0; 4];
        dest_addr.clone_from_slice(&bytes[16..20]);
        //TODO: Parse Options!

        let ip_layer = IPv4 {
            version,
            header_len,
            diffserv,
            congestion_notification,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            header_xsum,
            source_addr,
            dest_addr,
        };

        let ret_next_byte = next_byte + 4usize * (ip_layer.header_len as usize);

        (ip_layer, ret_next_byte)
    }
}

impl fmt::Display for IPv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Internet Protocol Version 4, Src: {}, Dst: {}",
            ipaddr_to_string(&self.source_addr),
            ipaddr_to_string(&self.dest_addr)
        )
    }
}
