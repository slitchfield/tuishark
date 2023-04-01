use core::fmt;
use tui::style::{Color, Style};
use tui_tree_widget::TreeItem;

#[derive(Clone, Debug)]
pub enum Ethertype {
    Unidentified,
}

impl fmt::Display for Ethertype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unidentified => {
                write!(f, "Unidentified")
            }
        }
    }
}

fn mac_to_string(mac_addr_in: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_addr_in[0],
        mac_addr_in[1],
        mac_addr_in[2],
        mac_addr_in[3],
        mac_addr_in[4],
        mac_addr_in[5],
    )
    .to_string()
}

#[derive(Clone, Debug)]
pub struct Ethernet {
    pub destination_mac: [u8; 6],
    pub source_mac: [u8; 6],
    pub ether_type_raw: [u8; 2],
    pub ether_type: Ethertype,
}

#[allow(dead_code)]
impl Ethernet {
    pub fn new() -> Self {
        Ethernet {
            destination_mac: [0; 6],
            source_mac: [0; 6],
            ether_type_raw: [0; 2],
            ether_type: Ethertype::Unidentified,
        }
    }

    pub fn to_tree_item<'a, 'b>(&'a self) -> TreeItem<'b> {
        TreeItem::new_leaf(self.to_string())
            .style(Style::default().fg(Color::Black).bg(Color::LightYellow))
    }

    pub fn from_bytes(_next_byte: usize, bytes: &[u8]) -> (Self, usize) {
        let mut destination_mac: [u8; 6] = [0u8; 6];
        destination_mac.clone_from_slice(&bytes[0..6]);

        let mut source_mac: [u8; 6] = [0u8; 6];
        source_mac.clone_from_slice(&bytes[6..12]);

        let mut ether_type_raw: [u8; 2] = [0u8; 2];
        ether_type_raw.clone_from_slice(&bytes[12..14]);

        // TODO: Handle 802.1q tag value of ethertype. Requires consumption of more bytes
        let ethtypetmp: u32 = (ether_type_raw[0] as u32) * 256 + (ether_type_raw[1] as u32);
        let ether_type = match ethtypetmp {
            _ => Ethertype::Unidentified,
        };

        let ethlayer = Ethernet {
            destination_mac,
            source_mac,
            ether_type_raw,
            ether_type,
        };

        let next_byte = 14usize;

        (ethlayer, next_byte)
    }
}

impl fmt::Display for Ethernet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ethernet Data [Source: {} | Destination: {} | Type: {}]",
            mac_to_string(&self.destination_mac),
            mac_to_string(&self.source_mac),
            self.ether_type
        )
    }
}
