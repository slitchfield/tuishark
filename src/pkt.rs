use std::fmt;
use std::fs::File;

use tui_tree_widget::TreeItem;

#[allow(dead_code)]
pub const MTU: usize = 1500;

#[derive(Clone, Debug)]
pub struct BytePool {
    bytes: Vec<u8>,
}

impl BytePool {
    fn new() -> Self {
        BytePool { bytes: vec![] }
    }

    pub fn hexdump(&self, window_width: usize) -> String {
        const ADDRESS_WIDTH: usize = 4;
        const ROW_PREAMBLE_WIDTH: usize = ADDRESS_WIDTH + 2 + 2; // Hex 0x + ": "

        let useful_space = window_width - ROW_PREAMBLE_WIDTH - 2; // Subtract further 2 for bytes/ascii break
        let maximum_bytes_per_line = useful_space / 4; // "XX " per byte
        let bytes_per_line = (2usize).pow((maximum_bytes_per_line as f32).log2() as u32);

        let mut retstr: String = String::new();
        retstr.extend([" "; ROW_PREAMBLE_WIDTH]);

        for i in 0..bytes_per_line {
            retstr += format!("{:02x} ", i).as_str();
        }
        retstr += "|\n";
        for _ in 0..(ROW_PREAMBLE_WIDTH + bytes_per_line * 4) {
            retstr += "-";
        }
        retstr += "\n";

        let num_lines = self.bytes.len() / bytes_per_line;
        for i in 0..num_lines {
            retstr += format!("{:#06X}| ", i * bytes_per_line).as_str();
            for j in 0..bytes_per_line {
                retstr += format!("{:02x} ", self.bytes[i * bytes_per_line + j]).as_str();
            }
            retstr += "| ";
            for j in 0..bytes_per_line {
                let byte = self.bytes[i * bytes_per_line + j];
                if byte.is_ascii() && !byte.is_ascii_control() {
                    retstr.push(byte as char);
                } else {
                    retstr.push('.');
                }
            }
            retstr += "\n";
        }

        let leftover_bytes = self.bytes.len() % bytes_per_line;
        if leftover_bytes != 0 {
            retstr += format!("{:#06X}| ", num_lines * bytes_per_line).as_str();
            for i in 0..leftover_bytes {
                retstr += format!("{:02x} ", self.bytes[num_lines * bytes_per_line + i]).as_str();
            }
            for _ in 0..bytes_per_line - leftover_bytes {
                retstr += "   ";
            }
            retstr += "| ";
            for j in 0..leftover_bytes {
                let byte = self.bytes[num_lines * bytes_per_line + j];
                if byte.is_ascii() && !byte.is_ascii_control() {
                    retstr.push(byte as char);
                } else {
                    retstr.push('.');
                }
            }
        }

        retstr
    }
}

impl fmt::Display for BytePool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "      00 01 02 03 04 05 06 07")?;
        write!(f, "0x00: ")?;
        for i in 0..8 {
            write!(f, "{:02X} ", self.bytes[i])?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Undecoded {
    start_offset: usize,
    length: usize,
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
        TreeItem::new_leaf(self.to_string())
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

#[derive(Clone, Debug)]
pub enum Layer {
    Undecoded(Undecoded),
}

impl Layer {
    pub fn to_tree_item<'a, 'b>(&'a self) -> TreeItem<'b> {
        match self {
            Layer::Undecoded(inner) => inner.to_tree_item(),
        }
    }
}
impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Layer::Undecoded(layer) => write!(f, "{}", layer)?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Packet {
    num: usize,
    pub bytepool: BytePool,
    pub layers: Vec<Layer>,
}

impl Packet {
    fn new() -> Self {
        Packet {
            num: 0,
            bytepool: BytePool::new(),
            layers: vec![],
        }
    }

    pub fn decode(&mut self) {
        // TODO: fill out current stub
        let num_bytes = self.bytepool.bytes.len();
        self.layers.push(Layer::Undecoded(Undecoded {
            start_offset: 0,
            length: num_bytes,
        }));
    }

    pub fn to_tree_item<'a, 'b>(&'a self) -> TreeItem<'b> {
        TreeItem::new(
            self.to_string(),
            //vec![TreeItem::new_leaf(self.layers[0].to_string())],
            self.layers
                .iter()
                .map(|l| l.to_tree_item())
                .collect::<Vec<TreeItem>>(),
        )
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Packet Num {} [ {}B ]",
            self.num,
            self.bytepool.bytes.len()
        )
    }
}

pub fn legacy_pcap_to_packet(path: String) -> Vec<Packet> {
    let file = File::open(path).unwrap();
    let mut num_datablocks: usize = 0;
    let mut reader = pcap_parser::create_reader(65536, file).expect("PcapNGReader");

    let mut ret_vec: Vec<Packet> = vec![];

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    pcap_parser::PcapBlockOwned::Legacy(legacyblock) => {
                        let mut pkt = Packet::new();
                        pkt.num = num_datablocks;
                        num_datablocks += 1;
                        let pkt_len = legacyblock.caplen as usize;
                        pkt.bytepool.bytes.reserve(pkt_len);
                        pkt.bytepool.bytes.extend_from_slice(legacyblock.data);
                        ret_vec.push(pkt);
                    }
                    pcap_parser::PcapBlockOwned::LegacyHeader(_legacyheader) => {}
                    pcap_parser::PcapBlockOwned::NG(_ng) => {}
                }
                reader.consume(offset);
            }
            Err(pcap_parser::PcapError::Eof) => break,
            Err(pcap_parser::PcapError::Incomplete) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }

    ret_vec
}
