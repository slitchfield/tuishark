use std::fmt;
use std::fs::File;

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

    pub fn hexdump(&self, _window_width: usize) -> String {
        let mut retstr: String = String::new();

        let bytes_per_line = 16; // TODO: Dynamic based on window width

        const ADDRESS_WIDTH: usize = 4;
        const ROW_PREAMBLE_WIDTH: usize = ADDRESS_WIDTH + 2 + 2; // Hex 0x + ": "

        retstr.extend([" "; ROW_PREAMBLE_WIDTH]);
        for i in 0..bytes_per_line {
            retstr += format!("{:02x} ", i).as_str();
        }
        retstr += "\n";

        let num_lines = self.bytes.len() / bytes_per_line;
        for i in 0..num_lines {
            retstr += format!("{:#06X}: ", i * bytes_per_line).as_str();
            for j in 0..bytes_per_line {
                retstr += format!("{:02x} ", self.bytes[i * bytes_per_line + j]).as_str();
            }
            retstr += "\n";
        }

        let leftover_bytes = self.bytes.len() % bytes_per_line;
        if leftover_bytes != 0 {
            retstr += format!("{:#06X}: ", num_lines * bytes_per_line).as_str();
            for i in 0..leftover_bytes {
                retstr += format!("{:02x} ", self.bytes[num_lines * bytes_per_line + i]).as_str();
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
pub struct Packet {
    num: usize,
    pub bytepool: BytePool,
}

impl Packet {
    fn new() -> Self {
        Packet {
            num: 0,
            bytepool: BytePool::new(),
        }
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
