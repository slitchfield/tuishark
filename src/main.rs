use core::fmt;
use std::{
    fs::File,
    io,
    time::{Duration, Instant},
};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Span, Spans, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

// High level TODO list
// - Change stateful list to a tree-based structure to support packet substructure
//   - see github.com/EdJoPaTo/tui-rs-tree-widget.git
// - Format byte field a la hexdump
// - Add "Unparsed Data" as pkt layer type

#[allow(dead_code)]
const MTU: usize = 1500;

#[derive(Clone, Debug)]
struct BytePool {
    bytes: Vec<u8>,
}

impl BytePool {
    fn new() -> Self {
        BytePool { bytes: vec![] }
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
struct Packet {
    num: usize,
    bytepool: BytePool,
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

fn legacy_pcap_to_packet(path: String) -> Vec<Packet> {
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

struct StatefulList<T> {
    state: ListState,
    items: Vec<T>,
}

impl<T> StatefulList<T> {
    fn with_items(items: Vec<T>) -> StatefulList<T> {
        StatefulList {
            state: ListState::default(),
            items,
        }
    }

    fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn prev(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn unselect(&mut self) {
        self.state.select(None);
    }
}

struct TuiSharkApp {
    num: usize,
    pkts: StatefulList<Packet>,
}

#[allow(dead_code)]
impl TuiSharkApp {
    fn new() -> Self {
        TuiSharkApp {
            num: 0usize,
            pkts: StatefulList::with_items(vec![]),
        }
    }

    fn load_packets_from_file(&mut self, path: String) {
        self.pkts = StatefulList::with_items(legacy_pcap_to_packet(path));
    }

    fn on_tick(&mut self) {}
}

impl fmt::Display for TuiSharkApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TuiSharkApp [ num: {} ]", self.num)
    }
}

fn ui<B: Backend>(f: &mut Frame<B>, app: &mut TuiSharkApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(80), Constraint::Percentage(20)].as_ref())
        .split(f.size());

    let mut item_vec: Vec<ListItem> = vec![];
    for pkt in &app.pkts.items {
        let pkt_item = ListItem::new(Spans::from(Span::styled(
            format!("{}", pkt),
            Style::default().add_modifier(Modifier::ITALIC),
        )));
        item_vec.push(pkt_item);
    }

    let packet_view = List::new(item_vec)
        .block(Block::default().borders(Borders::ALL).title("Packet View"))
        .highlight_style(
            Style::default()
                .bg(tui::style::Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(packet_view, chunks[0], &mut app.pkts.state);

    let byte_text = match app.pkts.state.selected() {
        Some(i) => {
            let bytepool = &app.pkts.items[i].bytepool;
            Text::from(bytepool.to_string())
        }
        None => Text::from(""),
    };

    let bytes_paragraph = Paragraph::new(byte_text)
        .block(Block::default().title("Byte View").borders(Borders::ALL))
        .style(Style::default())
        .alignment(tui::layout::Alignment::Left)
        .wrap(Wrap { trim: false });

    f.render_widget(bytes_paragraph, chunks[1]);
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    mut app: TuiSharkApp,
    tick_rate: Duration,
) -> io::Result<()> {
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Up => app.pkts.prev(),
                    KeyCode::Down => app.pkts.next(),
                    KeyCode::Left => app.pkts.unselect(),
                    KeyCode::Char('q') => return Ok(()),
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.on_tick();
            last_tick = Instant::now();
        }
    }
}

fn main() -> Result<(), io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let tick_rate = Duration::from_millis(250);
    let mut app = TuiSharkApp::new();
    //let path = "/Users/slitchfield3/reference/ICS-Security-Tools/pcaps/ModbusTCP/ModbusTCP.pcap";
    let path = "C:/Users/samue/Documents/Github/ICS-Security-Tools/pcaps/ModbusTCP/ModbusTCP.pcap";
    app.load_packets_from_file(path.to_string());
    let res = run_app(&mut terminal, app, tick_rate);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    } else {
        println!("Ok! Done and exiting...")
    }

    Ok(())
}
