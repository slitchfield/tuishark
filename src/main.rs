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
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem},
    Frame, Terminal,
};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

#[allow(dead_code)]
const MTU: usize = 1500;

#[derive(Clone, Copy, Debug)]
struct BytePool {
    bytes: [u8; MTU],
}

impl BytePool {
    fn new() -> Self {
        BytePool { bytes: [0; MTU] }
    }
}

#[derive(Clone, Copy, Debug)]
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

fn legacy_pcap_to_packet(path: String) -> Vec<Packet> {
    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut num_datablocks: usize = 0;
    let mut reader = pcap_parser::create_reader(65536, file).expect("PcapNGReader");

    let mut ret_vec: Vec<Packet> = vec![];

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                num_blocks += 1;
                match block {
                    pcap_parser::PcapBlockOwned::Legacy(legacyblock) => {
                        let mut pkt = Packet::new();
                        pkt.num = num_datablocks;
                        num_datablocks += 1;
                        pkt.bytepool.bytes[..legacyblock.caplen as usize]
                            .clone_from_slice(legacyblock.data);
                        ret_vec.push(pkt);
                    }
                    pcap_parser::PcapBlockOwned::LegacyHeader(_legacyheader) => {
                        println!("\tLegacy Header");
                    }
                    pcap_parser::PcapBlockOwned::NG(_ng) => {
                        println!("\tNG");
                    }
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

    println!("Got {} blocks in total", num_blocks);

    ret_vec
}

struct TuiSharkApp {
    num: usize,
    pkts: Vec<Packet>,
}

#[allow(dead_code)]
impl TuiSharkApp {
    fn new() -> Self {
        TuiSharkApp {
            num: 0usize,
            pkts: vec![],
        }
    }

    fn load_packets_from_file(&mut self, path: String) {
        self.pkts = legacy_pcap_to_packet(path);
    }

    fn on_tick(&mut self) {}

    fn tickup(&mut self) {
        self.num += 1;
    }

    fn tickdown(&mut self) {
        self.num -= 1;
    }
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

    let num_item = ListItem::new(Spans::from(Span::styled(
        format!("{}", app.num),
        Style::default().add_modifier(Modifier::ITALIC),
    )));
    let packet_view = List::new(vec![num_item])
        .block(Block::default().borders(Borders::ALL).title("Packet View"));

    f.render_widget(packet_view, chunks[0]);

    let bytes_view =
        List::new([]).block(Block::default().borders(Borders::ALL).title("Bytes View"));

    f.render_widget(bytes_view, chunks[1]);
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
                    KeyCode::Up => app.tickup(),
                    KeyCode::Down => app.tickdown(),
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
    let path = "/Users/slitchfield3/reference/ICS-Security-Tools/pcaps/ModbusTCP/ModbusTCP.pcap";
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
