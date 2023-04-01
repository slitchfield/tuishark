mod pkt;
use crate::pkt::{legacy_pcap_to_packet, Packet};

mod statefultree;
use crate::statefultree::StatefulTree;

use core::fmt;
use std::{
    io,
    time::{Duration, Instant},
};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::Text,
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};
use tui_tree_widget::Tree;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

// High level TODO list
// - Parse Ethernet Header

struct TuiSharkApp<'a> {
    raw_pkts: Vec<Packet>,
    pkt_tree: StatefulTree<'a>,
}

#[allow(dead_code)]
impl<'a> TuiSharkApp<'a> {
    fn new() -> Self {
        TuiSharkApp {
            raw_pkts: vec![],
            pkt_tree: StatefulTree::with_items(vec![]),
        }
    }

    fn load_packets_from_file(&mut self, path: String) {
        self.raw_pkts = legacy_pcap_to_packet(path);

        for pkt in &mut self.raw_pkts {
            pkt.decode();
        }

        self.pkt_tree =
            StatefulTree::with_items(self.raw_pkts.iter().map(|p| p.to_tree_item()).collect());
    }
}

impl fmt::Display for TuiSharkApp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TuiSharkApp")
    }
}

fn ui<B: Backend>(f: &mut Frame<B>, app: &mut TuiSharkApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(80), Constraint::Percentage(20)].as_ref())
        .split(f.size());

    let packet_view = Tree::new(app.pkt_tree.items.clone())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Packet View {:?}", app.pkt_tree.state)),
        )
        .highlight_style(
            Style::default()
                .fg(tui::style::Color::Black)
                .bg(tui::style::Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(packet_view, chunks[0], &mut app.pkt_tree.state);

    let byte_text = if app.pkt_tree.state.selected().is_empty() {
        Text::from("")
    } else {
        let idx = app.pkt_tree.state.selected()[0];
        let bytepool = &app.raw_pkts[idx].bytepool;
        let window_width = chunks[1].width - 2;
        Text::from(bytepool.hexdump(window_width as usize))
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
                    KeyCode::Left => app.pkt_tree.left(),
                    KeyCode::Right => app.pkt_tree.right(),
                    KeyCode::Down => app.pkt_tree.down(),
                    KeyCode::Up => app.pkt_tree.up(),

                    KeyCode::Char('q') => return Ok(()),
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
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
