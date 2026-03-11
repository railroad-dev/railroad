mod app;
mod ui;

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::prelude::*;

use crate::trace;

/// Run the session replay TUI.
pub fn run(session_id: &str) -> i32 {
    let trace_dir = trace::logger::global_trace_dir();

    match trace::logger::read_traces(&trace_dir, session_id) {
        Ok(entries) => {
            if entries.is_empty() {
                eprintln!("No traces found for session {}", session_id);
                return 1;
            }
            match run_tui(session_id, entries) {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("Replay error: {}", e);
                    1
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read traces: {}", e);
            1
        }
    }
}

fn run_tui(session_id: &str, entries: Vec<crate::types::TraceEntry>) -> io::Result<()> {
    // Restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = app::ReplayApp::new(session_id.to_string(), entries);

    loop {
        terminal.draw(|f| ui::draw(f, &mut app))?;

        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
                    KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
                    KeyCode::Char('G') => app.jump_to_end(),
                    KeyCode::Char('g') => app.jump_to_start(),
                    KeyCode::Enter => app.toggle_detail(),
                    KeyCode::Char('?') => app.show_help = !app.show_help,
                    _ => {}
                },
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
