use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, BorderType, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap};

use super::app::ReplayApp;

const GREEN: Color = Color::Green;
const YELLOW: Color = Color::Yellow;
const RED: Color = Color::Red;
const CYAN: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;
const TEXT: Color = Color::Reset;

pub fn draw(f: &mut Frame, app: &mut ReplayApp) {
    let area = f.area();

    let summary = app.summary();

    // Layout: header, timeline (+ optional detail), status bar
    let has_detail = app.detail_view && !app.entries.is_empty();

    let constraints = if has_detail {
        vec![
            Constraint::Length(2), // header
            Constraint::Percentage(60), // timeline
            Constraint::Percentage(40), // detail
            Constraint::Length(1), // status bar
        ]
    } else {
        vec![
            Constraint::Length(2), // header
            Constraint::Min(5),   // timeline
            Constraint::Length(1), // status bar
        ]
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    draw_header(f, app, &summary, chunks[0]);

    if has_detail {
        draw_timeline(f, app, chunks[1]);
        draw_detail(f, app, chunks[2]);
        draw_status_bar(f, &summary, chunks[3]);
    } else {
        draw_timeline(f, app, chunks[1]);
        draw_status_bar(f, &summary, chunks[2]);
    }

    if app.show_help {
        draw_help_overlay(f, area);
    }
}

fn draw_header(f: &mut Frame, app: &ReplayApp, summary: &super::app::ReplaySummary, area: Rect) {
    let short_id = if app.session_id.len() > 8 {
        &app.session_id[..8]
    } else {
        &app.session_id
    };

    let line1 = Line::from(vec![
        Span::styled(" replay", Style::default().fg(TEXT).bold()),
        Span::styled(
            format!(
                " \u{2500}\u{2500} session {} \u{2500}\u{2500} {} calls \u{2500}\u{2500} {} \u{2500}\u{2500} {} files touched",
                short_id, summary.total, summary.duration, summary.files_touched
            ),
            Style::default().fg(DIM),
        ),
    ]);

    let line2 = Line::from(vec![
        Span::styled(
            format!("  {} \u{2713} allowed", summary.allowed),
            Style::default().fg(GREEN),
        ),
        Span::styled("   ", Style::default().fg(DIM)),
        Span::styled(
            format!("{} \u{25cf} approved", summary.approved),
            Style::default().fg(YELLOW),
        ),
        Span::styled("   ", Style::default().fg(DIM)),
        Span::styled(
            format!("{} \u{2717} blocked", summary.blocked),
            Style::default().fg(RED),
        ),
    ]);

    let header = Paragraph::new(vec![line1, line2]);
    f.render_widget(header, area);
}

fn draw_timeline(f: &mut Frame, app: &mut ReplayApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::TOP | Borders::BOTTOM)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(DIM));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut items: Vec<ListItem> = Vec::new();

    for (idx, entry) in app.entries.iter().enumerate() {
        let (icon, icon_color) = match entry.decision.as_str() {
            "allow" | "completed" => ("\u{2713}", GREEN),
            "approve" | "warn" => ("\u{25cf}", YELLOW),
            "block" => ("\u{2717}", RED),
            _ => ("?", DIM),
        };

        let time = extract_time(&entry.timestamp);

        // Relative timestamp from first entry
        let relative = if idx > 0 {
            if let (Ok(first), Ok(current)) = (
                chrono::DateTime::parse_from_rfc3339(&app.entries[0].timestamp),
                chrono::DateTime::parse_from_rfc3339(&entry.timestamp),
            ) {
                let secs = current.signed_duration_since(first).num_seconds().max(0);
                format!("+{}s", secs)
            } else {
                time.clone()
            }
        } else {
            "start".to_string()
        };

        let tool_display = format!("{:<6}", if entry.tool.len() > 6 {
            &entry.tool[..6]
        } else {
            &entry.tool
        });

        // Truncate input
        let max_input = (inner.width as usize).saturating_sub(35);
        let input = if entry.input_summary.len() > max_input {
            format!("{}...", &entry.input_summary[..max_input.saturating_sub(3)])
        } else {
            entry.input_summary.clone()
        };

        let rule_suffix = entry.rule.as_deref()
            .map(|r| format!(" \u{2500} {}", r))
            .unwrap_or_default();

        let marker = if idx == app.selected { "\u{25b6} " } else { "  " };

        let spans = vec![
            Span::styled(marker, Style::default().fg(CYAN)),
            Span::styled(format!("{} ", icon), Style::default().fg(icon_color).bold()),
            Span::styled(format!("{:<8} ", relative), Style::default().fg(DIM)),
            Span::styled(format!("{} ", tool_display), Style::default().fg(CYAN)),
            Span::styled(input, Style::default().fg(TEXT)),
            Span::styled(rule_suffix, Style::default().fg(DIM)),
        ];

        items.push(ListItem::new(Line::from(spans)));
    }

    let list = List::new(items)
        .highlight_style(Style::default().bg(Color::Rgb(30, 30, 40)));
    let mut list_state = ListState::default();
    list_state.select(Some(app.selected));

    f.render_stateful_widget(list, inner, &mut list_state);
}

fn draw_detail(f: &mut Frame, app: &ReplayApp, area: Rect) {
    let block = Block::default()
        .title(" detail ")
        .title_style(Style::default().fg(TEXT).bold())
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(DIM))
        .padding(Padding::horizontal(1));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.entries.is_empty() {
        return;
    }

    let entry = &app.entries[app.selected];

    let mut lines = vec![
        Line::from(vec![
            Span::styled("event:    ", Style::default().fg(CYAN)),
            Span::styled(&entry.event, Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("tool:     ", Style::default().fg(CYAN)),
            Span::styled(&entry.tool, Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("decision: ", Style::default().fg(CYAN)),
            Span::styled(&entry.decision, Style::default().fg(match entry.decision.as_str() {
                "allow" | "completed" => GREEN,
                "approve" | "warn" => YELLOW,
                "block" => RED,
                _ => TEXT,
            })),
        ]),
        Line::from(vec![
            Span::styled("time:     ", Style::default().fg(CYAN)),
            Span::styled(&entry.timestamp, Style::default().fg(DIM)),
        ]),
        Line::from(vec![
            Span::styled("latency:  ", Style::default().fg(CYAN)),
            Span::styled(format!("{}ms", entry.duration_ms), Style::default().fg(DIM)),
        ]),
    ];

    if let Some(ref rule) = entry.rule {
        lines.push(Line::from(vec![
            Span::styled("rule:     ", Style::default().fg(CYAN)),
            Span::styled(rule, Style::default().fg(YELLOW)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("input:", Style::default().fg(CYAN)),
    ]));

    // Word-wrap the input summary
    let width = inner.width.saturating_sub(2) as usize;
    let input = &entry.input_summary;
    for chunk in input.as_bytes().chunks(width.max(1)) {
        if let Ok(s) = std::str::from_utf8(chunk) {
            lines.push(Line::from(Span::styled(
                format!("  {}", s),
                Style::default().fg(TEXT),
            )));
        }
    }

    let detail = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(detail, inner);
}

fn draw_status_bar(f: &mut Frame, _summary: &super::app::ReplaySummary, area: Rect) {
    let status = Line::from(vec![
        Span::styled(
            "  j/k: navigate   Enter: toggle detail   ?: help   q: quit",
            Style::default().fg(DIM),
        ),
    ]);
    f.render_widget(Paragraph::new(status), area);
}

fn draw_help_overlay(f: &mut Frame, area: Rect) {
    let help_width = 42u16;
    let help_height = 12u16;
    let x = area.width.saturating_sub(help_width) / 2;
    let y = area.height.saturating_sub(help_height) / 2;
    let help_area = Rect::new(x, y, help_width.min(area.width), help_height.min(area.height));

    f.render_widget(Clear, help_area);

    let help_text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  j/k     ", Style::default().fg(CYAN)),
            Span::raw("navigate timeline"),
        ]),
        Line::from(vec![
            Span::styled("  G       ", Style::default().fg(CYAN)),
            Span::raw("jump to end"),
        ]),
        Line::from(vec![
            Span::styled("  g       ", Style::default().fg(CYAN)),
            Span::raw("jump to start"),
        ]),
        Line::from(vec![
            Span::styled("  Enter   ", Style::default().fg(CYAN)),
            Span::raw("toggle detail panel"),
        ]),
        Line::from(vec![
            Span::styled("  ?       ", Style::default().fg(CYAN)),
            Span::raw("toggle help"),
        ]),
        Line::from(vec![
            Span::styled("  q       ", Style::default().fg(CYAN)),
            Span::raw("quit"),
        ]),
        Line::from(""),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .title(" keybindings ")
                .title_style(Style::default().fg(TEXT).bold())
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(DIM))
                .padding(Padding::horizontal(1)),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(help, help_area);
}

fn extract_time(timestamp: &str) -> String {
    if let Some(t_pos) = timestamp.find('T') {
        let after_t = &timestamp[t_pos + 1..];
        if after_t.len() >= 8 {
            return after_t[..8].to_string();
        }
    }
    timestamp.to_string()
}
