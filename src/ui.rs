//! Rendering. Colors come straight from the active `cybercore` theme
//! (`schema::load().palette`) rather than hardcoded RGB constants, so
//! this respects `CYBERGRID_THEME` like every other cybercore-aware tool.

use crate::app::{App, Mode};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

struct Theme {
    purple: Color,
    cyan: Color,
    acid_green: Color,
    hot_pink: Color,
    red: Color,
    muted: Color,
    line: Color,
    white: Color,
}

fn hex_to_color(hex: &str) -> Color {
    let hex = hex.trim_start_matches('#');
    let r = u8::from_str_radix(hex.get(0..2).unwrap_or("ff"), 16).unwrap_or(255);
    let g = u8::from_str_radix(hex.get(2..4).unwrap_or("ff"), 16).unwrap_or(255);
    let b = u8::from_str_radix(hex.get(4..6).unwrap_or("ff"), 16).unwrap_or(255);
    Color::Rgb(r, g, b)
}

impl Theme {
    fn load() -> Self {
        let p = &cybercore::schema::load().palette;
        Self {
            purple: hex_to_color(&p.purple),
            cyan: hex_to_color(&p.cyan),
            acid_green: hex_to_color(&p.acid_green),
            hot_pink: hex_to_color(&p.hot_pink),
            red: hex_to_color(&p.red),
            muted: hex_to_color(&p.muted),
            line: hex_to_color(&p.line),
            white: hex_to_color(&p.white),
        }
    }
}

pub fn draw(frame: &mut Frame, app: &App) {
    let theme = Theme::load();
    let has_input = matches!(
        app.mode,
        Mode::Filter | Mode::AddLabel | Mode::AddSecret | Mode::AddNote | Mode::GenPasswordLength | Mode::GenPassphraseWords
    );

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(if has_input { 3 } else { 0 }),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame.area());

    draw_title(frame, &theme, app, chunks[0]);
    if has_input {
        draw_input_line(frame, &theme, app, chunks[1]);
    }

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(chunks[2]);
    draw_list(frame, &theme, app, body[0]);
    draw_detail(frame, &theme, app, body[1]);

    draw_footer(frame, &theme, app, chunks[3]);
}

fn draw_title(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let count = app.data.entries.len();
    let title = Line::from(vec![
        Span::styled(" CYBERVAULT ", Style::default().fg(theme.purple).add_modifier(Modifier::BOLD)),
        Span::styled(format!("— {count} entr{} ", if count == 1 { "y" } else { "ies" }), Style::default().fg(theme.muted)),
    ]);
    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme.line));
    frame.render_widget(Paragraph::new(title).block(block), area);
}

fn draw_input_line(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let (label, masked): (String, bool) = match app.mode {
        Mode::Filter => ("filter".to_string(), false),
        Mode::AddLabel => ("label".to_string(), false),
        Mode::AddSecret => ("secret — ctrl+g generate password, ctrl+p generate passphrase".to_string(), true),
        Mode::GenPasswordLength => (format!("password length, 4-128 chars{}", preview_suffix(app)), false),
        Mode::GenPassphraseWords => (format!("passphrase word count, 3-12{}", preview_suffix(app)), false),
        Mode::AddNote => ("note (optional)".to_string(), false),
        Mode::Normal | Mode::ConfirmRemove => unreachable!(),
    };
    let shown = if masked { "*".repeat(app.input_buffer.chars().count()) } else { app.input_buffer.clone() };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.cyan))
        .title(Span::styled(format!(" {label} "), Style::default().fg(theme.cyan)));
    frame.render_widget(Paragraph::new(format!("{shown}_")).block(block), area);
}

/// " — ~155 bits (Very Strong)"-style suffix for the generate-options
/// prompts, live as the user types a length/word count. Empty while the
/// field doesn't parse to a valid number yet.
fn preview_suffix(app: &App) -> String {
    match app.gen_options_preview() {
        Some((bits, label)) => format!(" — ~{} bits ({label})", bits.round()),
        None => String::new(),
    }
}

fn draw_list(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let selected_idx = app.list_state.selected();
    let items: Vec<ListItem> = app
        .filtered
        .iter()
        .enumerate()
        .map(|(row, &idx)| {
            let label = app.labels[idx].clone();
            let style = if Some(row) == selected_idx {
                Style::default().fg(theme.acid_green).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.white)
            };
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.line))
        .title(Span::styled(" labels ", Style::default().fg(theme.muted)));

    let list = List::new(items).block(block).highlight_symbol("> ");
    let mut state = app.list_state.clone();
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_detail(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.line))
        .title(Span::styled(" detail ", Style::default().fg(theme.muted)));

    let lines: Vec<Line> = match app.selected_entry() {
        Some((label, entry)) => {
            let revealed = app.revealed.as_deref() == Some(label);
            let secret_line = if revealed {
                Line::from(vec![
                    Span::styled("secret   ", Style::default().fg(theme.muted)),
                    Span::styled(entry.secret.clone(), Style::default().fg(theme.hot_pink)),
                ])
            } else {
                Line::from(vec![
                    Span::styled("secret   ", Style::default().fg(theme.muted)),
                    Span::styled("•".repeat(entry.secret.chars().count().min(32)), Style::default().fg(theme.muted)),
                    Span::styled("  (v to reveal)", Style::default().fg(theme.muted)),
                ])
            };
            vec![
                Line::from(vec![Span::styled("label    ", Style::default().fg(theme.muted)), Span::styled(label.to_string(), Style::default().fg(theme.cyan).add_modifier(Modifier::BOLD))]),
                Line::from(vec![Span::styled("created  ", Style::default().fg(theme.muted)), Span::raw(entry.created.clone())]),
                Line::from(vec![Span::styled("note     ", Style::default().fg(theme.muted)), Span::raw(entry.note.clone().unwrap_or_default())]),
                Line::from(""),
                secret_line,
            ]
        }
        None => vec![Line::from(Span::styled("(no entry selected — 'a' to add one)", Style::default().fg(theme.muted)))],
    };

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_footer(frame: &mut Frame, theme: &Theme, app: &App, area: Rect) {
    let text = if let Some(status) = &app.status {
        Line::from(Span::styled(status.clone(), Style::default().fg(theme.acid_green)))
    } else {
        match app.mode {
            Mode::Normal => Line::from(Span::styled(
                "j/k move  /filter  v reveal  c copy  a add  d delete  q quit",
                Style::default().fg(theme.muted),
            )),
            Mode::ConfirmRemove => Line::from(Span::styled("remove this entry? y/n", Style::default().fg(theme.red))),
            Mode::AddSecret => Line::from(Span::styled(
                "enter confirm  esc cancel  ctrl+g generate password  ctrl+p generate passphrase",
                Style::default().fg(theme.muted),
            )),
            Mode::GenPasswordLength | Mode::GenPassphraseWords => {
                Line::from(Span::styled("enter generate  esc cancel (keeps what you had)", Style::default().fg(theme.muted)))
            }
            Mode::Filter | Mode::AddLabel | Mode::AddNote => {
                Line::from(Span::styled("enter confirm  esc cancel", Style::default().fg(theme.muted)))
            }
        }
    };
    frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), area);
}
