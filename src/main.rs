mod app;
mod clipboard;
mod crypto;
mod keysmith_gen;
mod ui;
mod vault;

use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use vault::{Entry, VaultData};

#[derive(Parser, Debug)]
#[command(name = "cybervault", version = "0.1.0", about = "Encrypted secrets vault")]
struct Args {
    /// Bare invocation (no subcommand) launches the interactive TUI.
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to the vault file. Defaults to ~/.local/share/cybervault/vault.cvlt.
    #[arg(long, global = true)]
    path: Option<PathBuf>,

    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new, empty vault. Prompts for the master password twice
    /// (confirmation) and refuses to overwrite an existing vault.
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Add or overwrite an entry. Reads the secret from stdin if it's
    /// piped (e.g. from Keysmith), otherwise prompts for it interactively
    /// (hidden input).
    Add {
        label: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Print (or copy) one entry's secret.
    Get {
        label: String,
        /// Copy to the clipboard via wl-copy instead of printing.
        #[arg(long)]
        copy: bool,
    },
    /// List every label, creation date, and note — never the secrets
    /// themselves. Safe to run without exposing everything at once.
    List,
    /// Remove an entry.
    Remove { label: String },
}

fn default_vault_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    PathBuf::from(home).join(".local/share/cybervault/vault.cvlt")
}

fn banner(color_on: bool) {
    let (c, r) = if color_on { (cybercore::palette::purple(), cybercore::palette::RESET) } else { (String::new(), "") };
    println!(
        "{c}
   ___      _              __     __         _ _
  / __\\   _| |__   ___ _ _\\ \\   / /_ _ _   _| | |_
 / / | | | | '_ \\ / _ \\ '__\\ \\ / / _` | | | | | __|
/ /__| |_| | |_) |  __/ |   \\ V / (_| | |_| | | |_
\\____/\\__, |_.__/ \\___|_|    \\_/ \\__,_|\\__,_|_|\\__|
      |___/{r}"
    );
    println!("  » Encrypted secrets vault\n");
}

fn read_master_password(confirm: bool) -> Result<String, String> {
    let pw = rpassword::prompt_password("Master password: ").map_err(|e| e.to_string())?;
    if confirm {
        let confirm_pw = rpassword::prompt_password("Confirm master password: ").map_err(|e| e.to_string())?;
        if pw != confirm_pw {
            return Err("passwords did not match".to_string());
        }
    }
    Ok(pw)
}

/// Reads the secret to store: from stdin if it's piped (not a TTY — the
/// path Keysmith's `--save` uses), otherwise an interactive hidden prompt.
fn read_secret_to_store() -> Result<String, String> {
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Secret to store: ").map_err(|e| e.to_string())
    } else {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).map_err(|e| e.to_string())?;
        Ok(buf.trim_end_matches(['\n', '\r']).to_string())
    }
}

pub fn today() -> String {
    Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown-date".to_string())
}

/// Unlocks the vault and runs the interactive TUI. Password entry and
/// the initial load happen *before* raw mode / the alternate screen are
/// entered, so a wrong password or a missing/corrupt vault fails with a
/// normal, readable terminal error instead of garbling the screen.
fn run_tui(path: PathBuf, color_on: bool) -> ExitCode {
    banner(color_on);

    if !path.exists() {
        eprintln!("cybervault: no vault at {} — run `cybervault init` first", path.display());
        return ExitCode::FAILURE;
    }
    let password = match read_master_password(false) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cybervault: {e}");
            return ExitCode::FAILURE;
        }
    };
    let data = match vault::load(&path, &password) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cybervault: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut app = app::App::new(path, password, data);
    let tui_result = (|| -> io::Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let run_result = run_event_loop(&mut terminal, &mut app);

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;
        run_result
    })();

    match tui_result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cybervault: TUI error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_event_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut app::App) -> io::Result<()> {
    loop {
        terminal.draw(|frame| ui::draw(frame, app))?;

        if app.should_quit {
            return Ok(());
        }

        if let Event::Key(key) = event::read()? {
            // Any keypress clears a one-shot status message from the
            // previous action rather than leaving it stuck on screen;
            // a handler below may set a fresh one for this action.
            app.status = None;
            match app.mode {
                app::Mode::Normal => handle_normal(app, key.code),
                app::Mode::Filter => handle_filter(app, key.code),
                app::Mode::AddLabel | app::Mode::AddSecret | app::Mode::AddNote => handle_add(app, key),
                app::Mode::ConfirmRemove => handle_confirm_remove(app, key.code),
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

fn handle_normal(app: &mut app::App, code: KeyCode) {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('j') | KeyCode::Down => app.next(),
        KeyCode::Char('k') | KeyCode::Up => app.previous(),
        KeyCode::Char('/') => {
            app.filter_text.clear();
            app.input_buffer.clear();
            app.mode = app::Mode::Filter;
        }
        KeyCode::Char('v') | KeyCode::Enter => app.toggle_reveal(),
        KeyCode::Char('c') => app.copy_selected(),
        KeyCode::Char('a') => app.begin_add(),
        KeyCode::Char('d') => {
            if app.selected_entry().is_some() {
                app.mode = app::Mode::ConfirmRemove;
            }
        }
        _ => {}
    }
}

fn handle_filter(app: &mut app::App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.filter_text.clear();
            app.input_buffer.clear();
            app.apply_filter();
            app.mode = app::Mode::Normal;
        }
        KeyCode::Enter => app.mode = app::Mode::Normal,
        KeyCode::Backspace => {
            app.input_buffer.pop();
            app.filter_text = app.input_buffer.clone();
            app.apply_filter();
        }
        KeyCode::Char(c) => {
            app.input_buffer.push(c);
            app.filter_text = app.input_buffer.clone();
            app.apply_filter();
        }
        _ => {}
    }
}

fn handle_add(app: &mut app::App, key: KeyEvent) {
    // Ctrl+G / Ctrl+P generate a password/passphrase via Keysmith, but
    // only while typing the secret itself — checked before the generic
    // Char(c) arm below so a plain 'g'/'p' still types normally in the
    // label/note steps (and as part of a manually-typed secret elsewhere
    // in this same step, since those two are Ctrl-modified here).
    if app.mode == app::Mode::AddSecret && key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('g') => {
                app.generate_secret(keysmith_gen::Kind::Password);
                return;
            }
            KeyCode::Char('p') => {
                app.generate_secret(keysmith_gen::Kind::Passphrase);
                return;
            }
            _ => {}
        }
    }
    match key.code {
        KeyCode::Esc => app.cancel_add(),
        KeyCode::Enter => match app.mode {
            app::Mode::AddLabel => app.confirm_label(),
            app::Mode::AddSecret => app.confirm_secret(),
            app::Mode::AddNote => app.confirm_note_and_save(),
            _ => {}
        },
        KeyCode::Backspace => {
            app.input_buffer.pop();
        }
        KeyCode::Char(c) => app.input_buffer.push(c),
        _ => {}
    }
}

fn handle_confirm_remove(app: &mut app::App, code: KeyCode) {
    match code {
        KeyCode::Char('y') | KeyCode::Char('Y') => app.remove_selected(),
        _ => app.mode = app::Mode::Normal,
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    let color_on = !args.no_color;
    let path = args.path.unwrap_or_else(default_vault_path);

    let Some(command) = args.command else {
        return run_tui(path, color_on);
    };

    banner(color_on);

    match command {
        Commands::Init { force } => {
            if path.exists() && !force {
                eprintln!("cybervault: {} already exists — pass --force to overwrite it (this destroys the existing vault)", path.display());
                return ExitCode::FAILURE;
            }
            let password = match read_master_password(true) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("cybervault: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match vault::save(&path, &password, &VaultData::default()) {
                Ok(()) => {
                    println!("cybervault: new empty vault created at {}", path.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("cybervault: failed to create vault: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        Commands::Add { label, note } => {
            let password = match read_master_password(false) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("cybervault: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let mut data = match vault::load(&path, &password) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("cybervault: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let secret = match read_secret_to_store() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("cybervault: {e}");
                    return ExitCode::FAILURE;
                }
            };
            data.entries.insert(label.clone(), Entry { secret, created: today(), note });
            match vault::save(&path, &password, &data) {
                Ok(()) => {
                    println!("cybervault: saved \"{label}\"");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("cybervault: failed to save vault: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        Commands::Get { label, copy } => {
            let password = match read_master_password(false) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("cybervault: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let data = match vault::load(&path, &password) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("cybervault: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match data.entries.get(&label) {
                Some(entry) => {
                    if copy {
                        match clipboard::copy(&entry.secret) {
                            Ok(()) => println!("cybervault: \"{label}\" copied to clipboard"),
                            Err(e) => eprintln!("cybervault: failed to copy to clipboard: {e}"),
                        }
                    } else {
                        println!("{}", entry.secret);
                    }
                    ExitCode::SUCCESS
                }
                None => {
                    eprintln!("cybervault: no entry named \"{label}\"");
                    ExitCode::FAILURE
                }
            }
        }

        Commands::List => {
            let password = match read_master_password(false) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("cybervault: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let data = match vault::load(&path, &password) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("cybervault: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if data.entries.is_empty() {
                println!("(vault is empty)");
            } else {
                for (label, entry) in &data.entries {
                    let note = entry.note.as_deref().unwrap_or("");
                    println!("{:<24} created {}  {}", label, entry.created, note);
                }
            }
            ExitCode::SUCCESS
        }

        Commands::Remove { label } => {
            let password = match read_master_password(false) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("cybervault: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let mut data = match vault::load(&path, &password) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("cybervault: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if data.entries.remove(&label).is_none() {
                eprintln!("cybervault: no entry named \"{label}\"");
                return ExitCode::FAILURE;
            }
            match vault::save(&path, &password, &data) {
                Ok(()) => {
                    println!("cybervault: removed \"{label}\"");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("cybervault: failed to save vault: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
