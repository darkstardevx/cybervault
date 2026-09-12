mod crypto;
mod vault;

use clap::{Parser, Subcommand};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use vault::{Entry, VaultData};

#[derive(Parser, Debug)]
#[command(name = "cybervault", version = "0.1.0", about = "Encrypted secrets vault")]
struct Args {
    #[command(subcommand)]
    command: Commands,

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

fn today() -> String {
    Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown-date".to_string())
}

fn copy_to_clipboard(text: &str) -> std::io::Result<()> {
    use std::process::Stdio;
    let mut child = Command::new("wl-copy").stdin(Stdio::piped()).spawn()?;
    child.stdin.take().expect("stdin was piped").write_all(text.as_bytes())?;
    child.wait().map(|_| ())
}

fn main() -> ExitCode {
    let args = Args::parse();
    let color_on = !args.no_color;
    let path = args.path.unwrap_or_else(default_vault_path);

    banner(color_on);

    match args.command {
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
                        match copy_to_clipboard(&entry.secret) {
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
