//! Shells out to the `keysmith` binary to generate a password or
//! passphrase for the TUI's add wizard — symmetric to Keysmith's own
//! `vault_save.rs`, which shells out to `cybervault add`. `--raw` gives
//! exactly one secret on stdout, no banner/meter/color, safe to capture
//! directly.

use std::process::Command;

pub enum Kind {
    Password,
    Passphrase,
}

pub fn generate(kind: Kind) -> Result<String, String> {
    let args: &[&str] = match kind {
        Kind::Password => &["password", "--raw", "--length", "24"],
        Kind::Passphrase => &["passphrase", "--raw"],
    };
    let output = Command::new("keysmith")
        .args(args)
        .output()
        .map_err(|e| format!("failed to run keysmith — is it installed? ({e})"))?;
    if !output.status.success() {
        return Err(format!("keysmith exited with an error: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if secret.is_empty() {
        return Err("keysmith produced no output".to_string());
    }
    Ok(secret)
}
