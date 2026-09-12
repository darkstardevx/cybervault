//! Shells out to the `keysmith` binary to generate a password or
//! passphrase for the TUI's add wizard — symmetric to Keysmith's own
//! `vault_save.rs`, which shells out to `cybervault add`. `--raw` gives
//! exactly one secret on stdout, no banner/meter/color, safe to capture
//! directly.
//!
//! Entropy estimates here are computed locally (not by asking Keysmith)
//! so the length/word-count prompt can show live strength feedback
//! without a subprocess round-trip on every keystroke. The constants
//! mirror Keysmith's own defaults exactly: `password.rs`'s default
//! `Charset` (lower+upper+digits+symbols, no exclusions) has an 87-char
//! pool; the embedded EFF wordlist is 7776 words. If either ever drifts
//! from Keysmith, this estimate would too — acceptable since it's a
//! preview, and the real secret always comes from Keysmith itself.

use std::process::Command;

pub enum Kind {
    Password(usize),
    Passphrase(usize),
}

pub fn generate(kind: &Kind) -> Result<String, String> {
    let args: Vec<String> = match kind {
        Kind::Password(length) => vec!["password".into(), "--raw".into(), "--length".into(), length.to_string()],
        Kind::Passphrase(words) => vec!["passphrase".into(), "--raw".into(), "--words".into(), words.to_string()],
    };
    let output = Command::new("keysmith")
        .args(&args)
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

const PASSWORD_POOL_SIZE: f64 = 87.0; // lower(26) + upper(26) + digits(10) + symbols(25)
const WORDLIST_SIZE: f64 = 7776.0; // EFF large wordlist, 6^5

pub fn password_entropy_bits(length: usize) -> f64 {
    length as f64 * PASSWORD_POOL_SIZE.log2()
}

pub fn passphrase_entropy_bits(words: usize) -> f64 {
    words as f64 * WORDLIST_SIZE.log2()
}

/// Mirrors Keysmith's own `strength::label` thresholds.
pub fn strength_label(bits: f64) -> &'static str {
    match bits {
        b if b < 28.0 => "Very Weak",
        b if b < 36.0 => "Weak",
        b if b < 60.0 => "Fair",
        b if b < 128.0 => "Strong",
        _ => "Very Strong",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_entropy_matches_hand_calculation() {
        let bits = password_entropy_bits(24);
        let expected = 24.0 * 87f64.log2();
        assert!((bits - expected).abs() < 0.001);
    }

    #[test]
    fn passphrase_entropy_matches_hand_calculation() {
        let bits = passphrase_entropy_bits(6);
        let expected = 6.0 * 7776f64.log2();
        assert!((bits - expected).abs() < 0.001);
    }

    #[test]
    fn strength_label_boundaries() {
        assert_eq!(strength_label(10.0), "Very Weak");
        assert_eq!(strength_label(150.0), "Very Strong");
    }
}
