//! The on-disk vault format and (de)serialization. Layout:
//! `MAGIC(4) | salt(16) | nonce(12) | ciphertext(rest, includes the
//! Poly1305 auth tag)`. Salt and nonce aren't secret — they need to be
//! stored to re-derive the same key and decrypt later — only the
//! ciphertext and the master password are.

use crate::crypto::{self, KEY_LEN, NONCE_LEN, SALT_LEN};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

const MAGIC: &[u8; 4] = b"CVL1";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    pub secret: String,
    pub created: String,
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct VaultData {
    pub entries: BTreeMap<String, Entry>,
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn save(path: &Path, password: &str, data: &VaultData) -> Result<(), String> {
    let salt: [u8; SALT_LEN] = random_bytes();
    let nonce: [u8; NONCE_LEN] = random_bytes();
    let key = crypto::derive_key(password, &salt);
    let plaintext = serde_json::to_vec(data).map_err(|e| e.to_string())?;
    let ciphertext = crypto::encrypt(&key, &nonce, &plaintext);

    let mut out = Vec::with_capacity(4 + SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, out).map_err(|e| e.to_string())
}

pub fn load(path: &Path, password: &str) -> Result<VaultData, String> {
    let raw = std::fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let header_len = 4 + SALT_LEN + NONCE_LEN;
    if raw.len() < header_len {
        return Err(format!("{} is too short to be a valid vault file", path.display()));
    }
    if &raw[0..4] != MAGIC {
        return Err(format!("{} is not a CyberVault file (bad magic bytes)", path.display()));
    }
    let salt = &raw[4..4 + SALT_LEN];
    let nonce_bytes = &raw[4 + SALT_LEN..header_len];
    let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().expect("slice length matches NONCE_LEN by construction");
    let ciphertext = &raw[header_len..];

    let key: [u8; KEY_LEN] = crypto::derive_key(password, salt);
    let plaintext = crypto::decrypt(&key, &nonce, ciphertext)?;
    serde_json::from_slice(&plaintext).map_err(|e| format!("vault decrypted but contents aren't valid: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cybervault-test-{name}-{}.cvlt", std::process::id()))
    }

    #[test]
    fn saves_and_loads_round_trip() {
        let path = scratch_path("roundtrip");
        let mut data = VaultData::default();
        data.entries.insert("github".to_string(), Entry { secret: "hunter2".to_string(), created: "2026-09-12".to_string(), note: None });

        save(&path, "master-password", &data).unwrap();
        let loaded = load(&path, "master-password").unwrap();

        assert_eq!(loaded.entries["github"].secret, "hunter2");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_master_password_fails_to_load() {
        let path = scratch_path("wrongpw");
        let data = VaultData::default();
        save(&path, "correct-password", &data).unwrap();

        assert!(load(&path, "wrong-password").is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_a_file_with_bad_magic_bytes() {
        let path = scratch_path("badmagic");
        std::fs::write(&path, b"NOTAVAULTFILEATALL_______________").unwrap();

        let result = load(&path, "any-password");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a CyberVault file"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_a_truncated_file() {
        let path = scratch_path("truncated");
        std::fs::write(&path, b"CVL1short").unwrap();

        let result = load(&path, "any-password");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn each_save_uses_a_fresh_salt_and_nonce() {
        // Same password, same data, saved twice — the ciphertext bytes
        // (including header) must differ, since a reused nonce with the
        // same key is a real cryptographic break for this cipher.
        let path_a = scratch_path("fresh-a");
        let path_b = scratch_path("fresh-b");
        let data = VaultData::default();
        save(&path_a, "same-password", &data).unwrap();
        save(&path_b, "same-password", &data).unwrap();

        let a = std::fs::read(&path_a).unwrap();
        let b = std::fs::read(&path_b).unwrap();
        assert_ne!(a, b, "identical inputs must not produce identical vault files (salt/nonce must be fresh each time)");

        std::fs::remove_file(&path_a).ok();
        std::fs::remove_file(&path_b).ok();
    }
}
