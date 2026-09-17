//! The on-disk vault format and (de)serialization. Layout:
//! `MAGIC(4) | salt(16) | nonce(12) | ciphertext(rest, includes the
//! Poly1305 auth tag)`. Salt and nonce aren't secret — they need to be
//! stored to re-derive the same key and decrypt later — only the
//! ciphertext and the master password are.

use crate::crypto::{self, KEY_LEN, NONCE_LEN, SALT_LEN};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
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
        // Applied unconditionally, not just on first create, so a
        // directory that pre-dates this fix (or got loosened somehow)
        // self-heals on the next save rather than staying world-readable.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    std::fs::write(path, out).map_err(|e| e.to_string())?;
    // Same reasoning: `write` creates a new file at the umask-default
    // mode (typically 644) or leaves an existing file's mode untouched
    // either way, so the vault — ciphertext, but still something "another
    // user on the machine" per our own threat model shouldn't be able to
    // read at all — is locked to owner-only every save, not just at
    // creation.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())
}

pub fn load(path: &Path, password: &str) -> Result<VaultData, String> {
    let raw = std::fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let header_len = 4 + SALT_LEN + NONCE_LEN;
    if raw.len() < header_len {
        return Err(format!(
            "{} is too short to be a valid vault file",
            path.display()
        ));
    }
    if &raw[0..4] != MAGIC {
        return Err(format!(
            "{} is not a CyberVault file (bad magic bytes)",
            path.display()
        ));
    }
    let salt = &raw[4..4 + SALT_LEN];
    let nonce_bytes = &raw[4 + SALT_LEN..header_len];
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .expect("slice length matches NONCE_LEN by construction");
    let ciphertext = &raw[header_len..];

    let key: [u8; KEY_LEN] = crypto::derive_key(password, salt);
    let plaintext = crypto::decrypt(&key, &nonce, ciphertext)?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("vault decrypted but contents aren't valid: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A private per-test directory (not `temp_dir()` directly): `save`
    /// now chmods its parent directory to 0700, and several tests here
    /// deliberately mangle that directory's permissions — sharing `/tmp`
    /// itself as the "parent" would chmod `/tmp`, and a shared
    /// subdirectory across tests would race between threads.
    fn scratch_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cybervault-vault-test-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("vault.cvlt")
    }

    #[test]
    fn saves_and_loads_round_trip() {
        let path = scratch_path("roundtrip");
        let mut data = VaultData::default();
        data.entries.insert(
            "github".to_string(),
            Entry {
                secret: "hunter2".to_string(),
                created: "2026-09-12".to_string(),
                note: None,
            },
        );

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

    #[test]
    fn save_locks_the_file_and_its_directory_to_owner_only() {
        // The vault's own threat model names "another user on the
        // machine" as an adversary — the file must not be group/world
        // readable even though its contents are encrypted, since a
        // world-readable ciphertext is still needless exposure.
        let path = scratch_path("perms");
        save(&path, "master-password", &VaultData::default()).unwrap();

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "vault file must be owner-read/write only");

        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "vault directory must be owner-only");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn save_tightens_permissions_that_were_already_loosened() {
        // Simulates a pre-existing vault created before this fix (644/755,
        // the umask-default this box actually produced) — confirms a
        // later save self-heals it rather than only fixing brand-new files.
        let path = scratch_path("preexisting-loose");
        save(&path, "master-password", &VaultData::default()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        save(&path, "master-password", &VaultData::default()).unwrap();

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);

        std::fs::remove_file(&path).ok();
    }
}
