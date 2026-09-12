//! Key derivation (Argon2id) and authenticated encryption
//! (ChaCha20-Poly1305) — the same "correctly compose audited primitives,
//! don't invent anything" approach as Keysmith's `pwhash.rs`. Argon2id
//! here derives raw key *bytes* for the cipher, not a PHC hash string —
//! a different mode of the same crate, `hash_password_into` rather than
//! `hash_password`.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

pub fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Argon2id key derivation should not fail for valid, bounded inputs");
    key
}

pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.encrypt(Nonce::from_slice(nonce), plaintext).expect("encryption with a fresh nonce should not fail")
}

/// `Err` covers both "wrong password" and "file corrupted/tampered" —
/// ChaCha20-Poly1305 is authenticated, so both look identical from the
/// outside (the integrity tag just doesn't verify) and there's no way to
/// usefully distinguish them without leaking information to an attacker.
pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext).map_err(|_| "wrong password, or the vault file is corrupted/tampered".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_correctly() {
        let salt = [7u8; SALT_LEN];
        let nonce = [3u8; NONCE_LEN];
        let key = derive_key("correct horse battery staple", &salt);
        let ciphertext = encrypt(&key, &nonce, b"a secret");
        let plaintext = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(plaintext, b"a secret");
    }

    #[test]
    fn wrong_password_fails_to_decrypt() {
        let salt = [7u8; SALT_LEN];
        let nonce = [3u8; NONCE_LEN];
        let key = derive_key("right password", &salt);
        let ciphertext = encrypt(&key, &nonce, b"a secret");

        let wrong_key = derive_key("wrong password", &salt);
        assert!(decrypt(&wrong_key, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let salt = [7u8; SALT_LEN];
        let nonce = [3u8; NONCE_LEN];
        let key = derive_key("a password", &salt);
        let mut ciphertext = encrypt(&key, &nonce, b"a secret");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF; // flip a bit in the auth tag

        assert!(decrypt(&key, &nonce, &ciphertext).is_err(), "tampered ciphertext must fail the integrity check, not silently decrypt garbage");
    }

    #[test]
    fn same_password_and_salt_derive_the_same_key() {
        let salt = [1u8; SALT_LEN];
        let a = derive_key("consistent", &salt);
        let b = derive_key("consistent", &salt);
        assert_eq!(a, b);
    }

    #[test]
    fn different_salt_derives_a_different_key_from_the_same_password() {
        let a = derive_key("consistent", &[1u8; SALT_LEN]);
        let b = derive_key("consistent", &[2u8; SALT_LEN]);
        assert_ne!(a, b);
    }
}
