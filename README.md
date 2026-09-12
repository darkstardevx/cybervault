# 🔐 CyberVault

`Rust` · `Argon2id` · `ChaCha20-Poly1305`

**Encrypted secrets vault.** Master-password unlock, one file, authenticated
encryption — for storing generated passwords/passphrases (from
[Keysmith](https://github.com/darkstardevx/keysmith)) or anything else you
don't want sitting around in plaintext.

## 🎯 Threat model — read this before trusting it with anything

This protects secrets **at rest**: someone with read access to the vault
file (a stolen disk, another user on the machine, a backup that leaks)
can't read it without the master password. It does **not** protect
against a keylogger, malware on an already-unlocked session, or someone
watching over your shoulder while you type the master password. Know
what you're actually defending against.

## 🚀 Commands

```bash
cybervault init                          # create a new, empty vault
cybervault add github --note "personal account"
cybervault get github --copy             # copy to clipboard, don't print
cybervault list                          # labels + dates + notes — never secrets
cybervault remove github
```

Every operation prompts for the master password fresh — no unlocked
session sits around anywhere to be stolen. `add` reads the secret from
stdin if it's piped (the path Keysmith's `--save` would use), otherwise
prompts interactively with hidden input.

## 🔒 How it actually works

- **Key derivation**: Argon2id (same primitive as Keysmith's `pwhash`, different mode — `hash_password_into` derives raw key bytes, not a PHC string) turns the master password + a random salt into a 256-bit key
- **Encryption**: ChaCha20-Poly1305 — authenticated, so a tampered vault file fails to decrypt rather than silently producing garbage
- **File format**: `MAGIC(4) | salt(16) | nonce(12) | ciphertext`. A fresh random salt and nonce every single save — reusing a nonce with the same key would be a real cryptographic break for this cipher, verified by a test that saves the same data twice and confirms the output differs

This composes well-audited primitives (`argon2`, `chacha20poly1305` — both real RustCrypto crates) correctly. It does not invent any cryptography.

## ✅ Verification

10 unit tests on the crypto/vault-format layer: round-trip correctness,
wrong-password rejection, tampered-ciphertext detection (bit-flip in the
auth tag, confirmed it fails rather than decrypting to garbage silently),
fresh salt/nonce per save, bad-magic-bytes and truncated-file rejection.
CLI layer verified for help text and graceful (non-panicking) failure
when there's no real terminal for the password prompt — the actual
interactive `init`/`add`/`get` workflow needs a real terminal to fully
exercise, same limitation as Keysmith's `pwhash`.

## 🧩 Layout

```
src/crypto.rs   Argon2id key derivation + ChaCha20-Poly1305 encrypt/decrypt
src/vault.rs    on-disk file format, Entry/VaultData, save/load
src/main.rs     CLI
```

## 🗺 Known limitations

- No re-keying (changing the master password re-encrypts with a new key derived from the new password, but there's no dedicated `change-password` command yet — would need to load with the old password and save with the new one manually today)
- Clipboard support is Wayland-only (`wl-copy`)
- No Keysmith `--save` integration yet — planned, not yet wired up

## 📄 License

MIT
