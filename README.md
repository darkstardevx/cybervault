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
cybervault                               # launch the interactive TUI
cybervault init                          # create a new, empty vault
cybervault add github --note "personal account"
cybervault get github --copy             # copy to clipboard, don't print
cybervault list                          # labels + dates + notes — never secrets
cybervault remove github
```

Every **CLI** operation (`add`/`get`/`list`/`remove`) prompts for the
master password fresh — no unlocked session sits around anywhere to be
stolen. `add` reads the secret from stdin if it's piped — the path
[Keysmith](https://github.com/darkstardevx/keysmith)'s `--save <label>`
flag uses (`keysmith password --save github`) — otherwise prompts
interactively with hidden input.

## 🖥️ TUI

Bare `cybervault` (no subcommand) launches an interactive terminal UI —
unlock once, then browse/search/copy/add/remove without re-entering the
master password for every action. This is a deliberate, explicit
exception to the "re-prompt every operation" model above: the derived
key is held in memory only for the TUI's session and is gone the moment
it exits, but it *is* resident in memory while the TUI is open (same
tradeoff as any interactive password manager — mitigates a stolen-disk
attacker, not a live memory-scraper on an already-open session).

```
j / k, ↓ / ↑    move selection
/               filter by label
v, Enter        reveal/hide the selected secret
c               copy the selected secret to clipboard
a               add a new entry (label -> secret -> optional note)
d               remove the selected entry (y/n to confirm)
q, Esc          quit
```

Colors come from the active `cybercore` theme (respects `CYBERGRID_THEME`),
same as every other cybercore-aware tool.

## 🔒 How it actually works

- **Key derivation**: Argon2id (same primitive as Keysmith's `pwhash`, different mode — `hash_password_into` derives raw key bytes, not a PHC string) turns the master password + a random salt into a 256-bit key
- **Encryption**: ChaCha20-Poly1305 — authenticated, so a tampered vault file fails to decrypt rather than silently producing garbage
- **File format**: `MAGIC(4) | salt(16) | nonce(12) | ciphertext`. A fresh random salt and nonce every single save — reusing a nonce with the same key would be a real cryptographic break for this cipher, verified by a test that saves the same data twice and confirms the output differs

This composes well-audited primitives (`argon2`, `chacha20poly1305` — both real RustCrypto crates) correctly. It does not invent any cryptography.

## ✅ Verification

15 unit tests. 10 on the crypto/vault-format layer: round-trip correctness,
wrong-password rejection, tampered-ciphertext detection (bit-flip in the
auth tag, confirmed it fails rather than decrypting to garbage silently),
fresh salt/nonce per save, bad-magic-bytes and truncated-file rejection.
5 on the TUI's app-state logic (`app.rs`): filter narrowing (case-insensitive,
including the empty-result case), the add wizard persisting a real entry to
disk (reloaded independently to confirm, not just checked in memory) and
correctly cancelling on an empty secret, and remove actually persisting.
CLI/TUI layer verified for help text and graceful (non-panicking) failure
when there's no real terminal for the password prompt or for entering
raw mode — the actual interactive `init`/`add`/`get`/TUI workflow needs a
real terminal to fully exercise, same limitation as Keysmith's `pwhash`.

## 🧩 Layout

```
src/crypto.rs      Argon2id key derivation + ChaCha20-Poly1305 encrypt/decrypt
src/vault.rs       on-disk file format, Entry/VaultData, save/load
src/clipboard.rs   wl-copy integration (shared by `get --copy` and the TUI)
src/app.rs         TUI application state
src/ui.rs          TUI rendering (ratatui, cybercore-themed)
src/main.rs        CLI + TUI event loop
```

## 🗺 Known limitations

- No re-keying (changing the master password re-encrypts with a new key derived from the new password, but there's no dedicated `change-password` command yet — would need to load with the old password and save with the new one manually today)
- Clipboard support is Wayland-only (`wl-copy`)

## 📄 License

MIT
