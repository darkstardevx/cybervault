# Security Policy

## Threat model

What CyberVault's design actually defends against, and what it
doesn't — read this before trusting it with anything real.

### What's defended

- **The master password is never stored, only used to derive a key.**
  `crypto::derive_key` runs Argon2id (memory-hard, GPU/ASIC-resistant
  key derivation — the current recommended choice over PBKDF2/bcrypt
  for this purpose) directly into raw key bytes for the cipher, not a
  PHC hash string. No home-rolled crypto anywhere — both Argon2id and
  ChaCha20-Poly1305 are audited, widely-used implementations, composed
  the straightforward way.
- **Tampering is detected, not silently decrypted into garbage.**
  ChaCha20-Poly1305 is authenticated — flipping even one bit anywhere
  in the ciphertext (including the auth tag) makes decryption fail
  outright, verified by a real test (`tampered_ciphertext_fails_to_decrypt`)
  that does exactly that. A wrong password and a corrupted file are
  deliberately indistinguishable from the outside (both just fail to
  decrypt) — there's no way to tell them apart without leaking
  information useful to an attacker trying passwords.
- **A fresh salt and nonce on every single save.** Reusing a nonce
  with the same key is a real cryptographic break for this cipher —
  verified by a real test (`each_save_uses_a_fresh_salt_and_nonce`)
  that saves identical data twice and confirms the resulting files
  differ.
- **File and directory permissions are self-healing, not just set at
  creation.** `vault::save` re-applies `0600` (file) / `0700`
  (directory) on *every* save, verified by a real test
  (`save_tightens_permissions_that_were_already_loosened`) that
  deliberately loosens both first and confirms the next save fixes
  them. The threat model explicitly names "another user on this
  machine" as an adversary — a world-readable ciphertext is real
  exposure even though the contents are encrypted (metadata like
  label names and entry count would still leak, and it's needless
  exposure regardless).

### What's NOT defended (by design, or by necessity)

- **The master password itself has no rate-limiting or lockout.**
  Argon2id's own cost parameters are the only brute-force friction —
  there's no attempt counter, no exponential backoff, no lockout after
  N failed unlocks. A weak master password is the real risk here, not
  the cipher or the key derivation.
- **`keysmith` and `wl-copy` are trusted subprocesses**, same user and
  machine, not sandboxed or verified beyond "the command named
  `keysmith`/`wl-copy` on `PATH` did what it claims." A compromised
  `keysmith` binary, or a clipboard manager that logs clipboard
  history, are outside this tool's own control and not defended
  against.
- **The clipboard has no auto-clear.** `clipboard.rs`'s `wl-copy`
  integration copies a secret and returns — there's no timer to
  overwrite the clipboard afterward, so a copied secret persists until
  something else overwrites it. A real, deliberately out-of-scope gap
  for this pass (auto-clear is a real feature with its own design
  questions — what should trigger it, and when — not a one-line fix),
  documented here so it's a known tradeoff, not a silent one.
- **The host it runs on.** Like every other project in this
  workspace, CyberVault assumes the machine it runs on isn't already
  compromised. It doesn't defend against a local attacker with access
  to the running process, its memory, or its config/vault files.

## Supported deployment model

A single user's own machine, for their own secrets — the same "a
handful of things you personally administer" model as the rest of
this workspace. Not designed for shared or multi-user access to the
same vault file.

## Reporting a vulnerability

Email **darkstardevx@gmail.com** (primary) or, as a backup,
**cybercore.sh@gmail.com**. Include:

- the affected file/commit and a minimal repro or PoC
- what you'd expect to happen instead
- how you'd rate the impact (your best guess is fine)

Expect an acknowledgement within a few days. Please don't include
exploit details in a public GitHub issue or PR until a fix has
shipped.

## Supported versions

Only the latest commit on `main` is supported — there's no tagged
release yet.
