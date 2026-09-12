//! Wayland clipboard integration via `wl-copy`. Shared by the `get --copy`
//! CLI command and the TUI's copy keybinding — one implementation instead
//! of two copies drifting apart.

use std::io::Write;
use std::process::{Command, Stdio};

pub fn copy(text: &str) -> std::io::Result<()> {
    let mut child = Command::new("wl-copy").stdin(Stdio::piped()).spawn()?;
    child.stdin.take().expect("stdin was piped").write_all(text.as_bytes())?;
    child.wait().map(|_| ())
}
