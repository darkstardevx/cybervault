//! Clipboard integration: `wl-copy` on Linux/Wayland, `pbcopy` on macOS.
//! Shared by the `get --copy` CLI command and the TUI's copy keybinding —
//! one implementation instead of two copies drifting apart.

use std::io::Write;
use std::process::{Command, Stdio};

#[cfg(target_os = "macos")]
const CLIPBOARD_CMD: &str = "pbcopy";

#[cfg(not(target_os = "macos"))]
const CLIPBOARD_CMD: &str = "wl-copy";

pub fn copy(text: &str) -> std::io::Result<()> {
    let mut child = Command::new(CLIPBOARD_CMD)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("failed to run '{CLIPBOARD_CMD}': {e} (is it installed and on PATH?)"),
            )
        })?;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(text.as_bytes())?;
    child.wait().map(|_| ())
}
