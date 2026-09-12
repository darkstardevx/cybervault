//! TUI application state. Unlocking happens once, before the alternate
//! screen is entered (see `main.rs::run_tui`) — the derived master
//! password is then held in memory for the session so browsing, copying,
//! and adding entries doesn't re-prompt on every action. That's a
//! deliberate, explicitly-chosen tradeoff against CyberVault's CLI
//! model (where every command re-prompts fresh): the TUI's whole reason
//! to exist is removing that friction for interactive use.

use crate::vault::{Entry, VaultData};
use ratatui::widgets::ListState;
use std::path::PathBuf;

#[derive(PartialEq, Eq, Debug)]
pub enum Mode {
    Normal,
    Filter,
    AddLabel,
    AddSecret,
    /// Entered from `AddSecret` via Ctrl+G: pick a password length
    /// before Keysmith actually generates it.
    GenPasswordLength,
    /// Entered from `AddSecret` via Ctrl+P: pick a passphrase word
    /// count before Keysmith actually generates it.
    GenPassphraseWords,
    AddNote,
    ConfirmRemove,
}

pub struct App {
    pub path: PathBuf,
    password: String,
    pub data: VaultData,

    /// All labels, sorted (mirrors `data.entries`, a `BTreeMap`).
    pub labels: Vec<String>,
    /// Indices into `labels` that match `filter_text`.
    pub filtered: Vec<usize>,
    pub list_state: ListState,

    pub mode: Mode,
    pub filter_text: String,
    pub input_buffer: String,
    /// Label + secret collected so far while stepping through the
    /// AddLabel -> AddSecret -> AddNote wizard.
    pending_label: Option<String>,
    pending_secret: Option<String>,
    /// `input_buffer`'s content from `AddSecret`, stashed while a
    /// `GenPassword*`/`GenPassphrase*` options prompt is open so Esc can
    /// restore it instead of losing whatever was typed/generated so far.
    saved_secret_buffer: String,
    /// Last-used length/word-count, so reopening the generate options
    /// (or rerolling) starts from where you left off rather than
    /// resetting to a hardcoded default every time.
    pub gen_password_length: usize,
    pub gen_passphrase_words: usize,

    /// Label currently shown in plaintext in the detail panel, if any.
    pub revealed: Option<String>,
    pub status: Option<String>,
    pub should_quit: bool,
}

impl App {
    pub fn new(path: PathBuf, password: String, data: VaultData) -> Self {
        let labels: Vec<String> = data.entries.keys().cloned().collect();
        let mut app = Self {
            path,
            password,
            data,
            labels,
            filtered: Vec::new(),
            list_state: ListState::default(),
            mode: Mode::Normal,
            filter_text: String::new(),
            input_buffer: String::new(),
            pending_label: None,
            pending_secret: None,
            saved_secret_buffer: String::new(),
            gen_password_length: 24,
            gen_passphrase_words: 6,
            revealed: None,
            status: None,
            should_quit: false,
        };
        app.apply_filter();
        app
    }

    pub fn apply_filter(&mut self) {
        let needle = self.filter_text.to_lowercase();
        self.filtered = self
            .labels
            .iter()
            .enumerate()
            .filter(|(_, l)| needle.is_empty() || l.to_lowercase().contains(&needle))
            .map(|(i, _)| i)
            .collect();
        if self.filtered.is_empty() {
            self.list_state.select(None);
        } else {
            let clamped = self.list_state.selected().unwrap_or(0).min(self.filtered.len() - 1);
            self.list_state.select(Some(clamped));
        }
    }

    fn selected_label(&self) -> Option<&str> {
        let i = self.list_state.selected()?;
        let idx = *self.filtered.get(i)?;
        self.labels.get(idx).map(String::as_str)
    }

    pub fn selected_entry(&self) -> Option<(&str, &Entry)> {
        let label = self.selected_label()?;
        self.data.entries.get(label).map(|e| (label, e))
    }

    pub fn next(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) if i + 1 < self.filtered.len() => i + 1,
            Some(_) => 0,
            None => 0,
        };
        self.list_state.select(Some(i));
        self.revealed = None;
    }

    pub fn previous(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(0) | None => self.filtered.len() - 1,
            Some(i) => i - 1,
        };
        self.list_state.select(Some(i));
        self.revealed = None;
    }

    pub fn toggle_reveal(&mut self) {
        let Some(label) = self.selected_label() else { return };
        self.revealed = if self.revealed.as_deref() == Some(label) { None } else { Some(label.to_string()) };
    }

    pub fn copy_selected(&mut self) {
        match self.selected_entry() {
            Some((label, entry)) => {
                let label = label.to_string();
                match crate::clipboard::copy(&entry.secret) {
                    Ok(()) => self.status = Some(format!("copied \"{label}\" to clipboard")),
                    Err(e) => self.status = Some(format!("clipboard error: {e}")),
                }
            }
            None => self.status = Some("nothing selected".to_string()),
        }
    }

    fn save_vault(&mut self) -> Result<(), String> {
        crate::vault::save(&self.path, &self.password, &self.data)
    }

    pub fn begin_add(&mut self) {
        self.pending_label = None;
        self.pending_secret = None;
        self.input_buffer.clear();
        self.mode = Mode::AddLabel;
    }

    /// Called on Enter while in `AddLabel`: stash the label, move to
    /// `AddSecret`. An empty label cancels back to Normal.
    pub fn confirm_label(&mut self) {
        let label = self.input_buffer.trim().to_string();
        if label.is_empty() {
            self.mode = Mode::Normal;
            return;
        }
        self.pending_label = Some(label);
        self.input_buffer.clear();
        self.mode = Mode::AddSecret;
    }

    /// Called on Enter while in `AddSecret`. An empty secret cancels the
    /// whole add (a label with no secret isn't useful).
    pub fn confirm_secret(&mut self) {
        if self.input_buffer.is_empty() {
            self.cancel_add();
            self.status = Some("add cancelled: secret can't be empty".to_string());
            return;
        }
        self.pending_secret = Some(self.input_buffer.clone());
        self.input_buffer.clear();
        self.mode = Mode::AddNote;
    }

    /// Called on Enter while in `AddNote` — the last step. An empty note
    /// is stored as `None`, not an empty string.
    pub fn confirm_note_and_save(&mut self) {
        let (Some(label), Some(secret)) = (self.pending_label.take(), self.pending_secret.take()) else {
            self.mode = Mode::Normal;
            return;
        };
        let note = if self.input_buffer.trim().is_empty() { None } else { Some(self.input_buffer.trim().to_string()) };
        self.input_buffer.clear();
        self.mode = Mode::Normal;

        let is_new = !self.data.entries.contains_key(&label);
        self.data.entries.insert(label.clone(), Entry { secret, created: crate::today(), note });
        match self.save_vault() {
            Ok(()) => {
                self.status = Some(format!("{} \"{label}\"", if is_new { "added" } else { "updated" }));
                self.labels = self.data.entries.keys().cloned().collect();
                self.apply_filter();
                if let Some(pos) = self.filtered.iter().position(|&i| self.labels[i] == label) {
                    self.list_state.select(Some(pos));
                }
            }
            Err(e) => self.status = Some(format!("failed to save: {e}")),
        }
    }

    /// Ctrl+G from `AddSecret`: stash the in-progress secret and switch
    /// to picking a length before Keysmith actually generates anything.
    pub fn begin_generate_password_options(&mut self) {
        if self.mode != Mode::AddSecret {
            return;
        }
        self.saved_secret_buffer = std::mem::take(&mut self.input_buffer);
        self.input_buffer = self.gen_password_length.to_string();
        self.mode = Mode::GenPasswordLength;
    }

    /// Ctrl+P from `AddSecret`: same as above, for word count.
    pub fn begin_generate_passphrase_options(&mut self) {
        if self.mode != Mode::AddSecret {
            return;
        }
        self.saved_secret_buffer = std::mem::take(&mut self.input_buffer);
        self.input_buffer = self.gen_passphrase_words.to_string();
        self.mode = Mode::GenPassphraseWords;
    }

    /// Esc from either generate-options prompt: restore whatever was in
    /// `AddSecret` before Ctrl+G/Ctrl+P was pressed, discard the number
    /// being typed.
    pub fn cancel_generate_options(&mut self) {
        self.input_buffer = std::mem::take(&mut self.saved_secret_buffer);
        self.mode = Mode::AddSecret;
    }

    /// Live entropy estimate for whatever's currently typed in a
    /// generate-options prompt, for on-screen feedback as the user picks
    /// a value — `None` while the field doesn't parse as a valid count
    /// yet (e.g. empty, mid-edit).
    pub fn gen_options_preview(&self) -> Option<(f64, &'static str)> {
        let n: usize = self.input_buffer.trim().parse().ok()?;
        let bits = match self.mode {
            Mode::GenPasswordLength => crate::keysmith_gen::password_entropy_bits(n),
            Mode::GenPassphraseWords => crate::keysmith_gen::passphrase_entropy_bits(n),
            _ => return None,
        };
        Some((bits, crate::keysmith_gen::strength_label(bits)))
    }

    /// Enter from `GenPasswordLength`: validate, remember the length for
    /// next time, and actually generate. Out-of-range/non-numeric input
    /// reports an error and stays on this screen rather than silently
    /// falling back to a default.
    pub fn confirm_password_length(&mut self) {
        match self.input_buffer.trim().parse::<usize>() {
            Ok(n) if (4..=128).contains(&n) => {
                self.gen_password_length = n;
                self.run_generate(crate::keysmith_gen::Kind::Password(n));
            }
            _ => self.status = Some("enter a length between 4 and 128".to_string()),
        }
    }

    /// Enter from `GenPassphraseWords`: same idea, for word count.
    pub fn confirm_passphrase_words(&mut self) {
        match self.input_buffer.trim().parse::<usize>() {
            Ok(n) if (3..=12).contains(&n) => {
                self.gen_passphrase_words = n;
                self.run_generate(crate::keysmith_gen::Kind::Passphrase(n));
            }
            _ => self.status = Some("enter a word count between 3 and 12".to_string()),
        }
    }

    /// Shells out to Keysmith and lands back in `AddSecret` either way:
    /// on success with the generated secret in `input_buffer` (still
    /// editable, still reroll-able), on failure with whatever was there
    /// before Ctrl+G/Ctrl+P restored.
    fn run_generate(&mut self, kind: crate::keysmith_gen::Kind) {
        match crate::keysmith_gen::generate(&kind) {
            Ok(secret) => {
                self.input_buffer = secret;
                self.status = Some("generated via keysmith — ctrl+g/ctrl+p to reroll, enter to accept".to_string());
            }
            Err(e) => {
                self.input_buffer = std::mem::take(&mut self.saved_secret_buffer);
                self.status = Some(format!("keysmith: {e}"));
            }
        }
        self.mode = Mode::AddSecret;
    }

    pub fn cancel_add(&mut self) {
        self.pending_label = None;
        self.pending_secret = None;
        self.input_buffer.clear();
        self.mode = Mode::Normal;
    }

    pub fn remove_selected(&mut self) {
        let Some(label) = self.selected_label().map(str::to_string) else {
            self.mode = Mode::Normal;
            return;
        };
        self.data.entries.remove(&label);
        match self.save_vault() {
            Ok(()) => {
                self.status = Some(format!("removed \"{label}\""));
                self.labels = self.data.entries.keys().cloned().collect();
                self.revealed = None;
                self.apply_filter();
            }
            Err(e) => self.status = Some(format!("failed to save: {e}")),
        }
        self.mode = Mode::Normal;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A private per-test directory, not `temp_dir()` directly: `save`
    /// chmods its parent directory to 0700, and `/tmp` itself is owned
    /// by root — a regular user can't chmod it (EPERM).
    fn scratch_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cybervault-app-test-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("vault.cvlt")
    }

    fn new_app_with(path: PathBuf, entries: &[(&str, &str)]) -> App {
        let mut data = VaultData::default();
        for (label, secret) in entries {
            data.entries.insert(label.to_string(), Entry { secret: secret.to_string(), created: "2026-01-01".to_string(), note: None });
        }
        crate::vault::save(&path, "test-password", &data).unwrap();
        App::new(path, "test-password".to_string(), data)
    }

    #[test]
    fn filter_narrows_to_matching_labels_case_insensitively() {
        let path = scratch_path("filter");
        let mut app = new_app_with(path.clone(), &[("github", "a"), ("gitlab", "b"), ("aws-root", "c")]);

        app.filter_text = "GIT".to_string();
        app.apply_filter();

        let matched: Vec<&str> = app.filtered.iter().map(|&i| app.labels[i].as_str()).collect();
        assert_eq!(matched, vec!["github", "gitlab"]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn filter_with_no_matches_clears_selection() {
        let path = scratch_path("nomatch");
        let mut app = new_app_with(path.clone(), &[("github", "a")]);

        app.filter_text = "nonexistent".to_string();
        app.apply_filter();

        assert!(app.filtered.is_empty());
        assert_eq!(app.list_state.selected(), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn add_wizard_persists_a_new_entry_to_disk() {
        let path = scratch_path("addwizard");
        let mut app = new_app_with(path.clone(), &[]);

        app.begin_add();
        app.input_buffer = "newlabel".to_string();
        app.confirm_label();
        assert_eq!(app.mode, Mode::AddSecret);

        app.input_buffer = "s3cr3t".to_string();
        app.confirm_secret();
        assert_eq!(app.mode, Mode::AddNote);

        app.input_buffer = "test note".to_string();
        app.confirm_note_and_save();
        assert_eq!(app.mode, Mode::Normal);

        assert_eq!(app.data.entries["newlabel"].secret, "s3cr3t");

        // Reload from disk independently to confirm it was actually
        // persisted, not just held in the in-memory `data`.
        let reloaded = crate::vault::load(&path, "test-password").unwrap();
        assert_eq!(reloaded.entries["newlabel"].secret, "s3cr3t");
        assert_eq!(reloaded.entries["newlabel"].note.as_deref(), Some("test note"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn add_wizard_cancels_on_empty_secret_without_creating_an_entry() {
        let path = scratch_path("emptysecret");
        let mut app = new_app_with(path.clone(), &[]);

        app.begin_add();
        app.input_buffer = "willnotbecreated".to_string();
        app.confirm_label();
        app.input_buffer.clear();
        app.confirm_secret();

        assert_eq!(app.mode, Mode::Normal);
        assert!(!app.data.entries.contains_key("willnotbecreated"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn remove_selected_deletes_and_persists() {
        let path = scratch_path("remove");
        let mut app = new_app_with(path.clone(), &[("github", "a"), ("gitlab", "b")]);
        app.list_state.select(Some(0)); // "github", first alphabetically

        app.remove_selected();

        assert!(!app.data.entries.contains_key("github"));
        let reloaded = crate::vault::load(&path, "test-password").unwrap();
        assert!(!reloaded.entries.contains_key("github"));
        assert!(reloaded.entries.contains_key("gitlab"));
        std::fs::remove_file(&path).ok();
    }

    /// Exercises the real `keysmith` binary (installed on this box's
    /// PATH) rather than mocking the subprocess boundary — same
    /// ground-truth-over-assumption discipline as every other
    /// cross-tool integration this session.
    #[test]
    fn confirm_password_length_generates_a_password_of_the_chosen_length() {
        let path = scratch_path("generate-password");
        let mut app = new_app_with(path.clone(), &[]);
        app.begin_add();
        app.input_buffer = "genlabel".to_string();
        app.confirm_label();
        assert_eq!(app.mode, Mode::AddSecret);

        app.begin_generate_password_options();
        assert_eq!(app.mode, Mode::GenPasswordLength);
        app.input_buffer = "32".to_string();
        app.confirm_password_length();

        assert_eq!(app.mode, Mode::AddSecret);
        assert_eq!(app.gen_password_length, 32);
        assert_eq!(app.input_buffer.chars().count(), 32, "keysmith password --raw --length 32 should be exactly 32 chars");
        assert!(app.status.as_deref().unwrap_or_default().contains("generated via keysmith"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn confirm_passphrase_words_generates_the_chosen_word_count() {
        let path = scratch_path("generate-passphrase");
        let mut app = new_app_with(path.clone(), &[]);
        app.begin_add();
        app.input_buffer = "genlabel".to_string();
        app.confirm_label();

        app.begin_generate_passphrase_options();
        assert_eq!(app.mode, Mode::GenPassphraseWords);
        app.input_buffer = "4".to_string();
        app.confirm_passphrase_words();

        assert_eq!(app.mode, Mode::AddSecret);
        assert_eq!(app.gen_passphrase_words, 4);
        assert_eq!(app.input_buffer.split('-').count(), 4, "4 words joined by the default '-' separator");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn out_of_range_length_is_rejected_and_stays_on_the_prompt() {
        let path = scratch_path("generate-outofrange");
        let mut app = new_app_with(path.clone(), &[]);
        app.begin_add();
        app.input_buffer = "genlabel".to_string();
        app.confirm_label();
        app.begin_generate_password_options();

        app.input_buffer = "9999".to_string();
        app.confirm_password_length();

        assert_eq!(app.mode, Mode::GenPasswordLength, "should stay on the prompt rather than silently falling back");
        assert!(app.status.as_deref().unwrap_or_default().contains("enter a length"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn non_numeric_length_is_rejected() {
        let path = scratch_path("generate-nonnumeric");
        let mut app = new_app_with(path.clone(), &[]);
        app.begin_add();
        app.input_buffer = "genlabel".to_string();
        app.confirm_label();
        app.begin_generate_password_options();

        app.input_buffer = "abc".to_string();
        app.confirm_password_length();

        assert_eq!(app.mode, Mode::GenPasswordLength);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn cancel_generate_options_restores_the_secret_typed_so_far() {
        let path = scratch_path("generate-cancel");
        let mut app = new_app_with(path.clone(), &[]);
        app.begin_add();
        app.input_buffer = "genlabel".to_string();
        app.confirm_label();
        app.input_buffer = "typed-so-far".to_string();

        app.begin_generate_password_options();
        assert_eq!(app.mode, Mode::GenPasswordLength);
        app.cancel_generate_options();

        assert_eq!(app.mode, Mode::AddSecret);
        assert_eq!(app.input_buffer, "typed-so-far");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn generate_options_ignored_outside_add_secret_mode() {
        let path = scratch_path("generate-wrongmode");
        let mut app = new_app_with(path.clone(), &[]);
        app.begin_add(); // Mode::AddLabel, not AddSecret

        app.begin_generate_password_options();

        assert_eq!(app.mode, Mode::AddLabel);
        assert!(app.input_buffer.is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn gen_options_preview_reflects_typed_value() {
        let path = scratch_path("generate-preview");
        let mut app = new_app_with(path.clone(), &[]);
        app.begin_add();
        app.input_buffer = "genlabel".to_string();
        app.confirm_label();
        app.begin_generate_password_options();

        app.input_buffer = "24".to_string();
        let (bits_24, _) = app.gen_options_preview().unwrap();
        app.input_buffer = "48".to_string();
        let (bits_48, _) = app.gen_options_preview().unwrap();

        assert!(bits_48 > bits_24, "doubling the length should increase the entropy estimate");

        app.input_buffer = "not-a-number".to_string();
        assert!(app.gen_options_preview().is_none());
        std::fs::remove_file(&path).ok();
    }
}
