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

    fn scratch_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("cybervault-app-test-{name}-{}.cvlt", std::process::id()))
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
}
