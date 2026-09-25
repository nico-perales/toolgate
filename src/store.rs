//! The proxy's pin store: one file per server.
//!
//! A pin is the set of definitions the user approved, learnt on first use.
//! Whatever the server declares differently afterwards goes to `pending` until
//! `accept`. The file is read once, before the server starts, and written
//! atomically.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;
use crate::lock::{PinnedTool, sha256_hex};

/// Version of the pin file format.
pub const PIN_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PinState {
    /// First use: what the server declares is trusted, except critical findings.
    Learning,
    /// The approved baseline: every change goes to pending.
    Sealed,
}

/// Why something waits for review.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PendingKind {
    /// A pinned definition that changed.
    Changed,
    /// Not in the pin at all.
    New,
    /// Carries a deterministic finding; accepting it needs `--force`.
    Critical,
    /// The name appears more than once in a listing; never pinnable.
    Duplicate,
    /// Not a valid tool definition; never pinnable.
    Malformed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedText {
    pub hash: String,
    pub text: String,
}

impl PinnedText {
    pub fn new(text: &str) -> Self {
        Self {
            hash: sha256_hex(text.as_bytes()),
            text: text.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingTool {
    pub kind: PendingKind,
    pub hash: String,
    pub definition: Value,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingText {
    pub kind: PendingKind,
    pub text: PinnedText,
    pub reasons: Vec<String>,
}

/// What the server declared since the pin that nobody has approved yet. Only the
/// latest version of each change is kept: there is no history.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pending {
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    #[serde(default)]
    pub tools: BTreeMap<String, PendingTool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<PendingText>,
}

impl Pending {
    fn is_empty(&self) -> bool {
        self.tools.is_empty() && self.instructions.is_none()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerPin {
    pub version: u32,
    pub server: String,
    /// The launch command, for whoever reads the file. Never used as a key.
    pub command: Vec<String>,
    pub state: PinState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<PinnedText>,
    #[serde(default)]
    pub tools: BTreeMap<String, PinnedTool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
}

/// What `accept` did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Accepted {
    pub promoted: Vec<String>,
    /// Duplicates and malformed definitions: dropped, never pinned.
    pub dropped: Vec<String>,
    pub instructions: bool,
}

impl ServerPin {
    /// A pin for a server seen for the first time.
    pub fn new(server: &str, command: &[String]) -> Self {
        Self {
            version: PIN_VERSION,
            server: server.to_owned(),
            command: command.to_vec(),
            state: PinState::Learning,
            instructions: None,
            tools: BTreeMap::new(),
            pending: None,
        }
    }

    pub fn is_sealed(&self) -> bool {
        self.state == PinState::Sealed
    }

    pub fn seal(&mut self) {
        self.state = PinState::Sealed;
    }

    pub fn has_pending_tool(&self, name: &str) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|p| p.tools.contains_key(name))
    }

    fn pending_mut(&mut self, now_ms: u64) -> &mut Pending {
        let pending = self.pending.get_or_insert_with(|| Pending {
            first_seen_ms: now_ms,
            ..Pending::default()
        });
        pending.last_seen_ms = now_ms;
        pending
    }

    /// Records the latest unapproved version of a tool, replacing any earlier one.
    pub fn note_pending_tool(&mut self, name: &str, entry: PendingTool, now_ms: u64) {
        self.pending_mut(now_ms)
            .tools
            .insert(name.to_owned(), entry);
    }

    pub fn note_pending_instructions(&mut self, entry: PendingText, now_ms: u64) {
        self.pending_mut(now_ms).instructions = Some(entry);
    }

    pub fn clear_pending_tool(&mut self, name: &str) {
        if let Some(pending) = &mut self.pending {
            pending.tools.remove(name);
        }
        self.drop_empty_pending();
    }

    pub fn clear_pending_instructions(&mut self) {
        if let Some(pending) = &mut self.pending {
            pending.instructions = None;
        }
        self.drop_empty_pending();
    }

    fn drop_empty_pending(&mut self) {
        if self.pending.as_ref().is_some_and(Pending::is_empty) {
            self.pending = None;
        }
    }

    /// Promotes every pending change to the pin. Refuses critical findings
    /// unless `force`, exactly like `pin`; duplicates and malformed definitions
    /// are dropped, because there is nothing coherent to pin.
    pub fn accept(&mut self, force: bool) -> Result<Accepted, Error> {
        let Some(pending) = self.pending.take() else {
            return Ok(Accepted::default());
        };
        let critical = pending
            .tools
            .values()
            .any(|t| t.kind == PendingKind::Critical)
            || pending
                .instructions
                .as_ref()
                .is_some_and(|t| t.kind == PendingKind::Critical);
        if critical && !force {
            self.pending = Some(pending);
            return Err(Error::Pin(
                "critical findings are pending; review them, and pass --force to accept anyway"
                    .to_owned(),
            ));
        }

        let mut accepted = Accepted::default();
        for (name, entry) in pending.tools {
            match entry.kind {
                PendingKind::Duplicate | PendingKind::Malformed => accepted.dropped.push(name),
                PendingKind::Changed | PendingKind::New | PendingKind::Critical => {
                    self.tools.insert(
                        name.clone(),
                        PinnedTool {
                            name: name.clone(),
                            hash: entry.hash,
                            definition: entry.definition,
                        },
                    );
                    accepted.promoted.push(name);
                }
            }
        }
        if let Some(entry) = pending.instructions {
            self.instructions = Some(entry.text);
            accepted.instructions = true;
        }
        Ok(accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::{PendingKind, PendingText, PendingTool, PinState, PinnedText, ServerPin};
    use serde_json::json;

    fn pin() -> ServerPin {
        ServerPin::new("docs", &["node".to_owned()])
    }

    fn entry(kind: PendingKind) -> PendingTool {
        PendingTool {
            kind,
            hash: "h".to_owned(),
            definition: json!({ "name": "x" }),
            reasons: vec!["r".to_owned()],
        }
    }

    #[test]
    fn a_new_pin_is_learning_and_empty() {
        let p = pin();
        assert_eq!(p.state, PinState::Learning);
        assert!(p.tools.is_empty() && p.pending.is_none() && p.instructions.is_none());
    }

    #[test]
    fn pending_keeps_when_it_was_first_seen() {
        let mut p = pin();
        p.note_pending_tool("a", entry(PendingKind::New), 10);
        p.note_pending_tool("a", entry(PendingKind::Changed), 20);
        let pending = p.pending.as_ref().unwrap();
        assert_eq!((pending.first_seen_ms, pending.last_seen_ms), (10, 20));
        // Only the latest version of a change is kept.
        assert_eq!(pending.tools["a"].kind, PendingKind::Changed);
    }

    #[test]
    fn accept_promotes_changes_and_new_tools() {
        let mut p = pin();
        p.seal();
        p.note_pending_tool("a", entry(PendingKind::Changed), 1);
        p.note_pending_tool("b", entry(PendingKind::New), 1);
        p.note_pending_instructions(
            PendingText {
                kind: PendingKind::New,
                text: PinnedText::new("Guide."),
                reasons: Vec::new(),
            },
            1,
        );
        let accepted = p.accept(false).unwrap();
        assert_eq!(accepted.promoted, ["a", "b"]);
        assert!(accepted.instructions);
        assert!(p.pending.is_none());
        assert_eq!(p.tools["a"].hash, "h");
        assert_eq!(p.instructions.unwrap().text, "Guide.");
    }

    #[test]
    fn accept_refuses_critical_findings_without_force() {
        let mut p = pin();
        p.note_pending_tool("a", entry(PendingKind::Critical), 1);
        assert!(p.accept(false).is_err());
        assert!(
            p.has_pending_tool("a"),
            "a refused accept keeps the pending entry"
        );
        assert_eq!(p.accept(true).unwrap().promoted, ["a"]);
    }

    #[test]
    fn accept_drops_duplicates_and_malformed_entries() {
        let mut p = pin();
        p.note_pending_tool("dup", entry(PendingKind::Duplicate), 1);
        p.note_pending_tool("bad", entry(PendingKind::Malformed), 1);
        let accepted = p.accept(false).unwrap();
        assert_eq!(accepted.dropped, ["bad", "dup"]);
        assert!(p.tools.is_empty());
    }

    #[test]
    fn clearing_the_last_entry_clears_pending() {
        let mut p = pin();
        p.note_pending_tool("a", entry(PendingKind::New), 1);
        p.clear_pending_tool("a");
        assert!(p.pending.is_none());
    }
}
