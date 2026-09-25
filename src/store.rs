//! The proxy's pin store: one file per server.
//!
//! A pin is the set of definitions the user approved, learnt on first use.
//! Whatever the server declares differently afterwards goes to `pending` until
//! `accept`. The file is read once, before the server starts, and written
//! atomically.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

/// Where the proxy keeps its files: `TOOLGATE_HOME`, or `.toolgate` in the
/// user's profile. The proxy gets the client's environment, so the profile
/// variable is there.
pub fn home() -> Result<PathBuf, Error> {
    let profile = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    home_from(std::env::var_os("TOOLGATE_HOME"), std::env::var_os(profile)).ok_or_else(|| {
        Error::Pin(format!(
            "neither TOOLGATE_HOME nor {profile} is set; set TOOLGATE_HOME"
        ))
    })
}

// The pure core of `home`, so the precedence can be tested without touching
// the environment.
fn home_from(explicit: Option<OsString>, profile: Option<OsString>) -> Option<PathBuf> {
    explicit
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            profile
                .filter(|v| !v.is_empty())
                .map(|p| PathBuf::from(p).join(".toolgate"))
        })
}

/// The name a server's pin is stored under: `--name` if given, otherwise one
/// derived from the launch command. **Never** from what the server reports
/// about itself: a malicious update could rename itself to get a fresh first use.
pub fn server_key(name: Option<&str>, command: &[String]) -> Result<String, Error> {
    let Some(name) = name else {
        return Ok(derived_key(command));
    };
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if valid {
        Ok(name.to_owned())
    } else {
        Err(Error::Pin(format!(
            "invalid server name {name:?}: use 1 to 64 of A-Z a-z 0-9 . _ -"
        )))
    }
}

// The command's file stem plus a digest of the whole command line, so two
// servers launched through the same program get different keys.
fn derived_key(command: &[String]) -> String {
    let stem = command
        .first()
        .and_then(|c| Path::new(c).file_stem())
        .and_then(|s| s.to_str())
        .unwrap_or("server");
    let slug: String = stem
        .chars()
        .take(48)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let digest = sha256_hex(command.join("\0").as_bytes());
    format!("{slug}-{}", &digest[..8])
}

pub fn pin_path(home: &Path, key: &str) -> PathBuf {
    home.join("pins").join(format!("{key}.json"))
}

/// Reads a server's pin. A missing file means first use. A file that cannot be
/// read, or that is corrupt, is an **error**: starting over silently would
/// reopen the trust-on-first-use window.
pub fn load(home: &Path, key: &str) -> Result<Option<ServerPin>, Error> {
    let path = pin_path(home, key);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Error::Io {
                path: path.display().to_string(),
                source: e,
            });
        }
    };
    let corrupt = |e: serde_json::Error| Error::Pin(format!("{} is corrupt: {e}", path.display()));
    let value: Value = serde_json::from_str(&text).map_err(corrupt)?;
    match value.get("version").and_then(Value::as_u64) {
        Some(v) if v == u64::from(PIN_VERSION) => {
            serde_json::from_value(value).map(Some).map_err(corrupt)
        }
        Some(v) => Err(Error::Pin(format!(
            "{} uses pin format v{v}; this toolgate reads v{PIN_VERSION}",
            path.display()
        ))),
        None => Err(Error::Pin(format!(
            "{} has no version; this toolgate reads v{PIN_VERSION}",
            path.display()
        ))),
    }
}

/// Writes a server's pin atomically: to a temporary file, then renamed over the
/// real one, so a crash never leaves half a pin behind.
pub fn save(home: &Path, pin: &ServerPin) -> Result<(), Error> {
    let path = pin_path(home, &pin.server);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(io_error(dir))?;
    }
    let tmp = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let text = serde_json::to_string_pretty(pin).map_err(|e| Error::Pin(e.to_string()))?;
    std::fs::write(&tmp, text).map_err(io_error(&tmp))?;
    rename_with_retries(&tmp, &path)
}

fn io_error(path: &Path) -> impl FnOnce(std::io::Error) -> Error + '_ {
    move |source| Error::Io {
        path: path.display().to_string(),
        source,
    }
}

// On Windows a rename fails while another process has the target open; a few
// short retries ride out a concurrent session reading its pin.
fn rename_with_retries(from: &Path, to: &Path) -> Result<(), Error> {
    let mut last = None;
    for _ in 0..5 {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    let _ = std::fs::remove_file(from);
    Err(Error::Io {
        path: to.display().to_string(),
        source: last.unwrap_or_else(|| std::io::Error::other("rename failed")),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        PendingKind, PendingText, PendingTool, PinState, PinnedText, ServerPin, home_from, load,
        pin_path, save, server_key,
    };
    use serde_json::json;
    use std::ffi::OsString;
    use std::path::PathBuf;

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

    // A fresh, empty directory per test, so parallel tests never share state.
    fn temp_home(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("toolgate-store-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn home_prefers_the_explicit_variable() {
        let profile = Some(OsString::from("/users/me"));
        let default = Some(PathBuf::from("/users/me").join(".toolgate"));
        assert_eq!(
            home_from(Some(OsString::from("/custom")), profile.clone()),
            Some(PathBuf::from("/custom"))
        );
        assert_eq!(home_from(Some(OsString::new()), profile.clone()), default);
        assert_eq!(home_from(None, profile), default);
        assert_eq!(home_from(None, None), None);
    }

    #[test]
    fn a_given_name_is_validated() {
        assert_eq!(
            server_key(Some("github.v2_x-1"), &[]).unwrap(),
            "github.v2_x-1"
        );
        let long = "x".repeat(65);
        for bad in ["", "a/b", "../x", "with space", long.as_str()] {
            assert!(
                server_key(Some(bad), &[]).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn a_derived_key_is_stable_and_depends_on_every_argument() {
        let cmd = |args: &[&str]| args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
        let key = server_key(None, &cmd(&["/usr/bin/npx", "-y", "@acme/docs"])).unwrap();
        assert!(
            key.starts_with("npx-") && key.len() == "npx-".len() + 8,
            "{key}"
        );
        assert_eq!(
            key,
            server_key(None, &cmd(&["/usr/bin/npx", "-y", "@acme/docs"])).unwrap()
        );
        assert_ne!(
            key,
            server_key(None, &cmd(&["/usr/bin/npx", "-y", "@acme/other"])).unwrap()
        );
    }

    #[test]
    fn a_pin_survives_a_round_trip() {
        let home = temp_home("roundtrip");
        let mut p = ServerPin::new("docs", &["node".to_owned()]);
        p.seal();
        p.note_pending_tool("a", entry(PendingKind::New), 7);
        save(&home, &p).unwrap();
        assert_eq!(load(&home, "docs").unwrap(), Some(p));
    }

    #[test]
    fn a_missing_pin_means_first_use() {
        assert_eq!(load(&temp_home("missing"), "docs").unwrap(), None);
    }

    #[test]
    fn a_corrupt_pin_is_an_error_not_a_fresh_start() {
        // Starting over would silently reopen the trust-on-first-use window.
        let home = temp_home("corrupt");
        std::fs::create_dir_all(home.join("pins")).unwrap();
        std::fs::write(pin_path(&home, "docs"), "{ not json").unwrap();
        assert!(load(&home, "docs").is_err());
    }

    #[test]
    fn an_unknown_pin_version_is_an_error() {
        let home = temp_home("version");
        std::fs::create_dir_all(home.join("pins")).unwrap();
        std::fs::write(pin_path(&home, "docs"), r#"{"version":99}"#).unwrap();
        assert!(load(&home, "docs").unwrap_err().to_string().contains("v1"));
    }

    #[test]
    fn saving_leaves_no_temporary_file() {
        let home = temp_home("tmp");
        save(&home, &ServerPin::new("docs", &[])).unwrap();
        let names: Vec<String> = std::fs::read_dir(home.join("pins"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["docs.json"]);
    }
}
