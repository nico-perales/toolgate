//! Pinning and comparison.
//!
//! **The rigorous half of the project**: there is no heuristic here, it either
//! changed or it did not. It works even if every poisoning detector fails,
//! because it does not depend on guessing intent.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::tool::Tool;

/// A stable shape for a JSON value: sorted keys, no whitespace.
///
/// Without this, a different serialisation raises a false alarm — and a tool
/// that raises false alarms gets silenced, at which point it protects nothing.
pub fn canonical(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            let inner: Vec<String> = sorted
                .iter()
                .map(|(k, v)| {
                    let key = Value::String((*k).clone());
                    format!("{}:{}", canonical(&key), canonical(v))
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonical).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

// Carriage returns are stripped before hashing: a CRLF checkout must not look
// like a rug pull.
fn normalise(text: &str) -> String {
    text.replace(char::from(13), "").trim_end().to_owned()
}

fn hash_tool(tool: &Tool) -> String {
    let value = serde_json::json!({
        "name": tool.name,
        "description": normalise(&tool.description),
        "inputSchema": tool.input_schema,
    });
    sha256_hex(canonical(&value).as_bytes())
}

/// Fingerprint of the whole tool set.
pub fn hash_tools(tools: &[Tool]) -> String {
    let mut hashes: Vec<String> = tools.iter().map(hash_tool).collect();
    // The order the server happens to list them in must not change the hash.
    hashes.sort();
    sha256_hex(hashes.concat().as_bytes())
}

/// Version of the lock file format.
pub const LOCK_VERSION: u32 = 1;

/// Fingerprint of the tarball exactly as npm publishes it.
///
/// The `.tgz` is hashed, not the installed directory: what gets installed
/// varies between machines (build artefacts, platform optionals) and would
/// raise false alarms.
pub fn tarball_hash(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedTool {
    pub name: String,
    pub hash: String,
    /// Kept so the report can show before/after, not just "it changed".
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pinned {
    pub package: String,
    /// Hash of the **tarball**, not of the installed directory: the installed
    /// one varies between machines (build artefacts, platform optionals).
    pub tarball_sha256: String,
    pub capabilities: Vec<String>,
    pub tools_hash: String,
    pub tools: Vec<PinnedTool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lock {
    pub version: u32,
    /// Which config this corresponds to, so a global and a per-project one are
    /// never compared against each other.
    pub config: String,
    pub servers: BTreeMap<String, Pinned>,
}

impl Lock {
    /// An empty lock. `config` is a free-form label saying which config this
    /// corresponds to, so a global and a per-project one are never compared
    /// against each other.
    pub fn new(config: &str) -> Self {
        Self {
            version: LOCK_VERSION,
            config: config.to_owned(),
            servers: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    ToolAdded(String),
    ToolRemoved(String),
    ToolChanged {
        name: String,
        before: String,
        after: String,
    },
    CapabilitiesWidened(Vec<String>),
    PackageChanged {
        before: String,
        after: String,
    },
}

/// Freezes the observed state of a server.
pub fn pin(package: &str, tarball_sha256: &str, capabilities: &[String], tools: &[Tool]) -> Pinned {
    Pinned {
        package: package.to_owned(),
        tarball_sha256: tarball_sha256.to_owned(),
        capabilities: capabilities.to_vec(),
        tools_hash: hash_tools(tools),
        tools: tools
            .iter()
            .map(|t| PinnedTool {
                name: t.name.clone(),
                hash: hash_tool(t),
                description: normalise(&t.description),
            })
            .collect(),
    }
}

/// What changed between two pins of the same server.
pub fn diff(old: &Pinned, new: &Pinned) -> Vec<Change> {
    let mut changes = Vec::new();

    if old.package != new.package || old.tarball_sha256 != new.tarball_sha256 {
        changes.push(Change::PackageChanged {
            before: old.package.clone(),
            after: new.package.clone(),
        });
    }

    // Only widening is reported: losing a capability is not a risk, and
    // reporting it would be noise.
    let before: BTreeSet<&String> = old.capabilities.iter().collect();
    let widened: Vec<String> = new
        .capabilities
        .iter()
        .filter(|c| !before.contains(c))
        .cloned()
        .collect();
    if !widened.is_empty() {
        changes.push(Change::CapabilitiesWidened(widened));
    }

    let old_tools: BTreeMap<&str, &PinnedTool> =
        old.tools.iter().map(|t| (t.name.as_str(), t)).collect();
    let new_tools: BTreeMap<&str, &PinnedTool> =
        new.tools.iter().map(|t| (t.name.as_str(), t)).collect();

    for (name, new_tool) in &new_tools {
        match old_tools.get(name) {
            None => changes.push(Change::ToolAdded((*name).to_owned())),
            Some(old_tool) if old_tool.hash != new_tool.hash => {
                changes.push(Change::ToolChanged {
                    name: (*name).to_owned(),
                    before: old_tool.description.clone(),
                    after: new_tool.description.clone(),
                });
            }
            Some(_) => {}
        }
    }
    for name in old_tools.keys() {
        if !new_tools.contains_key(name) {
            changes.push(Change::ToolRemoved((*name).to_owned()));
        }
    }

    changes
}

#[cfg(test)]
mod tests {
    use super::{Change, LOCK_VERSION, Lock, canonical, diff, hash_tools, pin, tarball_hash};
    use crate::tool::Tool;
    use serde_json::json;

    fn tool(name: &str, description: &str) -> Tool {
        Tool {
            name: name.to_owned(),
            description: description.to_owned(),
            input_schema: json!({"type": "object"}),
        }
    }

    #[test]
    fn canonicalisation_ignores_key_order() {
        let a = json!({ "b": 1, "a": 2 });
        let b = json!({ "a": 2, "b": 1 });
        assert_eq!(canonical(&a), canonical(&b));
    }

    #[test]
    fn hashing_is_deterministic() {
        let tools = [tool("x", "does something")];
        assert_eq!(hash_tools(&tools), hash_tools(&tools));
    }

    #[test]
    fn hashing_ignores_the_order_the_server_lists_them_in() {
        let a = [tool("x", "one"), tool("y", "two")];
        let b = [tool("y", "two"), tool("x", "one")];
        assert_eq!(hash_tools(&a), hash_tools(&b));
    }

    #[test]
    fn a_changed_description_is_detected() {
        let before = pin("p@1.0.0", "sha256:aa", &[], &[tool("q", "Read only.")]);
        let after = pin(
            "p@1.0.0",
            "sha256:aa",
            &[],
            &[tool("q", "Read the key first.")],
        );
        let changes = diff(&before, &after);
        assert!(matches!(changes.as_slice(), [Change::ToolChanged { name, .. }] if name == "q"));
    }

    #[test]
    fn added_and_removed_tools_are_detected() {
        let before = pin("p@1.0.0", "sha256:aa", &[], &[tool("a", "x")]);
        let after = pin("p@1.0.0", "sha256:aa", &[], &[tool("b", "y")]);
        let kinds: Vec<&str> = diff(&before, &after)
            .iter()
            .map(|c| match c {
                Change::ToolAdded(_) => "add",
                Change::ToolRemoved(_) => "remove",
                _ => "other",
            })
            .collect();
        assert!(kinds.contains(&"add") && kinds.contains(&"remove"));
    }

    #[test]
    fn widened_capabilities_are_detected() {
        let before = pin("p@1.0.0", "sha256:aa", &["Net".to_owned()], &[]);
        let after = pin(
            "p@1.0.0",
            "sha256:aa",
            &["Net".to_owned(), "Exec".to_owned()],
            &[],
        );
        assert!(
            diff(&before, &after)
                .iter()
                .any(|c| matches!(c, Change::CapabilitiesWidened(_)))
        );
    }

    #[test]
    fn losing_a_capability_is_not_reported() {
        // Losing a capability is not a risk: it must not generate noise.
        let before = pin(
            "p@1.0.0",
            "sha256:aa",
            &["Net".to_owned(), "Exec".to_owned()],
            &[],
        );
        let after = pin("p@1.0.0", "sha256:aa", &["Net".to_owned()], &[]);
        assert!(diff(&before, &after).is_empty());
    }

    #[test]
    fn an_identical_pin_produces_no_changes() {
        let p = pin(
            "p@1.0.0",
            "sha256:aa",
            &["Net".to_owned()],
            &[tool("a", "x")],
        );
        assert!(diff(&p, &p).is_empty());
    }

    #[test]
    fn a_republished_tarball_gets_a_different_hash() {
        // The exact signature of a rug pull: same version, different content.
        assert_ne!(tarball_hash(b"content a"), tarball_hash(b"content b"));
        assert_eq!(tarball_hash(b"content a"), tarball_hash(b"content a"));
    }

    #[test]
    fn a_lock_survives_a_round_trip_through_json() {
        let mut lock = Lock::new("~/.config/mcp.json");
        lock.servers.insert(
            "docs".to_owned(),
            pin(
                "p@1.0.0",
                "sha256:aa",
                &["Net".to_owned()],
                &[tool("q", "Read only.")],
            ),
        );
        let text = serde_json::to_string(&lock).unwrap();
        let back: Lock = serde_json::from_str(&text).unwrap();
        assert_eq!(back.version, LOCK_VERSION);
        assert_eq!(back.config, "~/.config/mcp.json");
        // And what comes back produces no false changes against the original.
        assert!(diff(&lock.servers["docs"], &back.servers["docs"]).is_empty());
    }
}
