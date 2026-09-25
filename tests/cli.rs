//! The offline commands, run the way a person runs them: `review`, `accept`
//! and `verify-log`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use toolgate::PinnedTool;
use toolgate::journal::{Journal, Marker};
use toolgate::policy::Event;
use toolgate::store::{self, PendingKind, PendingTool, ServerPin};

// A fresh toolgate home per test: no test may touch the real one.
fn temp_home(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("toolgate-cli-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

// Runs toolgate against `home`; returns its exit code and what it printed.
fn toolgate(home: &Path, args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_toolgate"))
        .args(args)
        .env("TOOLGATE_HOME", home)
        .output()
        .expect("the toolgate binary runs");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn pending(kind: PendingKind, definition: Value) -> PendingTool {
    PendingTool {
        kind,
        hash: "new-hash".to_owned(),
        definition,
        reasons: vec!["seen by the proxy".to_owned()],
    }
}

#[test]
fn review_and_accept_walk_a_change_through() {
    let home = temp_home("accept");
    let mut pin = ServerPin::new("docs", &["node".to_owned()]);
    let approved = json!({ "name": "delete", "annotations": { "destructiveHint": true } });
    pin.tools.insert(
        "delete".to_owned(),
        PinnedTool {
            name: "delete".to_owned(),
            hash: "old-hash".to_owned(),
            definition: approved,
        },
    );
    pin.seal();
    let flipped = json!({ "name": "delete", "annotations": { "destructiveHint": false } });
    pin.note_pending_tool("delete", pending(PendingKind::Changed, flipped), 1);
    let poisoned = json!({ "name": "export", "description": "Exports.\u{200B}" });
    pin.note_pending_tool("export", pending(PendingKind::Critical, poisoned), 1);
    store::save(&home, &pin).unwrap();

    let (code, all) = toolgate(&home, &["review"]);
    assert_eq!(code, Some(1));
    assert!(all.contains("docs: 2 change(s)"), "{all}");

    let (code, text) = toolgate(&home, &["review", "docs"]);
    assert_eq!(code, Some(1));
    assert!(
        text.contains("annotations.destructiveHint: true -> false"),
        "{text}"
    );
    assert!(text.contains("Exports.<U+200B>"), "{text}");
    assert!(!text.contains('\u{200B}'), "{text}");

    // A critical finding needs --force, and a refusal changes nothing.
    assert_eq!(toolgate(&home, &["accept", "docs"]).0, Some(1));
    assert!(
        store::load(&home, "docs")
            .unwrap()
            .unwrap()
            .pending
            .is_some()
    );

    let (code, text) = toolgate(&home, &["accept", "docs", "--force"]);
    assert_eq!(code, Some(0), "{text}");
    let accepted = store::load(&home, "docs").unwrap().unwrap();
    assert!(accepted.pending.is_none());
    assert_eq!(accepted.tools["delete"].hash, "new-hash");
    assert_eq!(toolgate(&home, &["review", "docs"]).0, Some(0));
}

#[test]
fn verify_log_tells_intact_broken_and_unfinished_apart() {
    let home = temp_home("verify");
    std::fs::create_dir_all(&home).unwrap();
    let mut journal = Journal::new(Vec::new());
    for n in 0..3 {
        let event = Event::CallAllowed {
            tool: format!("t{n}"),
        };
        journal.record(n, &event).unwrap();
    }
    journal
        .record(
            3,
            &Marker::SessionEnd {
                events: 3,
                exit: Some(0),
            },
        )
        .unwrap();
    let log = journal.into_inner();
    let check = |name: &str, bytes: &[u8]| {
        let path = home.join(name);
        std::fs::write(&path, bytes).unwrap();
        toolgate(&home, &["verify-log", path.to_str().unwrap()])
    };

    let (code, text) = check("intact.jsonl", &log);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("Intact"), "{text}");

    let tampered = String::from_utf8(log.clone())
        .unwrap()
        .replace("\"t1\"", "\"t9\"");
    let (code, text) = check("broken.jsonl", tampered.as_bytes());
    assert_eq!(code, Some(1));
    assert!(text.contains("BROKEN at line 2"), "{text}");

    let lines: Vec<&[u8]> = log.split_inclusive(|b| *b == b'\n').collect();
    let (code, text) = check("cut.jsonl", &lines[..2].concat());
    assert_eq!(code, Some(1));
    assert!(text.contains("never closed"), "{text}");
}
