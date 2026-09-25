//! The session log: one JSONL file per proxy session, every line chained to
//! the one before by its hash.
//!
//! What the chain proves, and what it does not. It catches a line changed or
//! removed in the middle of the file. It cannot catch a cut at the end, because
//! the shorter file is still a valid chain, so a missing `session_end` is
//! reported as unfinished, never as tampering. And whoever can write the file
//! can recompute the whole chain: the head each session prints to stderr, which
//! the MCP client keeps in its own logs, is the only anchor outside the file.
#![deny(clippy::print_stdout)]

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;

use crate::error::Error;
use crate::lock::sha256_hex;
use crate::store::PinState;

/// The `prev` of a log's first line.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Milliseconds since the Unix epoch: the log's timestamps, without a date
/// library.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The lines that open and close a session.
#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Marker<'a> {
    SessionStart {
        server: &'a str,
        command: &'a [String],
        pin: PinState,
        toolgate: &'a str,
    },
    SessionEnd {
        events: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        exit: Option<i32>,
    },
}

#[derive(Serialize)]
struct Entry<'a, E: Serialize> {
    seq: u64,
    ts_ms: u64,
    prev: &'a str,
    event: &'a E,
}

/// Writes chained lines.
pub struct Journal<W: Write> {
    out: W,
    seq: u64,
    prev: String,
}

impl<W: Write> Journal<W> {
    pub fn new(out: W) -> Self {
        Self {
            out,
            seq: 0,
            prev: GENESIS.to_owned(),
        }
    }

    /// Writes `event` as one line, chained to the line before, and flushes it.
    pub fn record<E: Serialize>(&mut self, ts_ms: u64, event: &E) -> io::Result<()> {
        let entry = Entry {
            seq: self.seq,
            ts_ms,
            prev: &self.prev,
            event,
        };
        let mut line = serde_json::to_vec(&entry).map_err(io::Error::other)?;
        let hash = sha256_hex(&line);
        line.push(b'\n');
        self.out.write_all(&line)?;
        self.out.flush()?;
        self.seq += 1;
        self.prev = hash;
        Ok(())
    }

    /// How many lines were written.
    pub fn count(&self) -> u64 {
        self.seq
    }

    /// The hash of the last line: what the next line's `prev` will be.
    pub fn head(&self) -> &str {
        &self.prev
    }

    pub fn into_inner(self) -> W {
        self.out
    }
}

/// Creates this session's log, `<home>/logs/<server>/<ts_ms>-<pid>.jsonl`.
/// `server` must be a key `store::server_key` accepted, so it is a safe file
/// name.
pub fn open(home: &Path, server: &str, ts_ms: u64) -> Result<(PathBuf, Journal<File>), Error> {
    let dir = home.join("logs").join(server);
    std::fs::create_dir_all(&dir).map_err(|source| Error::Io {
        path: dir.display().to_string(),
        source,
    })?;
    let path = dir.join(format!("{ts_ms}-{}.jsonl", std::process::id()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|source| Error::Io {
            path: path.display().to_string(),
            source,
        })?;
    Ok((path, Journal::new(file)))
}

/// What `verify` found in a log.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The chain holds and the session closed normally.
    Intact { lines: u64, head: String },
    /// The chain holds, but there is no `session_end`: a crash, a kill, or a
    /// cut at the end. A hash chain cannot tell these apart.
    Unfinished { lines: u64, head: String },
    /// Line `seq` does not follow from the lines before it.
    Broken { seq: u64, reason: String },
}

/// Recomputes a log's chain.
pub fn verify(bytes: &[u8]) -> Verdict {
    let mut prev = GENESIS.to_owned();
    let mut lines: u64 = 0;
    let mut ended = false;
    let mut rest = bytes.split(|b| *b == b'\n').peekable();
    while let Some(line) = rest.next() {
        let last = rest.peek().is_none();
        if line.is_empty() && last {
            break; // the newline after the last line
        }
        let broken = |reason: &str| Verdict::Broken {
            seq: lines,
            reason: reason.to_owned(),
        };
        if ended {
            return broken("a line follows session_end");
        }
        let Ok(entry) = serde_json::from_slice::<Value>(line) else {
            if last {
                // A crash in the middle of a write leaves half a line.
                return Verdict::Unfinished { lines, head: prev };
            }
            return broken("the line is not JSON");
        };
        if entry.get("seq").and_then(Value::as_u64) != Some(lines) {
            return broken("its sequence number is wrong: a line was removed or reordered");
        }
        if entry.get("prev").and_then(Value::as_str) != Some(prev.as_str()) {
            return broken(
                "it does not chain to the line before: that line was changed, or one was removed",
            );
        }
        ended = entry.pointer("/event/event").and_then(Value::as_str) == Some("session_end");
        prev = sha256_hex(line);
        lines += 1;
    }
    if ended {
        Verdict::Intact { lines, head: prev }
    } else {
        Verdict::Unfinished { lines, head: prev }
    }
}

#[cfg(test)]
mod tests {
    use super::{GENESIS, Journal, Marker, Verdict, open, verify};
    use crate::policy::Event;
    use crate::store::PinState;

    // A complete session: start, `n` events, end.
    fn session(n: u64) -> Vec<u8> {
        let mut journal = Journal::new(Vec::new());
        let command = ["node".to_owned(), "server.js".to_owned()];
        let start = Marker::SessionStart {
            server: "docs",
            command: &command,
            pin: PinState::Learning,
            toolgate: "0.1.0",
        };
        journal.record(1, &start).unwrap();
        for i in 0..n {
            let event = Event::CallAllowed {
                tool: format!("t{i}"),
            };
            journal.record(2 + i, &event).unwrap();
        }
        let events = journal.count();
        journal
            .record(
                9,
                &Marker::SessionEnd {
                    events,
                    exit: Some(0),
                },
            )
            .unwrap();
        journal.into_inner()
    }

    fn lines(log: &[u8]) -> Vec<String> {
        String::from_utf8(log.to_vec())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn join(lines: &[String]) -> Vec<u8> {
        let mut out = lines.join("\n").into_bytes();
        out.push(b'\n');
        out
    }

    #[test]
    fn a_whole_session_verifies_as_intact() {
        let mut journal = Journal::new(Vec::new());
        let event = Event::CallAllowed {
            tool: "a".to_owned(),
        };
        journal.record(1, &event).unwrap();
        journal
            .record(
                2,
                &Marker::SessionEnd {
                    events: 1,
                    exit: None,
                },
            )
            .unwrap();
        let head = journal.head().to_owned();
        assert_eq!(
            verify(&journal.into_inner()),
            Verdict::Intact { lines: 2, head }
        );
    }

    #[test]
    fn the_first_line_starts_the_chain_and_names_its_fields() {
        let log = lines(&session(0));
        let first = &log[0];
        let expected =
            format!(r#"{{"seq":0,"ts_ms":1,"prev":"{GENESIS}","event":{{"event":"session_start","#);
        assert!(first.starts_with(&expected), "{first}");
    }

    #[test]
    fn a_changed_line_breaks_the_chain_at_the_next_one() {
        let mut log = lines(&session(3));
        log[2] = log[2].replace("\"t1\"", "\"t7\"");
        assert!(matches!(
            verify(&join(&log)),
            Verdict::Broken { seq: 3, .. }
        ));
    }

    #[test]
    fn a_removed_line_is_caught() {
        let mut log = lines(&session(3));
        log.remove(2);
        assert!(matches!(
            verify(&join(&log)),
            Verdict::Broken { seq: 2, .. }
        ));
    }

    #[test]
    fn a_cut_at_the_end_is_unfinished_not_tampering() {
        // The shorter file is a valid chain: a hash chain cannot tell a cut
        // from a crash, and must not claim it can.
        let log = lines(&session(3));
        assert!(matches!(
            verify(&join(&log[..3])),
            Verdict::Unfinished { lines: 3, .. }
        ));
    }

    #[test]
    fn half_a_last_line_is_unfinished() {
        let mut log = session(1);
        log.truncate(log.len() - 10);
        assert!(matches!(verify(&log), Verdict::Unfinished { lines: 2, .. }));
    }

    #[test]
    fn a_line_after_the_end_is_tampering() {
        let mut log = session(0);
        log.extend_from_slice(b"{}\n");
        assert!(matches!(verify(&log), Verdict::Broken { seq: 2, .. }));
    }

    #[test]
    fn each_session_gets_a_new_file_under_its_server() {
        let home = std::env::temp_dir().join(format!("toolgate-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let (path, _) = open(&home, "docs", 42).unwrap();
        let name = format!("42-{}.jsonl", std::process::id());
        assert_eq!(path, home.join("logs").join("docs").join(name));
        // Never an existing file: a clash fails instead of appending to it.
        assert!(open(&home, "docs", 42).is_err());
    }
}
