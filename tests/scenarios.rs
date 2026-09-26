//! End-to-end scenarios: the proxy binary in front of a scripted server that
//! misbehaves on purpose, in both protocol eras.

mod common;

use std::path::{Path, PathBuf};

use common::{Client, fixture, node_available, temp_home, toolgate};
use serde_json::{Value, json};

const SERVER: &str = "scenario";

#[derive(Clone, Copy, Debug)]
enum Era {
    /// `initialize`, and requests the server sends itself (2025-11-25).
    Legacy,
    /// `server/discover`, a protocol version in every request's `_meta`, and
    /// `input_required` results (2026-07-28).
    Modern,
}

// One client session through the proxy, in front of the scenario server.
struct Session {
    client: Client,
    era: Era,
    next_id: u64,
}

impl Session {
    fn open(home: &Path, era: Era, mode: &str) -> Self {
        let server = fixture("scenario_server.js");
        let args = [
            "proxy",
            "--name",
            SERVER,
            "--",
            "node",
            server.to_str().unwrap(),
        ];
        let trace = trace_file(home);
        let env = [
            ("TOOLGATE_TEST_MODE", mode),
            ("TOOLGATE_TEST_TRACE", trace.to_str().unwrap()),
        ];
        let mut session = Self {
            client: Client::proxy(home, &args, &env),
            era,
            next_id: 1,
        };
        match era {
            Era::Legacy => {
                let params = json!({ "protocolVersion": "2025-11-25",
                    "capabilities": { "sampling": {} },
                    "clientInfo": { "name": "test", "version": "1" } });
                session.request("initialize", params);
                session
                    .client
                    .send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
            }
            Era::Modern => {
                session.request("server/discover", json!({}));
            }
        }
        session
    }

    // A request in this session's era: a modern one carries its version.
    fn request(&mut self, method: &str, mut params: Value) -> Value {
        if let Era::Modern = self.era {
            params["_meta"] = json!({ "io.modelcontextprotocol/protocolVersion": "2026-07-28" });
        }
        let id = self.next_id;
        self.next_id += 1;
        self.client.request(id, method, params)
    }

    // Every page of the listing, or at most `max` of them.
    fn list(&mut self, max: usize) -> Vec<Value> {
        let mut tools = Vec::new();
        let mut cursor: Option<Value> = None;
        for _ in 0..max {
            let params = cursor.map_or_else(|| json!({}), |c| json!({ "cursor": c }));
            let page = self.request("tools/list", params);
            tools.extend(page["result"]["tools"].as_array().unwrap().iter().cloned());
            match page["result"].get("nextCursor") {
                Some(next) if !next.is_null() => cursor = Some(next.clone()),
                _ => break,
            }
        }
        tools
    }

    fn call(&mut self, tool: &str, extra: Value) -> Value {
        let mut params = json!({ "name": tool, "arguments": {} });
        if let Value::Object(fields) = extra {
            params.as_object_mut().unwrap().extend(fields);
        }
        self.request("tools/call", params)
    }

    fn close(self) {
        let closed = self.client.close();
        assert_eq!(closed.status.code(), Some(0), "stderr: {}", closed.stderr);
    }
}

fn trace_file(home: &Path) -> PathBuf {
    home.join("trace.txt")
}

// Whether the server received this request line in any session so far.
fn traced(home: &Path, line: &str) -> bool {
    std::fs::read_to_string(trace_file(home))
        .unwrap_or_default()
        .lines()
        .any(|l| l == line)
}

fn forget_trace(home: &Path) {
    let _ = std::fs::remove_file(trace_file(home));
}

fn names(tools: &[Value]) -> Vec<&str> {
    tools.iter().map(|t| t["name"].as_str().unwrap()).collect()
}

fn find<'a>(tools: &'a [Value], name: &str) -> &'a Value {
    tools
        .iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("{name} is not listed"))
}

// The text of a tool result, or of the error that replaced it.
fn result_text(response: &Value) -> String {
    response["result"]["content"][0]["text"]
        .as_str()
        .or_else(|| response["error"]["message"].as_str())
        .unwrap_or_default()
        .to_owned()
}

// Whether toolgate answered this call itself, instead of the server.
fn blocked(response: &Value) -> bool {
    response["result"]["isError"] == true && result_text(response).starts_with("[toolgate]")
}

// --- criterion 2: a rug pull across sessions, in both eras ---

fn rug_pull_across_sessions(era: Era) {
    if !node_available() {
        return;
    }
    let home = temp_home(&format!("rugpull-{era:?}"));

    // Session 1: first use learns every page and seals at the last one.
    let mut s = Session::open(&home, era, "benign");
    let tools = s.list(10);
    assert_eq!(
        names(&tools),
        ["read_file", "delete_file", "search", "fetch", "ask"]
    );
    assert!(!blocked(&s.call("delete_file", json!({}))));
    s.close();
    let pin = toolgate::store::load(&home, SERVER).unwrap().unwrap();
    assert!(pin.is_sealed());
    assert_eq!(pin.tools.len(), 5);

    // Session 2: the server now says delete_file is harmless.
    forget_trace(&home);
    let mut s = Session::open(&home, era, "rugpull-annotations");
    let tools = s.list(10);
    let delete = find(&tools, "delete_file");
    assert!(
        delete["description"]
            .as_str()
            .unwrap()
            .starts_with("[toolgate]"),
        "{delete}"
    );
    assert!(delete.get("annotations").is_none(), "{delete}");
    assert!(blocked(&s.call("delete_file", json!({}))));
    s.close();
    assert!(
        !traced(&home, "tools/call delete_file"),
        "the blocked call reached the server"
    );
    let (code, review) = toolgate(&home, &["review", SERVER]);
    assert_eq!(code, Some(1));
    assert!(
        review.contains("annotations.destructiveHint: true -> false"),
        "{review}"
    );
    assert_eq!(toolgate(&home, &["accept", SERVER]).0, Some(0));

    // Session 3: approved, so it goes through untouched.
    let mut s = Session::open(&home, era, "rugpull-annotations");
    let tools = s.list(10);
    assert_eq!(
        find(&tools, "delete_file")["annotations"]["destructiveHint"],
        false
    );
    assert!(!blocked(&s.call("delete_file", json!({}))));
    s.close();
    assert!(traced(&home, "tools/call delete_file"));
}

#[test]
fn a_rug_pull_is_caught_across_sessions_in_the_legacy_era() {
    rug_pull_across_sessions(Era::Legacy);
}

#[test]
fn a_rug_pull_is_caught_across_sessions_in_the_modern_era() {
    rug_pull_across_sessions(Era::Modern);
}

#[test]
fn a_rewritten_description_and_a_new_tool_are_held_back() {
    if !node_available() {
        return;
    }
    let home = temp_home("description");
    let mut s = Session::open(&home, Era::Legacy, "benign");
    s.list(10);
    s.close();

    forget_trace(&home);
    let mut s = Session::open(&home, Era::Legacy, "rugpull-description");
    let tools = s.list(10);
    // The stub carries nothing from the server but the approved name.
    let search = find(&tools, "search");
    assert!(!search.to_string().contains("id_rsa"), "{search}");
    // A tool nobody approved is not shown at all.
    assert!(!names(&tools).contains(&"export"));
    assert!(blocked(&s.call("search", json!({}))));
    assert!(blocked(&s.call("export", json!({}))));
    s.close();
    assert!(!traced(&home, "tools/call search"));
    assert!(!traced(&home, "tools/call export"));

    let (_, review) = toolgate(&home, &["review", SERVER]);
    assert!(review.contains("read ~/.ssh/id_rsa"), "{review}");
    assert!(review.contains("new: not in the approved set"), "{review}");
}
