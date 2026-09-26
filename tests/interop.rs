//! The proxy in front of the official MCP reference servers, which other
//! people wrote against the real SDK. Our own test servers can only prove the
//! proxy agrees with our reading of the protocol; these can prove it does not
//! break a server it has never seen.
//!
//! They download packages with npx, so they need the network and are ignored
//! by default. CI runs them in a job of their own:
//! `cargo test --test interop -- --ignored --test-threads=1`.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{Client, log_events, node_available, temp_home};
use serde_json::{Value, json};

// Pinned, so a new release cannot change what these tests mean.
const EVERYTHING: &str = "@modelcontextprotocol/server-everything@2026.8.31";
const FILESYSTEM: &str = "@modelcontextprotocol/server-filesystem@2026.8.31";
const MEMORY: &str = "@modelcontextprotocol/server-memory@2026.8.31";

// The first run downloads the package.
const FIRST_ANSWER: Duration = Duration::from_secs(180);

// Anything the policy logs when it blocks, hides or rewrites. None of it may
// happen to a reference server: if the proxy blocks what is legitimate, nobody
// will keep it installed.
const INTERVENTIONS: &[&str] = &[
    "tool_hidden",
    "tool_stubbed",
    "list_rewritten",
    "malformed_field",
    "instructions_stripped",
    "call_blocked",
    "output_blocked",
    "line_dropped",
];

/// One tool call in the script. `stable`: the server answers it the same way
/// every time, so its bytes can be compared across runs. Two do not, measured
/// on 2026-09-26: `get-resource-reference` stamps the time it made the
/// resource, and `get_file_info` reports when the file was last read.
struct Call {
    tool: &'static str,
    arguments: Value,
    stable: bool,
}

fn call(tool: &'static str, arguments: Value, stable: bool) -> Call {
    Call {
        tool,
        arguments,
        stable,
    }
}

/// What one session received: the handshake, the listing and every call's
/// answer, raw.
struct Transcript {
    answers: Vec<(String, bool)>,
}

fn session(mut client: Client, calls: &[Call]) -> Transcript {
    client.wait = FIRST_ANSWER;
    let mut answers = Vec::new();
    // Declaring roots, sampling and elicitation makes server-everything offer
    // the tools that exercise them.
    let params = json!({ "protocolVersion": "2025-11-25",
        "capabilities": { "roots": { "listChanged": true }, "sampling": {}, "elicitation": {} },
        "clientInfo": { "name": "toolgate-interop", "version": "1" } });
    answers.push((client.request_raw(1, "initialize", params), true));
    client.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    answers.push((client.request_raw(2, "tools/list", json!({})), true));
    for (n, c) in (10..).zip(calls) {
        let params = json!({ "name": c.tool, "arguments": c.arguments });
        answers.push((client.request_raw(n, "tools/call", params), c.stable));
    }
    let closed = client.close();
    assert_eq!(closed.status.code(), Some(0), "stderr: {}", closed.stderr);
    Transcript { answers }
}

/// Runs the script directly, then twice through the proxy (learning, then
/// sealed), and checks the proxy changed nothing and blocked nothing. `reset`
/// runs before each session, so each starts from the same state.
fn check(
    label: &str,
    package: &str,
    extra: &[&str],
    env: &[(&str, &str)],
    reset: &dyn Fn(),
    calls: &[Call],
) {
    if !node_available() {
        return;
    }
    let home = temp_home(&format!("interop-{label}"));
    let mut server = vec!["-y", package];
    server.extend_from_slice(extra);

    reset();
    let direct = session(Client::direct("npx", &server, env), calls);
    let mut args = vec!["proxy", "--name", label, "--", "npx"];
    args.extend_from_slice(&server);
    for run in ["learning", "sealed"] {
        reset();
        let proxied = session(Client::proxy(&home, &args, env), calls);
        for (i, ((ours, stable), (theirs, _))) in
            proxied.answers.iter().zip(&direct.answers).enumerate()
        {
            assert!(
                !ours.contains("[toolgate]"),
                "{label}, {run}: answer {i} was blocked: {ours}"
            );
            if *stable {
                assert_eq!(
                    ours, theirs,
                    "{label}, {run}: answer {i} changed on its way"
                );
            }
        }
    }

    let pin = toolgate::store::load(&home, label).unwrap().unwrap();
    assert!(pin.is_sealed(), "{label}: the first session did not seal");
    assert!(pin.pending.is_none(), "{label}: {:?}", pin.pending);
    let events = log_events(&home, label);
    for intervention in INTERVENTIONS {
        assert!(
            !events.iter().any(|e| e == intervention),
            "{label}: the proxy logged {intervention}: {events:?}"
        );
    }
}

#[test]
#[ignore = "downloads the reference servers with npx"]
fn server_everything_goes_through_untouched() {
    let calls = [
        call("echo", json!({ "message": "hello" }), true),
        call("get-sum", json!({ "a": 2, "b": 3 }), true),
        call(
            "get-annotated-message",
            json!({ "messageType": "error", "includeImage": true }),
            true,
        ),
        call("get-resource-links", json!({ "count": 3 }), true),
        call(
            "get-resource-reference",
            json!({ "resourceType": "Text", "resourceId": 1 }),
            false,
        ),
        call(
            "get-structured-content",
            json!({ "location": "Chicago" }),
            true,
        ),
        call("get-tiny-image", json!({}), true),
        call(
            "trigger-sampling-request",
            json!({ "prompt": "hi", "maxTokens": 5 }),
            true,
        ),
        call("get-roots-list", json!({}), true),
    ];
    check("everything", EVERYTHING, &[], &[], &|| {}, &calls);
}

#[test]
#[ignore = "downloads the reference servers with npx"]
fn server_filesystem_goes_through_untouched() {
    let home = temp_home("interop-fs-files");
    let dir = home.join("files");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("note.txt"), "a note\n").unwrap();
    // The server reports paths the way it resolved them; ask with the same.
    let dir = canonical(&dir);
    let note = format!("{dir}/note.txt");
    let calls = [
        call("list_allowed_directories", json!({}), true),
        call("list_directory", json!({ "path": dir }), true),
        call("read_text_file", json!({ "path": note }), true),
        call("get_file_info", json!({ "path": note }), false),
        call(
            "search_files",
            json!({ "path": dir, "pattern": "note" }),
            true,
        ),
    ];
    check("filesystem", FILESYSTEM, &[&dir], &[], &|| {}, &calls);
}

#[test]
#[ignore = "downloads the reference servers with npx"]
fn server_memory_goes_through_untouched() {
    let home = temp_home("interop-memory-files");
    let calls = [
        call(
            "create_entities",
            json!({ "entities": [{ "name": "Ada", "entityType": "person",
                                   "observations": ["wrote programs"] }] }),
            true,
        ),
        call("read_graph", json!({}), true),
        call("search_nodes", json!({ "query": "Ada" }), true),
    ];
    // The graph lives in this file: removed before each session, so each
    // starts empty.
    let file = home.join("memory.json");
    let reset = || {
        let _ = std::fs::remove_file(&file);
    };
    let env = [("MEMORY_FILE_PATH", file.to_str().unwrap())];
    check("memory", MEMORY, &[], &env, &reset, &calls);
}

fn canonical(dir: &Path) -> String {
    let path = dir.canonicalize().unwrap();
    let text = path.to_str().unwrap();
    // Windows' canonical form starts with \\?\, which the server does not use.
    text.strip_prefix(r"\\?\")
        .unwrap_or(text)
        .replace('\\', "/")
}
