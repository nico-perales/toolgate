//! The proxy as an MCP client sees it: the real binary, a real server process.

mod common;

#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use std::time::{Duration, Instant};

use common::{Client, fixture, node_available, temp_home};
use serde_json::json;

#[test]
fn a_first_session_learns_seals_and_blocks_an_unknown_tool() {
    if !node_available() {
        return;
    }
    let home = temp_home("first");
    let server = fixture("fake_server.js");
    let args = [
        "proxy",
        "--name",
        "smoke",
        "--",
        "node",
        server.to_str().unwrap(),
        // Many MCP servers take their API key as an argument.
        "--token=e2e-secret-4242",
    ];
    let mut client = Client::proxy(&home, &args, &[("TOOLGATE_TEST_INSTRUCTIONS", "Use ping.")]);

    let params = json!({ "protocolVersion": "2025-11-25", "capabilities": {},
                         "clientInfo": { "name": "test", "version": "1" } });
    let init = client.request(1, "initialize", params);
    // The server got the proxy's environment and working directory.
    let cwd = std::env::current_dir().unwrap();
    let expected = format!("Use ping. | cwd={}", cwd.display());
    assert_eq!(init["result"]["instructions"], expected);
    client.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));

    let list = client.request(2, "tools/list", json!({}));
    assert_eq!(list["result"]["tools"][0]["name"], "ping");

    // The complete listing sealed the pin: a name outside it never reaches the
    // server, which would not have answered anyway.
    let call = client.request(3, "tools/call", json!({ "name": "ghost", "arguments": {} }));
    assert_eq!(call["id"], 3);
    assert_eq!(call["result"]["isError"], true);

    // An answer asked for just before the client quits still gets through: the
    // proxy must not exit while it is on its way. It has to be large to catch
    // that. With the wait removed, a small answer almost always won the race
    // anyway, a 4 MB one was lost 4 times in 6, and a 16 MB one every time.
    client.send(&json!({ "jsonrpc": "2.0", "id": 4, "method": "test/sized",
        "params": { "bytes": 16_000_000 } }));
    let closed = client.close();
    assert_eq!(closed.status.code(), Some(0), "stderr: {}", closed.stderr);
    assert_eq!(closed.unread.len(), 1, "the last answer was lost");
    assert!(closed.unread[0].len() > 16_000_000);
    assert!(
        closed.stderr.contains("session log"),
        "stderr: {}",
        closed.stderr
    );

    let pin = toolgate::store::load(&home, "smoke")
        .unwrap()
        .expect("the pin was saved");
    assert!(pin.is_sealed());
    assert!(pin.tools.contains_key("ping"));
    let logs: Vec<PathBuf> = std::fs::read_dir(home.join("logs").join("smoke"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(logs.len(), 1);
    let log = std::fs::read(&logs[0]).unwrap();
    assert!(matches!(
        toolgate::journal::verify(&log),
        toolgate::journal::Verdict::Intact { .. }
    ));
    let text = String::from_utf8(log).unwrap();
    assert!(text.contains(r#""era":"legacy""#), "{text}");
    assert!(text.contains(r#""event":"call_blocked""#), "{text}");

    // Regression: the full launch command went to the log and the pin, so an
    // API key passed as an argument sat in plain text under ~/.toolgate.
    let pin_file = std::fs::read_to_string(home.join("pins").join("smoke.json")).unwrap();
    assert!(!text.contains("e2e-secret-4242"), "{text}");
    assert!(!pin_file.contains("e2e-secret-4242"), "{pin_file}");
}

#[cfg(windows)]
#[test]
fn a_server_that_ignores_eof_is_killed_with_everything_it_started() {
    // Measured on server-everything 2026.8.31: with a request to the client
    // still open it ignores end-of-file, and `Child::kill` on the `cmd.exe`
    // that `npx` runs through left node running.
    if !node_available() {
        return;
    }
    let home = temp_home("stubborn");
    let pid_file = home.join("server.pid");
    let script = fixture("stubborn.cmd");
    let args = [
        "proxy",
        "--name",
        "stubborn",
        "--",
        script.to_str().unwrap(),
        pid_file.to_str().unwrap(),
    ];
    let client = Client::proxy(&home, &args, &[]);
    let pid = wait_for_pid(&pid_file);

    let closed = client.close();
    assert_ne!(closed.status.code(), Some(0), "the server had to be killed");
    assert_gone(&pid);
}

#[cfg(windows)]
#[test]
fn what_a_server_leaves_running_when_it_exits_is_killed() {
    // Regression: the tree was killed only when the server itself had to be.
    // A server that exited first left its helper running, out of its tree and
    // out of `taskkill /T`'s reach, holding the client's pipes.
    if !node_available() {
        return;
    }
    let home = temp_home("orphan");
    let pid_file = home.join("helper.pid");
    let script = fixture("orphaning.cmd");
    let args = [
        "proxy",
        "--name",
        "orphan",
        "--",
        script.to_str().unwrap(),
        pid_file.to_str().unwrap(),
    ];
    let client = Client::proxy(&home, &args, &[]);
    let pid = wait_for_pid(&pid_file);
    let _ = client.close();
    assert_gone(&pid);
}

// The pid a test server wrote to `file`, once it is there.
#[cfg(windows)]
fn wait_for_pid(file: &Path) -> String {
    let deadline = Instant::now() + common::WAIT;
    loop {
        let text = std::fs::read_to_string(file).unwrap_or_default();
        if !text.trim().is_empty() {
            return text.trim().to_owned();
        }
        assert!(Instant::now() < deadline, "the server never started");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(windows)]
fn assert_gone(pid: &str) {
    let tasks = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
        .unwrap();
    let tasks = String::from_utf8_lossy(&tasks.stdout);
    let survived = tasks.contains(&format!("\"{pid}\""));
    if survived {
        // Killed before failing: a survivor holds this test's own output pipes,
        // inherited, and cargo would wait on them forever instead of failing.
        let _ = Command::new("taskkill")
            .args(["/F", "/PID"])
            .arg(pid)
            .output();
    }
    assert!(!survived, "node {pid} survived: {tasks}");
}
