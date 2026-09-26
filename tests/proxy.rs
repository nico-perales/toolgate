//! The proxy as an MCP client sees it: the real binary, a real server process.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const WAIT: Duration = Duration::from_secs(30);

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

// A fresh toolgate home per test: no test may touch the real one.
fn temp_home(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("toolgate-e2e-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

// The proxy, driven the way an MCP client drives it.
struct Proxy {
    child: Child,
    input: Option<ChildStdin>,
    lines: Receiver<String>,
    stderr: Receiver<String>,
}

impl Proxy {
    fn start(home: &Path, args: &[&str], env: &[(&str, &str)]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_toolgate"))
            .args(args)
            .env("TOOLGATE_HOME", home)
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the toolgate binary starts");
        let stdout = child.stdout.take().unwrap();
        let (line_tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if line_tx.send(line).is_err() {
                    break;
                }
            }
        });
        // Read on a thread of its own, so a full pipe can never block the
        // proxy, and with a timeout later, so a survivor holding it open can
        // never hang the test.
        let mut err = child.stderr.take().unwrap();
        let (err_tx, stderr) = mpsc::channel();
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = err.read_to_string(&mut text);
            let _ = err_tx.send(text);
        });
        let input = child.stdin.take();
        Self {
            child,
            input,
            lines,
            stderr,
        }
    }

    fn send(&mut self, message: &Value) {
        let input = self.input.as_mut().expect("the input is open");
        writeln!(input, "{message}").unwrap();
        input.flush().unwrap();
    }

    // Sends a request and returns the next message the proxy writes.
    fn ask(&mut self, message: &Value) -> Value {
        self.send(message);
        let line = self.lines.recv_timeout(WAIT).expect("the proxy answers");
        serde_json::from_str(&line).expect("everything the proxy writes to stdout is JSON")
    }

    // Closes the proxy's input, as a client does when it quits, and waits for
    // the proxy to exit. Returns its status, what it wrote to stderr, and the
    // messages it wrote to stdout that nobody had read yet.
    fn close(mut self) -> (ExitStatus, String, Vec<String>) {
        drop(self.input.take());
        let deadline = Instant::now() + WAIT;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("the proxy did not exit after its input closed");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let stderr = self
            .stderr
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_default();
        let mut unread = Vec::new();
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(5)) {
            unread.push(line);
        }
        (status, stderr, unread)
    }
}

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
    let mut proxy = Proxy::start(&home, &args, &[("TOOLGATE_TEST_INSTRUCTIONS", "Use ping.")]);

    let init = proxy.ask(&json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": { "name": "test", "version": "1" } } }));
    // The server got the proxy's environment and working directory.
    let cwd = std::env::current_dir().unwrap();
    let expected = format!("Use ping. | cwd={}", cwd.display());
    assert_eq!(init["result"]["instructions"], expected);
    proxy.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));

    let list = proxy.ask(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));
    assert_eq!(list["result"]["tools"][0]["name"], "ping");

    // The complete listing sealed the pin: a name outside it never reaches the
    // server, which would not have answered anyway.
    let call = proxy.ask(&json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": { "name": "ghost", "arguments": {} } }));
    assert_eq!(call["id"], 3);
    assert_eq!(call["result"]["isError"], true);

    // An answer asked for just before the client quits still gets through: the
    // proxy must not exit while it is on its way. It has to be large to catch
    // that. With the wait removed, a small answer almost always won the race
    // anyway, a 4 MB one was lost 4 times in 6, and a 16 MB one every time.
    proxy.send(&json!({ "jsonrpc": "2.0", "id": 4, "method": "test/sized",
        "params": { "bytes": 16_000_000 } }));
    let (status, stderr, unread) = proxy.close();
    assert_eq!(status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(unread.len(), 1, "the last answer was lost");
    assert!(unread[0].len() > 16_000_000);
    assert!(stderr.contains("session log"), "stderr: {stderr}");

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
    std::fs::create_dir_all(&home).unwrap();
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
    let proxy = Proxy::start(&home, &args, &[]);
    let pid = wait_for_pid(&pid_file);

    let (status, _, _) = proxy.close();
    assert_ne!(status.code(), Some(0), "the server had to be killed");
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
    std::fs::create_dir_all(&home).unwrap();
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
    let proxy = Proxy::start(&home, &args, &[]);
    let pid = wait_for_pid(&pid_file);
    let _ = proxy.close();
    assert_gone(&pid);
}

// The pid a test server wrote to `file`, once it is there.
#[cfg(windows)]
fn wait_for_pid(file: &Path) -> String {
    let deadline = Instant::now() + WAIT;
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
