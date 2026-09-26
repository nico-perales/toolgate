//! What the end-to-end tests share: a scripted MCP client that drives either
//! the proxy or a server directly, and the offline commands.
// Each test file compiles this module on its own and uses a different part.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// How long a client waits for an answer by default.
pub const WAIT: Duration = Duration::from_secs(30);

pub fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A fresh toolgate home per test: no test may touch the real one.
pub fn temp_home(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("toolgate-e2e-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Runs one of toolgate's offline commands against `home`; returns its exit
/// code and what it printed.
pub fn toolgate(home: &Path, args: &[&str]) -> (Option<i32>, String) {
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

/// The names of every event in the logs of `server`, in order, across sessions.
pub fn log_events(home: &Path, server: &str) -> Vec<String> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(home.join("logs").join(server))
        .map(|dir| dir.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default();
    files.sort();
    let mut events = Vec::new();
    for file in files {
        for line in std::fs::read_to_string(file).unwrap().lines() {
            let entry: Value = serde_json::from_str(line).unwrap();
            events.push(entry["event"]["event"].as_str().unwrap().to_owned());
        }
    }
    events
}

/// How a client session ended.
pub struct Closed {
    pub status: ExitStatus,
    pub stderr: String,
    /// Messages written to stdout that nobody had read yet.
    pub unread: Vec<String>,
}

/// A scripted MCP client over stdio.
pub struct Client {
    child: Child,
    input: Option<ChildStdin>,
    lines: Receiver<String>,
    stderr: Receiver<String>,
    /// Every line received, raw, in order: answers, notifications and the
    /// server's own requests.
    pub seen: Vec<String>,
    /// How long to wait for an answer.
    pub wait: Duration,
}

impl Client {
    /// The proxy, started with `args` (`proxy … -- <server>`), in `home`.
    pub fn proxy(home: &Path, args: &[&str], env: &[(&str, &str)]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_toolgate"));
        command.args(args).env("TOOLGATE_HOME", home);
        Self::spawn(command, env)
    }

    /// A server run directly, with no proxy in between.
    pub fn direct(program: &str, args: &[&str], env: &[(&str, &str)]) -> Self {
        let mut command = Command::new(toolgate::resolve_command(program));
        command.args(args);
        Self::spawn(command, env)
    }

    fn spawn(mut command: Command, env: &[(&str, &str)]) -> Self {
        let mut child = command
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the process starts");
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
        // process, and with a timeout later, so a survivor holding it open can
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
            seen: Vec::new(),
            wait: WAIT,
        }
    }

    pub fn send(&mut self, message: &Value) {
        let input = self.input.as_mut().expect("the input is open");
        writeln!(input, "{message}").unwrap();
        input.flush().unwrap();
    }

    /// Sends a request and returns its answer, raw. On the way it answers the
    /// server's own requests, the same way every time.
    pub fn request_raw(&mut self, id: u64, method: &str, params: Value) -> String {
        let mut message = json!({ "jsonrpc": "2.0", "id": id, "method": method });
        message["params"] = params;
        self.send(&message);
        loop {
            let line = self
                .lines
                .recv_timeout(self.wait)
                .unwrap_or_else(|_| panic!("no answer to {method}; received {:?}", self.seen));
            self.seen.push(line.clone());
            let message: Value = serde_json::from_str(&line)
                .unwrap_or_else(|_| panic!("a line that is not JSON reached the client: {line}"));
            match (
                message.get("method").and_then(Value::as_str),
                message.get("id"),
            ) {
                (Some(asked), Some(their_id)) => {
                    let result = answer_to(asked);
                    self.send(&json!({ "jsonrpc": "2.0", "id": their_id, "result": result }));
                }
                (None, Some(answered)) if *answered == json!(id) => return line,
                _ => {}
            }
        }
    }

    /// Sends a request and returns its answer.
    pub fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        serde_json::from_str(&self.request_raw(id, method, params)).unwrap()
    }

    /// Closes the input, as a client does when it quits, and waits for the
    /// process to exit.
    pub fn close(mut self) -> Closed {
        drop(self.input.take());
        let deadline = Instant::now() + self.wait;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("the process did not exit after its input closed");
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
        Closed {
            status,
            stderr,
            unread,
        }
    }
}

// What the scripted client answers when a server asks it something.
fn answer_to(method: &str) -> Value {
    match method {
        "roots/list" => json!({ "roots": [{ "uri": "file:///test", "name": "test" }] }),
        "sampling/createMessage" => json!({
            "role": "assistant",
            "content": { "type": "text", "text": "ok" },
            "model": "test",
            "stopReason": "endTurn"
        }),
        "elicitation/create" => json!({ "action": "decline" }),
        _ => json!({}),
    }
}
