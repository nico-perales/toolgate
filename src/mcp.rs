//! A minimal MCP client: just enough to enumerate tools.
//!
//! Transport is stdio: JSON-RPC 2.0, one JSON object per line. This client is
//! also the foundation of the later proxy, so none of it is throwaway work.

use std::time::Duration;

use serde_json::{Value, json};

use crate::error::Error;
use crate::launch::Contained;
use crate::tool::Tool;

// We imitate a real client: a tell-tale `clientInfo` would hand an adaptive
// server the detection that it is being audited. This does not prevent that —
// only the proxy does — but it raises the bar.
const CLIENT_NAME: &str = "claude-code";
const CLIENT_VERSION: &str = "1.0.0";
const PROTOCOL: &str = "2024-11-05";

fn send(server: &mut Contained, message: &Value) -> Result<(), Error> {
    server.send_line(&message.to_string())
}

// Reads lines until the response to `id` shows up, skipping notifications and
// whatever noise the server writes to stdout.
fn read_response(server: &mut Contained, id: u64, timeout: Duration) -> Result<Value, Error> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(Error::Timeout);
        }
        let line = server.recv_line(remaining)?;
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue; // not everything on stdout is JSON-RPC
        };
        if value.get("id").and_then(Value::as_u64) == Some(id) {
            if let Some(err) = value.get("error") {
                return Err(Error::Protocol(err.to_string()));
            }
            return value
                .get("result")
                .cloned()
                .ok_or_else(|| Error::Protocol("response has no result field".to_owned()));
        }
    }
}

/// Handshake, then enumerate the server's tools.
pub fn list_tools(server: &mut Contained, timeout: Duration) -> Result<Vec<Tool>, Error> {
    send(
        server,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL,
                "capabilities": {},
                "clientInfo": { "name": CLIENT_NAME, "version": CLIENT_VERSION }
            }
        }),
    )?;
    read_response(server, 1, timeout)?;

    // A notification: it carries no id and expects no response.
    send(
        server,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )?;

    send(
        server,
        &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    )?;
    let result = read_response(server, 2, timeout)?;

    let tools = result
        .get("tools")
        .cloned()
        .ok_or_else(|| Error::Protocol("tools/list response has no tools field".to_owned()))?;
    serde_json::from_value(tools).map_err(|e| Error::Protocol(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::list_tools;
    use crate::launch::Contained;
    use std::time::Duration;

    // The child's cwd is a temporary directory, so the script path has to be
    // absolute or node will not find it.
    fn fixture(name: &str) -> String {
        std::env::current_dir()
            .unwrap()
            .join("tests/fixtures")
            .join(name)
            .display()
            .to_string()
    }

    #[test]
    fn lists_the_tools_of_a_minimal_server() {
        let Ok(mut server) = Contained::spawn("node", &[fixture("fake_server.js")]) else {
            return; // without Node installed, skip
        };
        let tools = list_tools(&mut server, Duration::from_secs(15)).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "ping");
        assert_eq!(tools[0].description, "Answers pong.");
    }

    #[test]
    fn a_server_that_says_nothing_times_out() {
        let Ok(mut server) = Contained::spawn("node", &["-e".to_owned(), String::new()]) else {
            return;
        };
        assert!(list_tools(&mut server, Duration::from_millis(400)).is_err());
    }
}
