//! Cliente MCP mínimo: lo justo para enumerar herramientas.
//!
//! Transporte stdio: JSON-RPC 2.0, un objeto JSON por línea. Este cliente es
//! además el cimiento del proxy de una fase posterior, así que no es trabajo
//! desechable.

use std::time::Duration;

use serde_json::{Value, json};

use crate::error::Error;
use crate::launch::Contained;
use crate::tool::Tool;

// Se imita a un cliente real: un `clientInfo` delator le regalaría a un servidor
// adaptativo la detección de que lo están auditando. No lo impide —eso solo lo
// arregla el proxy— pero sube el listón.
const CLIENT_NAME: &str = "claude-code";
const CLIENT_VERSION: &str = "1.0.0";
const PROTOCOL: &str = "2024-11-05";

fn send(server: &mut Contained, message: &Value) -> Result<(), Error> {
    server.send_line(&message.to_string())
}

// Lee líneas hasta encontrar la respuesta a `id`, saltando notificaciones y
// cualquier ruido que el servidor escriba por stdout.
fn read_response(server: &mut Contained, id: u64, timeout: Duration) -> Result<Value, Error> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(Error::Timeout);
        }
        let line = server.recv_line(remaining)?;
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue; // no todo lo que sale por stdout es JSON-RPC
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

/// Handshake y enumeración de herramientas.
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

    // Notificación: no lleva id y no espera respuesta.
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

    // El cwd del hijo es un temporal, así que la ruta del script debe ser
    // absoluta o node no la encuentra.
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
            return; // sin Node instalado, el test se salta
        };
        let tools = list_tools(&mut server, Duration::from_secs(15)).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "ping");
        assert_eq!(tools[0].description, "Responde pong.");
    }

    #[test]
    fn a_server_that_says_nothing_times_out() {
        let Ok(mut server) = Contained::spawn("node", &["-e".to_owned(), String::new()]) else {
            return;
        };
        assert!(list_tools(&mut server, Duration::from_millis(400)).is_err());
    }
}
