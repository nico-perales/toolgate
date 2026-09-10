//! Contained launch of an MCP server.
//!
//! **This is not a sandbox.** It reduces the surface — minimal environment,
//! temporary cwd, timeout, bounded reads — but it does not contain an attacker.
//! The README says so just as plainly, not in the small print.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::Duration;

use crate::error::Error;

// A malicious server can flood stdout, so we cut it off.
const MAX_LINES: usize = 10_000;

pub struct Contained {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
}

impl Contained {
    /// Starts the server with a reduced environment and bounded output.
    pub fn spawn(command: &str, args: &[String]) -> Result<Contained, Error> {
        let cwd = std::env::temp_dir().join(format!("toolgate-{}", std::process::id()));
        std::fs::create_dir_all(&cwd).map_err(|e| Error::Io {
            path: cwd.display().to_string(),
            source: e,
        })?;

        let mut child = Command::new(command)
            .args(args)
            // Minimal environment: it inherits neither your variables nor your
            // credentials. Only PATH, so the process can find its binaries.
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .current_dir(&cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::Io {
                path: command.to_owned(),
                source: e,
            })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Protocol("the process exposes no stdin".to_owned()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Protocol("the process exposes no stdout".to_owned()))?;

        // A reader thread pushing lines down a channel: the portable way to get
        // a read timeout without async or OS-specific APIs.
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().take(MAX_LINES) {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        Ok(Contained {
            child,
            stdin,
            lines,
        })
    }

    pub fn send_line(&mut self, text: &str) -> Result<(), Error> {
        writeln!(self.stdin, "{text}").map_err(|e| Error::Io {
            path: "stdin".to_owned(),
            source: e,
        })?;
        self.stdin.flush().map_err(|e| Error::Io {
            path: "stdin".to_owned(),
            source: e,
        })
    }

    pub fn recv_line(&mut self, timeout: Duration) -> Result<String, Error> {
        match self.lines.recv_timeout(timeout) {
            Ok(line) => Ok(line),
            Err(RecvTimeoutError::Timeout) => Err(Error::Timeout),
            Err(RecvTimeoutError::Disconnected) => {
                Err(Error::Protocol("the server closed its output".to_owned()))
            }
        }
    }
}

impl Drop for Contained {
    fn drop(&mut self) {
        // An untrusted server is never left running.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::Contained;
    use std::time::Duration;

    #[test]
    fn spawning_a_missing_command_fails() {
        assert!(Contained::spawn("command_that_does_not_exist_xyz", &[]).is_err());
    }

    #[test]
    fn reading_with_nothing_to_read_times_out() {
        // `node -e ""` starts up and writes nothing.
        let Ok(mut server) = Contained::spawn("node", &["-e".to_owned(), String::new()]) else {
            return; // without Node installed, skip
        };
        assert!(server.recv_line(Duration::from_millis(400)).is_err());
    }

    #[test]
    fn round_trips_a_line() {
        let script = "process.stdin.on('data', d => process.stdout.write(d));";
        let Ok(mut server) = Contained::spawn("node", &["-e".to_owned(), script.to_owned()]) else {
            return;
        };
        server.send_line("hello").unwrap();
        let line = server.recv_line(Duration::from_secs(10)).unwrap();
        assert_eq!(line.trim(), "hello");
    }

    #[test]
    fn the_environment_is_minimal() {
        // The child must not inherit the parent's environment: only PATH, so it
        // can find its binaries. `set_var` is no use here because the crate
        // forbids `unsafe`, so we measure the resulting environment instead.
        let script = "process.stdout.write(Object.keys(process.env).length + \":\" + String(!!process.env.PATH));";
        let Ok(mut server) = Contained::spawn("node", &["-e".to_owned(), script.to_owned()]) else {
            return;
        };
        let line = server.recv_line(Duration::from_secs(10)).unwrap();
        let (count, has_path) = line.trim().split_once(char::from(58)).unwrap();
        assert_eq!(has_path, "true", "the child needs PATH");
        let count: usize = count.parse().unwrap();
        assert!(
            count < 5,
            "the environment should be minimal, it has {count} variables"
        );
    }
}
