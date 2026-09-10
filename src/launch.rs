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

// The only variables the child is allowed to see. Everything else is dropped:
// an MCP server has no business reading your tokens.
//
// Windows needs more than PATH. `SystemRoot` is where Win32 finds its own DLLs,
// and without it the Winsock and crypto initialisers fail, so the process dies
// on startup instead of reporting anything. None of these leak user data.
#[cfg(windows)]
const ALLOWED_ENV: &[&str] = &["PATH", "SYSTEMROOT", "WINDIR"];
#[cfg(not(windows))]
const ALLOWED_ENV: &[&str] = &["PATH"];

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

        // Minimal environment: it inherits neither your variables nor your
        // credentials, only what the platform needs to start a process at all.
        let mut builder = Command::new(command);
        builder.args(args).env_clear();
        for name in ALLOWED_ENV {
            if let Ok(value) = std::env::var(name) {
                builder.env(name, value);
            }
        }

        let mut child = builder
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
    use super::{ALLOWED_ENV, Contained};
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
    fn the_child_sees_only_the_allowed_variables() {
        // Asserting the actual property beats counting: an earlier version of
        // this test checked `count < 5`, which says nothing about *which*
        // variables got through and breaks the moment the allowlist changes.
        let script = "process.stdout.write(Object.keys(process.env).sort().join(','));";
        let Ok(mut server) = Contained::spawn("node", &["-e".to_owned(), script.to_owned()]) else {
            return; // without Node installed, skip
        };
        let line = server
            .recv_line(Duration::from_secs(10))
            .expect("the child must survive a cleared environment");

        let names: Vec<&str> = line.trim().split(',').filter(|n| !n.is_empty()).collect();
        let leaked: Vec<&&str> = names
            .iter()
            .filter(|name| !ALLOWED_ENV.iter().any(|a| a.eq_ignore_ascii_case(name)))
            .collect();
        assert!(leaked.is_empty(), "the child inherited {leaked:?}");
        assert!(
            names.iter().any(|n| n.eq_ignore_ascii_case("PATH")),
            "the child needs PATH to find its binaries, got {names:?}"
        );
        // The regression this encodes: without SystemRoot, Win32 initialisation
        // fails and the child dies before writing a byte. Node 20 happens to
        // tolerate it; the CI runners' Node does not.
        #[cfg(windows)]
        assert!(
            names.iter().any(|n| n.eq_ignore_ascii_case("SYSTEMROOT")),
            "on Windows the child needs SystemRoot, got {names:?}"
        );
    }
}
