//! `toolgate proxy`: an MCP server run behind the relay.
//!
//! The server gets the proxy's whole environment and working directory, as it
//! would have got them from the client. This is not `launch::Contained`, which
//! clears both: right for an audit, wrong for a server in use.
#![deny(clippy::print_stdout)]

use std::fs::File;
use std::io::{BufReader, Stdout};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::journal::{self, Journal, Marker};
use crate::policy::{Event, Session};
use crate::relay::{Outlet, Relay, SavePin, pump};
use crate::resolve::resolve_command;
use crate::store::{self, PinState, ServerPin};

/// The longest line accepted from a server. An image in base64 runs to a few
/// MB; a longer line is dropped rather than held in memory.
pub const MAX_LINE: usize = 64 * 1024 * 1024;

// How long a server gets to exit by itself once its input is closed.
const GRACE: Duration = Duration::from_secs(5);

// Which side ended the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    Client,
    Server,
    Panic,
}

// Tells the main thread a relay thread ended. Its drop also runs while
// unwinding, so a panic is reported, never silent.
struct Signal {
    done: Sender<End>,
    side: End,
}

impl Drop for Signal {
    fn drop(&mut self) {
        let end = if thread::panicking() {
            End::Panic
        } else {
            self.side
        };
        let _ = self.done.send(end);
    }
}

// What both relay threads share.
#[derive(Clone)]
struct Shared {
    relay: Arc<Relay>,
    client: Arc<Outlet<Stdout>>,
    server: Arc<Outlet<ChildStdin>>,
    book: Arc<Book>,
}

/// Runs the server in `launch` behind the proxy until either side ends the
/// session. Returns the exit code to leave with: the server's own.
pub fn run(name: Option<&str>, launch: &[String]) -> Result<u8, Error> {
    let Some((command, args)) = launch.split_first() else {
        return Err(Error::Proxy("no command to start the server".to_owned()));
    };
    let key = store::server_key(name, launch)?;
    let home = store::home()?;
    // Read once, before the server starts: a server that can write files must
    // not get to change the pin this session enforces.
    let pin = store::load(&home, &key)?.unwrap_or_else(|| ServerPin::new(&key, launch));

    let mut child = Command::new(resolve_command(command))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|source| Error::Io {
            path: command.clone(),
            source,
        })?;
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        kill_tree(&mut child);
        return Err(Error::Proxy(
            "the server exposes no stdin or stdout".to_owned(),
        ));
    };

    let shared = Shared {
        book: Arc::new(Book::open(&home, &key, launch, pin.state)),
        relay: Arc::new(Relay::new(Session::new(pin), journal::now_ms, saver(home))),
        client: Arc::new(Outlet::new(std::io::stdout())),
        server: Arc::new(Outlet::new(stdin)),
    };
    let (done, finished) = mpsc::channel();

    let up = shared.clone();
    let up_done = done.clone();
    thread::spawn(move || {
        let guard = Signal {
            done: up_done,
            side: End::Client,
        };
        let _ = pump(
            std::io::stdin().lock(),
            usize::MAX,
            &|line: &[u8]| up.relay.from_client(line),
            up.client.as_ref(),
            up.server.as_ref(),
            &|events: &[Event]| up.book.record(events),
        );
        // The client is gone: closing the server's input tells it to exit.
        up.server.close();
        drop(guard);
    });
    let down = shared.clone();
    thread::spawn(move || {
        let guard = Signal {
            done,
            side: End::Server,
        };
        let _ = pump(
            BufReader::new(stdout),
            MAX_LINE,
            &|line: &[u8]| down.relay.from_server(line),
            down.client.as_ref(),
            down.server.as_ref(),
            &|events: &[Event]| down.book.record(events),
        );
        drop(guard);
    });

    let (status, panicked) = wait_for_end(&mut child, &finished);
    shared.book.record(&shared.relay.finish());
    shared.book.end(status.and_then(|s| s.code()));
    if panicked {
        return Err(Error::Proxy(
            "a relay thread panicked; the server was stopped".to_owned(),
        ));
    }
    Ok(exit_code(status))
}

// Saves the pin whenever the policy changes it. A pin that cannot be written
// is reported, and the session carries on with the one in memory.
fn saver(home: PathBuf) -> SavePin {
    Box::new(move |pin: &ServerPin| {
        if let Err(e) = store::save(&home, pin) {
            eprintln!(
                "toolgate: could not save the pin for {}: {e}. What this session approved or blocked will not be remembered.",
                pin.server
            );
        }
    })
}

// Waits for a side to end the session, then makes sure the server is gone.
// Returns its exit status, if it gave one, and whether a relay thread panicked.
fn wait_for_end(child: &mut Child, finished: &Receiver<End>) -> (Option<ExitStatus>, bool) {
    loop {
        match finished.recv_timeout(Duration::from_millis(50)) {
            Ok(End::Panic) => {
                kill_tree(child);
                return (child.wait().ok(), true);
            }
            Ok(End::Client) => {
                // The client stopped writing, but may still be reading: what
                // the server answered before it exited must get through.
                let status = stop(child);
                drain(finished);
                return (status, false);
            }
            Ok(End::Server) | Err(RecvTimeoutError::Disconnected) => {
                return (stop(child), false);
            }
            Err(RecvTimeoutError::Timeout) => {
                // A server can exit while a process it started still holds its
                // output open, and then the relay never sees that output end.
                if let Ok(Some(status)) = child.try_wait() {
                    drain(finished);
                    return (Some(status), false);
                }
            }
        }
    }
}

// Gives the server side of the relay time to pass on what the server wrote
// before it exited. Returning from `run` ends the process, and that thread with
// it, whether or not it had finished: without this, a 16 MB answer asked for
// just before the client quit was lost every time. It only waits the full
// `GRACE` when a process the server started still holds its output open.
fn drain(finished: &Receiver<End>) {
    let deadline = Instant::now() + GRACE;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match finished.recv_timeout(left) {
            Ok(End::Server) | Err(_) => return,
            Ok(End::Client | End::Panic) => {}
        }
    }
}

// Gives the server `GRACE` to exit by itself, then kills it and everything it
// started. A server with a request to the client still open may ignore its
// end-of-file: server-everything did, until its own 60-second timeout.
fn stop(child: &mut Child) -> Option<ExitStatus> {
    let deadline = Instant::now() + GRACE;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => break,
        }
    }
    kill_tree(child);
    child.wait().ok()
}

// Kills the server and every process it started. On Windows `npx` runs through
// `cmd.exe`, so the direct child is the shell, and `Child::kill` alone leaves
// node running: measured on server-everything 2026.8.31, three processes
// survived it, and none survived `taskkill /T`. Its output goes nowhere near
// stdout, which belongs to the MCP client.
fn kill_tree(child: &mut Child) {
    #[cfg(windows)]
    {
        let taskkill = std::env::var_os("SystemRoot").map_or_else(
            || PathBuf::from("taskkill.exe"),
            |root| PathBuf::from(root).join("System32").join("taskkill.exe"),
        );
        let _ = Command::new(taskkill)
            .args(["/T", "/F", "/PID"])
            .arg(child.id().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
}

// The server's own exit code when it has one that fits; 1 when it was killed.
fn exit_code(status: Option<ExitStatus>) -> u8 {
    status
        .and_then(|s| s.code())
        .and_then(|c| u8::try_from(c).ok())
        .unwrap_or(1)
}

// The session's log, and the few lines the user sees on stderr. A log that
// cannot be written is reported once and then skipped: no decision depends on
// it, and stopping the relay would cost the user the server for nothing.
struct Book {
    server: String,
    path: Option<PathBuf>,
    journal: Mutex<Option<Journal<File>>>,
}

impl Book {
    fn open(home: &Path, server: &str, command: &[String], pin: PinState) -> Self {
        let now = journal::now_ms();
        let start = Marker::SessionStart {
            server,
            command,
            pin,
            toolgate: env!("CARGO_PKG_VERSION"),
        };
        let (path, journal) = match journal::open(home, server, now) {
            Ok((path, mut journal)) => match journal.record(now, &start) {
                Ok(()) => (Some(path), Some(journal)),
                Err(e) => {
                    eprintln!("toolgate: the session log failed: {e}");
                    (Some(path), None)
                }
            },
            Err(e) => {
                eprintln!("toolgate: no session log: {e}");
                (None, None)
            }
        };
        Self {
            server: server.to_owned(),
            path,
            journal: Mutex::new(journal),
        }
    }

    fn record(&self, events: &[Event]) {
        let changed = events
            .iter()
            .filter(|e| matches!(e, Event::ToolStubbed { .. } | Event::ToolHidden { .. }))
            .count();
        if changed > 0 {
            eprintln!(
                "toolgate: {changed} tool(s) in '{}' changed or appeared since you approved it; run `toolgate review {}`",
                self.server, self.server
            );
        }
        let mut guard = self.journal.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(journal) = guard.as_mut() else {
            return;
        };
        let now = journal::now_ms();
        for event in events {
            if let Err(e) = journal.record(now, event) {
                eprintln!("toolgate: the session log stopped: {e}");
                *guard = None;
                return;
            }
        }
    }

    fn end(&self, exit: Option<i32>) {
        let mut guard = self.journal.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(journal) = guard.as_mut() else {
            return;
        };
        let events = journal.count();
        let closed = journal.record(journal::now_ms(), &Marker::SessionEnd { events, exit });
        if let (Ok(()), Some(path)) = (closed, &self.path) {
            // The client keeps this line in its own logs: the one anchor for
            // the chain outside the file.
            eprintln!(
                "toolgate: session log {} (head {})",
                path.display(),
                journal.head()
            );
        }
    }
}
