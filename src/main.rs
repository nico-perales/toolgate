//! The toolgate command-line interface.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use toolgate::journal::{self, Verdict};
use toolgate::store;
use toolgate::{
    Audit, Lock, Pinned, Severity, Signal, audit, diff, escape, pin, render, render_changes,
    render_review, tarball_hash, veto_line,
};

#[derive(Parser, Debug)]
#[command(name = "toolgate", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Audit an MCP server's npm tarball.
    Audit {
        /// The .tgz exactly as npm publishes it.
        tarball: PathBuf,
        /// After `--`, the command that starts the server so its tools can be
        /// enumerated. Without it, only the static pass runs.
        #[arg(last = true, allow_hyphen_values = true)]
        launch: Vec<String>,
    },

    /// Record the current state of a server — package, capabilities and tools
    /// — as the baseline `check` compares against.
    Pin {
        /// The .tgz exactly as npm publishes it.
        tarball: PathBuf,
        /// Where the baseline is stored.
        #[arg(long, default_value = "toolgate.lock")]
        lock: PathBuf,
        /// Name to store it under. Defaults to the package name.
        #[arg(long)]
        name: Option<String>,
        /// Which MCP client config this lock file corresponds to.
        #[arg(long)]
        config: Option<String>,
        /// Pin even though the audit found critical signals.
        #[arg(long)]
        force: bool,
        /// After `--`, the command that starts the server. Required: pinning
        /// without enumerating would store zero tools, which is precisely what
        /// needs watching.
        #[arg(last = true, allow_hyphen_values = true, required = true)]
        launch: Vec<String>,
    },

    /// Re-audit a server and report what changed since it was pinned.
    Check {
        /// The .tgz exactly as npm publishes it.
        tarball: PathBuf,
        /// Where the baseline was stored.
        #[arg(long, default_value = "toolgate.lock")]
        lock: PathBuf,
        /// Name it was pinned under. Defaults to the package name.
        #[arg(long)]
        name: Option<String>,
        /// After `--`, the command that starts the server.
        #[arg(last = true, allow_hyphen_values = true, required = true)]
        launch: Vec<String>,
    },

    /// Run an MCP server behind toolgate: pin what it declares on first use,
    /// block what changes until you review it, and block hidden text in what
    /// its tools return.
    Proxy {
        /// Name to store the pin under. Defaults to one derived from the whole
        /// command, so changing an argument starts over.
        #[arg(long)]
        name: Option<String>,
        /// After `--`, the command that starts the server.
        #[arg(last = true, allow_hyphen_values = true, required = true)]
        launch: Vec<String>,
    },

    /// Show what changed in a server since you approved it, field by field.
    Review {
        /// The server's name, as given to `proxy --name`. Without it, lists
        /// every server with changes waiting.
        name: Option<String>,
    },

    /// Approve a server's pending changes. They take effect when your client
    /// reconnects the server.
    Accept {
        /// The server's name, as given to `proxy --name`.
        name: String,
        /// Approve critical findings too.
        #[arg(long)]
        force: bool,
    },

    /// Check the hash chain of a proxy session log.
    VerifyLog {
        /// A `.jsonl` file from the logs directory.
        file: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("toolgate: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        Command::Audit { tarball, launch } => run_audit(&tarball, &launch),
        Command::Pin {
            tarball,
            launch,
            lock,
            name,
            config,
            force,
        } => run_pin(&tarball, &launch, &lock, name, config, force),
        Command::Check {
            tarball,
            launch,
            lock,
            name,
        } => run_check(&tarball, &launch, &lock, name),
        Command::Proxy { name, launch } => Ok(ExitCode::from(toolgate::proxy::run(
            name.as_deref(),
            &launch,
        )?)),
        Command::Review { name } => run_review(name.as_deref()),
        Command::Accept { name, force } => run_accept(&name, force),
        Command::VerifyLog { file } => run_verify_log(&file),
    }
}

// --- helpers ---

fn read_tarball_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn split_launch(parts: &[String]) -> Result<(&str, &[String])> {
    parts
        .split_first()
        .map(|(command, args)| (command.as_str(), args))
        .context("`--` must be followed by the command that starts the server")
}

/// Turns "@scope/name@1.2.3" into "@scope/name", and "name@1.2.3" into "name".
fn server_key(package: &str) -> &str {
    match package.rsplit_once('@') {
        Some((name, _)) if !name.is_empty() => name,
        _ => package,
    }
}

fn critical_signals(report: &Audit) -> Vec<&Signal> {
    report
        .signals
        .iter()
        .filter(|s| s.severity == Severity::Critical)
        .collect()
}

/// A copy without tools, so only the static half is compared when the server
/// could not be enumerated.
fn without_tools(pinned: &Pinned) -> Pinned {
    Pinned {
        tools: Vec::new(),
        tools_hash: String::new(),
        ..pinned.clone()
    }
}

fn load_lock(path: &Path) -> Result<Option<Lock>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let lock = toolgate::read_lock(&text)
                .with_context(|| format!("{} is not a valid lock file", path.display()))?;
            Ok(Some(lock))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
    }
}

fn save_lock(path: &Path, lock: &Lock) -> Result<()> {
    let mut text = serde_json::to_string_pretty(lock).context("serialising the lock file")?;
    text.push('\n');
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}

fn pinned_from(report: &Audit, bytes: &[u8]) -> Pinned {
    pin(
        &report.package,
        &tarball_hash(bytes),
        &report.capability_names(),
        &report.tools,
    )
}

// --- subcommands ---

fn run_audit(tarball: &Path, launch: &[String]) -> Result<ExitCode> {
    let bytes = read_tarball_file(tarball)?;
    // Empty means no launch was requested: static analysis only.
    let launch_command = if launch.is_empty() {
        None
    } else {
        Some(split_launch(launch)?)
    };

    let report = audit(&bytes, launch_command)?;
    print!("{}", render(&report));

    // A veto counts too: there is no basis for calling it safe.
    if !critical_signals(&report).is_empty() || report.vetoed.is_some() {
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

fn run_pin(
    tarball: &Path,
    launch: &[String],
    lock_path: &Path,
    name: Option<String>,
    config: Option<String>,
    force: bool,
) -> Result<ExitCode> {
    let bytes = read_tarball_file(tarball)?;
    let (command, args) = split_launch(launch)?;
    let report = audit(&bytes, Some((command, args)))?;
    print!("{}", render(&report));

    // The report above already shows the veto reason, escaped.
    if report.vetoed.is_some() {
        eprintln!("\ntoolgate: nothing pinned: the static pass vetoed the launch.");
        eprintln!("Pinning without enumerating would store zero tools, and the");
        eprintln!("next check would see every one of them appear as new.");
        return Ok(ExitCode::from(1));
    }
    if report.tools.is_empty() {
        eprintln!("\ntoolgate: the server declared no tools at all.");
        eprintln!("There is nothing to pin.");
        return Ok(ExitCode::from(1));
    }
    if !force && !critical_signals(&report).is_empty() {
        eprintln!("\ntoolgate: there are unresolved critical signals.");
        eprintln!("Pinning now would freeze this as your trusted baseline.");
        eprintln!("Review it; if you accept it anyway, repeat with --force.");
        return Ok(ExitCode::from(1));
    }

    let key = name.unwrap_or_else(|| server_key(&report.package).to_owned());
    let mut lock =
        load_lock(lock_path)?.unwrap_or_else(|| Lock::new(config.as_deref().unwrap_or("")));
    if let Some(config) = config {
        lock.config = config;
    }
    let replaced = lock
        .servers
        .insert(key.clone(), pinned_from(&report, &bytes));
    save_lock(lock_path, &lock)?;

    let verb = if replaced.is_some() {
        "Re-pinned"
    } else {
        "Pinned"
    };
    println!(
        "\n{verb} {} in {} — {} · {} tool(s)",
        escape(&key),
        lock_path.display(),
        escape(&report.package),
        report.tools.len()
    );
    Ok(ExitCode::SUCCESS)
}

fn run_check(
    tarball: &Path,
    launch: &[String],
    lock_path: &Path,
    name: Option<String>,
) -> Result<ExitCode> {
    let bytes = read_tarball_file(tarball)?;
    let (command, args) = split_launch(launch)?;
    let report = audit(&bytes, Some((command, args)))?;

    let key = name.unwrap_or_else(|| server_key(&report.package).to_owned());
    let lock = load_lock(lock_path)?.with_context(|| {
        format!(
            "{} does not exist; record a baseline with `toolgate pin` first",
            lock_path.display()
        )
    })?;
    let old = lock.servers.get(&key).with_context(|| {
        format!(
            "nothing is pinned for {} in {}",
            escape(&key),
            lock_path.display()
        )
    })?;
    let new = pinned_from(&report, &bytes);

    if let Some(reason) = &report.vetoed {
        // Diffing tools here would claim they all vanished, and that would
        // be a lie: they were never looked at.
        let static_changes = diff(&without_tools(old), &without_tools(&new));
        print!("{}", render_changes(&static_changes));
        println!("\n{}", veto_line(reason));
        println!("The tools were NOT compared; the above covers only the static");
        println!("half. A server that was fine when pinned and now refuses to be");
        println!("enumerated is itself a change.");
        return Ok(ExitCode::from(1));
    }

    let changes = diff(old, &new);
    print!("{}", render_changes(&changes));

    let critical = critical_signals(&report);
    if !critical.is_empty() {
        println!(
            "\nAlso, {} critical signal(s) still standing:",
            critical.len()
        );
        for signal in &critical {
            println!("  x {} — {}", escape(&signal.tool), signal.detail);
        }
    }

    if changes.is_empty() && critical.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    Ok(ExitCode::from(1))
}

fn run_review(name: Option<&str>) -> Result<ExitCode> {
    let home = store::home()?;
    let Some(name) = name else {
        return review_all(&home);
    };
    let key = store::server_key(Some(name), &[])?;
    let pin = store::load(&home, &key)?
        .with_context(|| format!("nothing is pinned for {key} in {}", home.display()))?;
    print!("{}", render_review(&pin));
    if pin.pending.is_some() {
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

// Every pinned server, and which of them have changes waiting.
fn review_all(home: &Path) -> Result<ExitCode> {
    let dir = home.join("pins");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("No servers pinned yet in {}.", home.display());
            return Ok(ExitCode::SUCCESS);
        }
        Err(err) => return Err(err).with_context(|| format!("reading {}", dir.display())),
    };
    let mut keys = Vec::new();
    for entry in entries {
        let path = entry
            .with_context(|| format!("reading {}", dir.display()))?
            .path();
        if path.extension().is_some_and(|e| e == "json") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                keys.push(stem.to_owned());
            }
        }
    }
    keys.sort();
    let mut waiting = 0usize;
    for key in &keys {
        match store::load(home, key) {
            Ok(Some(pin)) => {
                if let Some(pending) = &pin.pending {
                    waiting += 1;
                    let count = pending.tools.len() + usize::from(pending.instructions.is_some());
                    println!(
                        "  {}: {count} change(s) waiting; run `toolgate review {}`",
                        escape(key),
                        escape(key)
                    );
                }
            }
            Ok(None) => {}
            Err(err) => println!("  ! {}: {err}", escape(key)),
        }
    }
    if waiting == 0 {
        println!(
            "Nothing waiting for review ({} server(s) pinned).",
            keys.len()
        );
        return Ok(ExitCode::SUCCESS);
    }
    Ok(ExitCode::from(1))
}

fn run_accept(name: &str, force: bool) -> Result<ExitCode> {
    let home = store::home()?;
    let key = store::server_key(Some(name), &[])?;
    let mut pin = store::load(&home, &key)?
        .with_context(|| format!("nothing is pinned for {key} in {}", home.display()))?;
    let accepted = match pin.accept(force) {
        Ok(accepted) => accepted,
        Err(err) => {
            eprintln!("toolgate: {err}");
            eprintln!("Nothing was approved. Look first: toolgate review {key}");
            return Ok(ExitCode::from(1));
        }
    };
    if accepted.promoted.is_empty() && accepted.dropped.is_empty() && !accepted.instructions {
        println!("Nothing waiting for review in {key}.");
        return Ok(ExitCode::SUCCESS);
    }
    store::save(&home, &pin)?;
    if !accepted.promoted.is_empty() {
        println!("Approved in {key}: {}", names(&accepted.promoted));
    }
    if accepted.instructions {
        println!("Approved the new instructions of {key}.");
    }
    if !accepted.dropped.is_empty() {
        println!("Dropped, never pinnable: {}", names(&accepted.dropped));
    }
    println!("Reconnect the server in your client (for example `/mcp` in Claude Code):");
    println!("a session already running keeps enforcing the old pin until it restarts.");
    Ok(ExitCode::SUCCESS)
}

// Names that came from a server, escaped, on one line.
fn names(list: &[String]) -> String {
    list.iter()
        .map(String::as_str)
        .map(escape)
        .collect::<Vec<_>>()
        .join(", ")
}

fn run_verify_log(file: &Path) -> Result<ExitCode> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    match journal::verify(&bytes) {
        Verdict::Intact { lines, head } => {
            println!("Intact: {lines} line(s), and the session closed normally.");
            println!("Head: {head}");
            println!(
                "Compare it with the head the session printed to stderr, in your client's logs."
            );
            Ok(ExitCode::SUCCESS)
        }
        Verdict::Unfinished { lines, head } => {
            println!("The chain holds for {lines} line(s), but the session never closed.");
            println!(
                "That is a crash, a kill, or a cut at the end: a hash chain cannot tell which."
            );
            println!("Head: {head}");
            Ok(ExitCode::from(1))
        }
        Verdict::Broken { seq, reason } => {
            println!("BROKEN at line {seq}: {reason}.");
            Ok(ExitCode::from(1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command, server_key};
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("should parse")
    }

    #[test]
    fn a_flag_after_the_command_separator_is_not_swallowed() {
        // Regression: with a variadic `--launch`, a later `--lock` ended up as
        // an argument to the server, so `check` read the default lock file and
        // reported "no changes". A false all-clear is the worst possible
        // failure in a security tool.
        let cli = parse(&[
            "toolgate",
            "check",
            "p.tgz",
            "--lock",
            "mine.lock",
            "--",
            "node",
            "s.js",
        ]);
        match cli.command {
            Command::Check { lock, launch, .. } => {
                assert_eq!(lock.to_str().unwrap(), "mine.lock");
                assert_eq!(launch, ["node", "s.js"]);
            }
            other => panic!("expected Check, got {other:?}"),
        }
    }

    #[test]
    fn the_server_command_keeps_its_own_hyphenated_flags() {
        let cli = parse(&["toolgate", "pin", "p.tgz", "--", "npx", "-y", "@acme/mcp"]);
        match cli.command {
            Command::Pin { launch, .. } => assert_eq!(launch, ["npx", "-y", "@acme/mcp"]),
            other => panic!("expected Pin, got {other:?}"),
        }
    }

    #[test]
    fn pin_and_check_refuse_to_run_without_a_launch_command() {
        // Pinning without enumerating would store zero tools.
        assert!(Cli::try_parse_from(["toolgate", "pin", "p.tgz"]).is_err());
        assert!(Cli::try_parse_from(["toolgate", "check", "p.tgz"]).is_err());
    }

    #[test]
    fn audit_still_works_without_one() {
        let cli = parse(&["toolgate", "audit", "p.tgz"]);
        match cli.command {
            Command::Audit { launch, .. } => assert!(launch.is_empty()),
            other => panic!("expected Audit, got {other:?}"),
        }
    }

    #[test]
    fn the_lock_key_drops_the_version_but_keeps_the_scope() {
        assert_eq!(server_key("@acme/docs-mcp@1.4.0"), "@acme/docs-mcp");
        assert_eq!(server_key("docs-mcp@1.4.0"), "docs-mcp");
        // With no version there is nothing to strip.
        assert_eq!(server_key("@acme/docs-mcp"), "@acme/docs-mcp");
    }

    #[test]
    fn proxy_keeps_the_server_command_after_the_separator() {
        let cli = parse(&[
            "toolgate", "proxy", "--name", "gh", "--", "npx", "-y", "@x/gh", "--name", "inner",
        ]);
        match cli.command {
            Command::Proxy { name, launch } => {
                assert_eq!(name.as_deref(), Some("gh"));
                assert_eq!(launch, ["npx", "-y", "@x/gh", "--name", "inner"]);
            }
            other => panic!("expected Proxy, got {other:?}"),
        }
    }

    #[test]
    fn proxy_refuses_to_run_without_a_server_command() {
        assert!(Cli::try_parse_from(["toolgate", "proxy"]).is_err());
    }

    #[test]
    fn the_offline_commands_parse() {
        assert!(matches!(
            parse(&["toolgate", "review"]).command,
            Command::Review { name: None }
        ));
        assert!(matches!(
            parse(&["toolgate", "accept", "gh", "--force"]).command,
            Command::Accept { force: true, .. }
        ));
        assert!(matches!(
            parse(&["toolgate", "verify-log", "x.jsonl"]).command,
            Command::VerifyLog { .. }
        ));
    }
}
