//! The toolgate command-line interface.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use toolgate::{
    Audit, Lock, Pinned, Severity, Signal, audit, diff, escape, pin, render, render_changes,
    tarball_hash, veto_line,
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
}
