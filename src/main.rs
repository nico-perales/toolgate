//! La interfaz de línea de comandos de toolgate.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use toolgate::{Severity, audit, render};

#[derive(Parser, Debug)]
#[command(name = "toolgate", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Analiza el tarball de un servidor MCP.
    Audit {
        /// El .tgz del paquete, tal cual lo publica npm.
        tarball: PathBuf,
        /// Comando que arranca el servidor, para enumerar sus herramientas.
        /// Sin esto solo se hace el análisis estático.
        #[arg(long, num_args = 1.., allow_hyphen_values = true)]
        launch: Option<Vec<String>>,
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
        Command::Audit { tarball, launch } => {
            let bytes = std::fs::read(&tarball)
                .with_context(|| format!("leyendo {}", tarball.display()))?;

            let launch_command = launch
                .as_ref()
                .and_then(|parts| parts.split_first())
                .map(|(command, args)| (command.as_str(), args));

            let report = audit(&bytes, launch_command)?;
            print!("{}", render(&report));

            let critical = report
                .signals
                .iter()
                .filter(|s| s.severity == Severity::Critical)
                .count();
            // Un veto también cuenta: no se puede afirmar que sea seguro.
            if critical > 0 || report.vetoed.is_some() {
                return Ok(ExitCode::from(1));
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
