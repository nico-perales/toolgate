//! La interfaz de línea de comandos de toolgate.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use toolgate::{
    Audit, Lock, Pinned, Severity, Signal, audit, diff, pin, render, render_changes, tarball_hash,
};

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
        /// Tras `--`, el comando que arranca el servidor para enumerar sus
        /// herramientas. Sin esto solo se hace el análisis estático.
        #[arg(last = true, allow_hyphen_values = true)]
        launch: Vec<String>,
    },

    /// Fija el estado actual de un servidor: paquete, capacidades y
    /// herramientas. Es la línea base contra la que compara `check`.
    Pin {
        tarball: PathBuf,
        #[arg(long, default_value = "toolgate.lock")]
        lock: PathBuf,
        /// Con qué nombre se guarda. Por defecto, el del paquete.
        #[arg(long)]
        name: Option<String>,
        /// A qué configuración de cliente MCP corresponde este bloqueo.
        #[arg(long)]
        config: Option<String>,
        /// Fija aunque la auditoría haya encontrado señales críticas.
        #[arg(long)]
        force: bool,
        /// Tras `--`, el comando que arranca el servidor. Obligatorio: fijar
        /// sin enumerar guardaría cero herramientas, que es justo lo que hay
        /// que vigilar.
        #[arg(last = true, allow_hyphen_values = true, required = true)]
        launch: Vec<String>,
    },

    /// Vuelve a auditar y compara con lo fijado.
    Check {
        tarball: PathBuf,
        #[arg(long, default_value = "toolgate.lock")]
        lock: PathBuf,
        #[arg(long)]
        name: Option<String>,
        /// Tras `--`, el comando que arranca el servidor.
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
    }
}

// --- utilidades ---

fn read_tarball_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("leyendo {}", path.display()))
}

fn split_launch(parts: &[String]) -> Result<(&str, &[String])> {
    parts
        .split_first()
        .map(|(command, args)| (command.as_str(), args))
        .context("tras `--` hace falta al menos el comando que arranca el servidor")
}

/// De "@ambito/nombre@1.2.3" saca "@ambito/nombre"; de "nombre@1.2.3", "nombre".
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

/// Copia sin herramientas, para comparar solo la parte estática cuando el
/// servidor no se ha podido enumerar.
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
            let lock: Lock = serde_json::from_str(&text)
                .with_context(|| format!("{} no es un bloqueo válido", path.display()))?;
            Ok(Some(lock))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("leyendo {}", path.display())),
    }
}

fn save_lock(path: &Path, lock: &Lock) -> Result<()> {
    let mut text = serde_json::to_string_pretty(lock).context("serializando el bloqueo")?;
    text.push('\n');
    std::fs::write(path, text).with_context(|| format!("escribiendo {}", path.display()))
}

fn pinned_from(report: &Audit, bytes: &[u8]) -> Pinned {
    pin(
        &report.package,
        &tarball_hash(bytes),
        &report.capability_names(),
        &report.tools,
    )
}

// --- subcomandos ---

fn run_audit(tarball: &Path, launch: &[String]) -> Result<ExitCode> {
    let bytes = read_tarball_file(tarball)?;
    // Vacío significa que no se pidió arrancar nada: solo análisis estático.
    let launch_command = if launch.is_empty() {
        None
    } else {
        Some(split_launch(launch)?)
    };

    let report = audit(&bytes, launch_command)?;
    print!("{}", render(&report));

    // Un veto también cuenta: no se puede afirmar que sea seguro.
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

    if let Some(reason) = &report.vetoed {
        eprintln!("\ntoolgate: no se fija nada ({reason}).");
        eprintln!("Fijar sin enumerar guardaría cero herramientas, y el próximo");
        eprintln!("check las vería aparecer todas como nuevas.");
        return Ok(ExitCode::from(1));
    }
    if report.tools.is_empty() {
        eprintln!("\ntoolgate: el servidor no declaró ninguna herramienta.");
        eprintln!("No hay nada que fijar.");
        return Ok(ExitCode::from(1));
    }
    if !force && !critical_signals(&report).is_empty() {
        eprintln!("\ntoolgate: hay señales críticas sin resolver.");
        eprintln!("Fijar ahora congelaría esto como la línea base de confianza.");
        eprintln!("Revísalo; si aun así lo aceptas, repite con --force.");
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
        "Refijado"
    } else {
        "Fijado"
    };
    println!(
        "\n{verb} {key} en {} — {} · {} herramienta(s)",
        lock_path.display(),
        report.package,
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
            "no existe {}; fija una línea base con `toolgate pin`",
            lock_path.display()
        )
    })?;
    let old = lock
        .servers
        .get(&key)
        .with_context(|| format!("no hay nada fijado para {key} en {}", lock_path.display()))?;
    let new = pinned_from(&report, &bytes);

    if let Some(reason) = &report.vetoed {
        // Comparar herramientas aquí diría que han desaparecido todas, y sería
        // mentira: no se han mirado.
        let static_changes = diff(&without_tools(old), &without_tools(&new));
        print!("{}", render_changes(&static_changes));
        println!("\nNO se arrancó el servidor: {reason}");
        println!("Las herramientas NO se han comparado; lo de arriba es solo la");
        println!("parte estática. Que un servidor ya fijado pase a vetarse es en");
        println!("sí mismo un cambio.");
        return Ok(ExitCode::from(1));
    }

    let changes = diff(old, &new);
    print!("{}", render_changes(&changes));

    let critical = critical_signals(&report);
    if !critical.is_empty() {
        println!(
            "\nAdemás, {} señal(es) crítica(s) vigentes:",
            critical.len()
        );
        for signal in &critical {
            println!("  x {} — {}", signal.tool, signal.detail);
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
        Cli::try_parse_from(args).expect("debe parsear")
    }

    #[test]
    fn a_flag_after_the_command_separator_is_not_swallowed() {
        // Regresión: con `--launch` de aridad variable, un `--lock` posterior
        // acababa como argumento del servidor y `check` miraba el bloqueo por
        // defecto informando "sin cambios". Un falso "todo bien" es el peor
        // fallo posible en una herramienta de seguridad.
        let cli = parse(&[
            "toolgate", "check", "p.tgz", "--lock", "mi.lock", "--", "node", "s.js",
        ]);
        match cli.command {
            Command::Check { lock, launch, .. } => {
                assert_eq!(lock.to_str().unwrap(), "mi.lock");
                assert_eq!(launch, ["node", "s.js"]);
            }
            other => panic!("se esperaba Check, salió {other:?}"),
        }
    }

    #[test]
    fn the_server_command_keeps_its_own_hyphenated_flags() {
        let cli = parse(&["toolgate", "pin", "p.tgz", "--", "npx", "-y", "@acme/mcp"]);
        match cli.command {
            Command::Pin { launch, .. } => assert_eq!(launch, ["npx", "-y", "@acme/mcp"]),
            other => panic!("se esperaba Pin, salió {other:?}"),
        }
    }

    #[test]
    fn pin_and_check_refuse_to_run_without_a_launch_command() {
        // Fijar sin enumerar guardaría cero herramientas.
        assert!(Cli::try_parse_from(["toolgate", "pin", "p.tgz"]).is_err());
        assert!(Cli::try_parse_from(["toolgate", "check", "p.tgz"]).is_err());
    }

    #[test]
    fn audit_still_works_without_one() {
        let cli = parse(&["toolgate", "audit", "p.tgz"]);
        match cli.command {
            Command::Audit { launch, .. } => assert!(launch.is_empty()),
            other => panic!("se esperaba Audit, salió {other:?}"),
        }
    }

    #[test]
    fn the_lock_key_drops_the_version_but_keeps_the_scope() {
        assert_eq!(server_key("@acme/docs-mcp@1.4.0"), "@acme/docs-mcp");
        assert_eq!(server_key("docs-mcp@1.4.0"), "docs-mcp");
        // Sin versión no hay nada que quitar.
        assert_eq!(server_key("@acme/docs-mcp"), "@acme/docs-mcp");
    }
}
