//! La orquestación del análisis, y el **veto**.
//!
//! La regla que sostiene el diseño: arrancar un servidor no confiado para
//! enumerarlo puede ejecutar su código, así que el análisis estático va primero
//! y tiene poder de veto. Sin esto, el orden "estático primero" sería decorativo.

use std::collections::{BTreeMap, BTreeSet};

use crate::capabilities::{self, Capability, Evidence};
use crate::error::Error;
use crate::launch::Contained;
use crate::mcp;
use crate::pkg::{self, Package};
use crate::poison::{self, Signal};
use crate::tool::Tool;

const ENUMERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Debug)]
pub struct Audit {
    pub package: String,
    /// El paquete se publica minificado: el inventario es aproximado.
    pub bundled: bool,
    pub capabilities: Vec<Evidence>,
    pub scripts: BTreeMap<String, String>,
    pub tools: Vec<Tool>,
    pub signals: Vec<Signal>,
    /// Presente si el análisis estático prohibió arrancar el servidor.
    pub vetoed: Option<String>,
}

impl Audit {
    /// Nombres únicos y ordenados de las capacidades detectadas.
    ///
    /// Es lo que se fija y lo que se compara: el orden y las repeticiones del
    /// inventario dependen de en qué fichero apareció cada cosa, y eso cambia
    /// entre publicaciones sin que cambie nada relevante.
    pub fn capability_names(&self) -> Vec<String> {
        let unique: BTreeSet<String> = self
            .capabilities
            .iter()
            .map(|e| format!("{:?}", e.capability))
            .collect();
        unique.into_iter().collect()
    }
}

/// Motivos por los que el análisis estático prohíbe arrancar el servidor.
fn veto(pkg: &Package, evidence: &[Evidence]) -> Option<String> {
    // Un script de instalación es código que se ejecuta antes que nada: si lo
    // hay, no se arranca el servidor para enumerarlo.
    for hook in ["preinstall", "install", "postinstall"] {
        if let Some(command) = pkg.scripts.get(hook) {
            return Some(format!("{hook} script: {command}"));
        }
    }
    // Evaluación dinámica: el inventario estático ya no es completo, así que no
    // se puede afirmar que arrancarlo sea razonable.
    if evidence.iter().any(|e| e.capability == Capability::Dynamic) {
        return Some("the package uses dynamic evaluation (eval or a computed require)".to_owned());
    }
    None
}

/// Análisis completo de un tarball.
///
/// La enumeración solo ocurre si el análisis estático no la veta **y** se ha
/// dado un comando para arrancar el servidor.
pub fn audit(tarball: &[u8], launch_command: Option<(&str, &[String])>) -> Result<Audit, Error> {
    let package = pkg::read_tarball(tarball)?;
    let evidence = capabilities::scan(&package);

    let mut report = Audit {
        package: format!("{}@{}", package.name, package.version),
        bundled: package.bundled,
        capabilities: evidence.clone(),
        scripts: package.scripts.clone(),
        tools: Vec::new(),
        signals: Vec::new(),
        vetoed: None,
    };

    if let Some(reason) = veto(&package, &evidence) {
        // Se informa, no se arranca.
        report.vetoed = Some(reason);
        return Ok(report);
    }

    if let Some((command, args)) = launch_command {
        let mut server = Contained::spawn(command, args)?;
        let tools = mcp::list_tools(&mut server, ENUMERATION_TIMEOUT)?;
        report.signals = poison::inspect(&tools);
        report.tools = tools;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::audit;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    fn tarball(files: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(u64::try_from(body.len()).unwrap());
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("package/{name}"), body.as_bytes())
                .unwrap();
        }
        let tar = builder.into_inner().unwrap();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn an_install_script_vetoes_the_launch() {
        let manifest =
            r#"{"name":"x","version":"1.0.0","scripts":{"postinstall":"node setup.js"}}"#;
        let bytes = tarball(&[("package.json", manifest), ("index.js", "const a = 1;")]);
        let report = audit(&bytes, None).unwrap();
        assert!(report.vetoed.is_some());
        assert!(report.vetoed.unwrap().contains("postinstall"));
    }

    #[test]
    fn dynamic_evaluation_vetoes_the_launch() {
        let manifest = r#"{"name":"x","version":"1.0.0"}"#;
        let bytes = tarball(&[("package.json", manifest), ("index.js", "eval(payload);")]);
        assert!(audit(&bytes, None).unwrap().vetoed.is_some());
    }

    #[test]
    fn a_clean_package_is_not_vetoed() {
        let manifest = r#"{"name":"x","version":"1.0.0"}"#;
        let bytes = tarball(&[("package.json", manifest), ("index.js", "const a = 1;")]);
        assert!(audit(&bytes, None).unwrap().vetoed.is_none());
    }

    #[test]
    fn capabilities_are_reported_for_a_clean_package() {
        let manifest = r#"{"name":"x","version":"1.0.0"}"#;
        let source = "const fs = require('fs');";
        let bytes = tarball(&[("package.json", manifest), ("index.js", source)]);
        let report = audit(&bytes, None).unwrap();
        // Las capacidades son información, no hallazgo: se listan aunque esté limpio.
        assert!(!report.capabilities.is_empty());
        assert!(report.vetoed.is_none());
    }
}
