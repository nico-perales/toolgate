//! Lectura de un tarball de npm **sin instalarlo**.
//!
//! Es lo que permite el orden correcto: analizar antes de que se ejecute ningún
//! script de instalación. Las entradas de un `.tgz` de npm van todas bajo el
//! prefijo `package/`.

use std::collections::BTreeMap;
use std::io::Read;

use flate2::read::GzDecoder;
use serde::Deserialize;

use crate::error::Error;

// Un fichero con líneas larguísimas es, en la práctica, código minificado.
const MINIFIED_LINE: usize = 500;
// Techo por fichero: no se analizan blobs enormes.
const MAX_FILE: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: String,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub scripts: BTreeMap<String, String>,
    pub sources: Vec<SourceFile>,
    /// El paquete se publica empaquetado/minificado: el inventario de
    /// capacidades no podrá atribuir con precisión, y el informe debe decirlo.
    pub bundled: bool,
}

#[derive(Deserialize)]
struct Manifest {
    name: String,
    version: String,
    #[serde(default)]
    scripts: BTreeMap<String, String>,
}

fn is_source(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"]
        .iter()
        .any(|ext| lower.ends_with(ext))
}

// Quita el prefijo `package/` que npm pone a todas las entradas.
fn strip_prefix(path: &str) -> String {
    path.strip_prefix("package/").unwrap_or(path).to_owned()
}

/// Lee un `.tgz` de npm en memoria.
pub fn read_tarball(bytes: &[u8]) -> Result<Package, Error> {
    let mut archive = tar::Archive::new(GzDecoder::new(bytes));
    let mut manifest_text: Option<String> = None;
    let mut sources = Vec::new();

    let entries = archive
        .entries()
        .map_err(|e| Error::Tarball(e.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| Error::Tarball(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| Error::Tarball(e.to_string()))?
            .to_string_lossy()
            .into_owned();
        let name = strip_prefix(&path);

        let is_manifest = name == "package.json";
        if !is_manifest && !is_source(&name) {
            continue;
        }

        // Un fichero binario o gigante se salta en vez de reventar el análisis.
        let mut text = String::new();
        if entry
            .by_ref()
            .take(MAX_FILE)
            .read_to_string(&mut text)
            .is_err()
        {
            continue;
        }

        if is_manifest {
            manifest_text = Some(text);
        } else {
            sources.push(SourceFile { path: name, text });
        }
    }

    let manifest_text =
        manifest_text.ok_or_else(|| Error::Manifest("no hay package.json".to_owned()))?;
    let manifest: Manifest =
        serde_json::from_str(&manifest_text).map_err(|e| Error::Manifest(e.to_string()))?;

    let bundled = sources
        .iter()
        .any(|s| s.text.lines().any(|l| l.len() > MINIFIED_LINE));

    Ok(Package {
        name: manifest.name,
        version: manifest.version,
        scripts: manifest.scripts,
        sources,
        bundled,
    })
}

#[cfg(test)]
mod tests {
    use super::read_tarball;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    // Construye un .tgz de npm en memoria: las entradas van bajo `package/`.
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
    fn reads_name_version_and_scripts() {
        let manifest = r#"{
            "name": "@acme/db-mcp",
            "version": "1.2.0",
            "scripts": { "postinstall": "node setup.js" }
        }"#;
        let bytes = tarball(&[("package.json", manifest), ("index.js", "const x = 1;")]);
        let pkg = read_tarball(&bytes).unwrap();
        assert_eq!(pkg.name, "@acme/db-mcp");
        assert_eq!(pkg.version, "1.2.0");
        assert_eq!(
            pkg.scripts.get("postinstall").map(String::as_str),
            Some("node setup.js")
        );
    }

    #[test]
    fn collects_only_source_files() {
        let manifest = r#"{"name":"x","version":"1.0.0"}"#;
        let bytes = tarball(&[
            ("package.json", manifest),
            ("index.js", "const a = 1;"),
            ("README.md", "# hola"),
        ]);
        let pkg = read_tarball(&bytes).unwrap();
        let paths: Vec<&str> = pkg.sources.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, vec!["index.js"]);
    }

    #[test]
    fn detects_a_bundled_package() {
        let manifest = r#"{"name":"x","version":"1.0.0"}"#;
        // Una línea larguísima es la firma de un bundle minificado.
        let minified = format!("const a={};", "1+".repeat(400));
        let bytes = tarball(&[("package.json", manifest), ("dist/index.js", &minified)]);
        let pkg = read_tarball(&bytes).unwrap();
        assert!(
            pkg.bundled,
            "un dist minificado debe marcarse como empaquetado"
        );
    }

    #[test]
    fn a_normal_package_is_not_bundled() {
        let manifest = r#"{"name":"x","version":"1.0.0"}"#;
        let bytes = tarball(&[("package.json", manifest), ("index.js", "const a = 1;\n")]);
        assert!(!read_tarball(&bytes).unwrap().bundled);
    }

    #[test]
    fn rejects_a_tarball_without_manifest() {
        let bytes = tarball(&[("index.js", "const a = 1;")]);
        assert!(read_tarball(&bytes).is_err());
    }
}
