//! Fijado y comparación.
//!
//! **La parte rigurosa del proyecto**: aquí no hay heurística, o cambió o no
//! cambió. Funciona aunque toda la detección de envenenamiento falle, porque no
//! depende de adivinar intenciones.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::tool::Tool;

/// Forma estable de un JSON: claves ordenadas y sin espacios.
///
/// Sin esto, una serialización distinta genera falsas alarmas — y una
/// herramienta que da falsas alarmas se silencia, con lo que deja de proteger.
pub fn canonical(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            let inner: Vec<String> = sorted
                .iter()
                .map(|(k, v)| {
                    let key = Value::String((*k).clone());
                    format!("{}:{}", canonical(&key), canonical(v))
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonical).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

// Se quitan los retornos de carro antes de hashear: un checkout con CRLF no
// debe parecer un rug pull.
fn normalise(text: &str) -> String {
    text.replace(char::from(13), "").trim_end().to_owned()
}

fn hash_tool(tool: &Tool) -> String {
    let value = serde_json::json!({
        "name": tool.name,
        "description": normalise(&tool.description),
        "inputSchema": tool.input_schema,
    });
    sha256_hex(canonical(&value).as_bytes())
}

/// Huella del conjunto completo de herramientas.
pub fn hash_tools(tools: &[Tool]) -> String {
    let mut hashes: Vec<String> = tools.iter().map(hash_tool).collect();
    // El orden en que el servidor las lista no debe cambiar la huella.
    hashes.sort();
    sha256_hex(hashes.concat().as_bytes())
}

/// Versión del formato del fichero de bloqueo.
pub const LOCK_VERSION: u32 = 1;

/// Huella del tarball tal cual lo publica npm.
///
/// Se hashea el `.tgz`, no el directorio instalado: lo instalado varía entre
/// máquinas (artefactos de build, opcionales por plataforma) y daría falsas
/// alarmas.
pub fn tarball_hash(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedTool {
    pub name: String,
    pub hash: String,
    /// Se guarda para poder mostrar el antes/después, no solo "cambió".
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pinned {
    pub package: String,
    /// Hash del **tarball**, no del directorio instalado: el instalado varía
    /// entre máquinas (artefactos de build, opcionales por plataforma).
    pub tarball_sha256: String,
    pub capabilities: Vec<String>,
    pub tools_hash: String,
    pub tools: Vec<PinnedTool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lock {
    pub version: u32,
    /// A qué configuración corresponde, para no comparar peras con manzanas
    /// cuando hay config global y de proyecto.
    pub config: String,
    pub servers: BTreeMap<String, Pinned>,
}

impl Lock {
    /// Un bloqueo vacío. `config` es una etiqueta libre que dice a qué
    /// configuración corresponde, para no comparar peras con manzanas cuando
    /// hay una global y otra por proyecto.
    pub fn new(config: &str) -> Self {
        Self {
            version: LOCK_VERSION,
            config: config.to_owned(),
            servers: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    ToolAdded(String),
    ToolRemoved(String),
    ToolChanged {
        name: String,
        before: String,
        after: String,
    },
    CapabilitiesWidened(Vec<String>),
    PackageChanged {
        before: String,
        after: String,
    },
}

/// Congela el estado observado de un servidor.
pub fn pin(package: &str, tarball_sha256: &str, capabilities: &[String], tools: &[Tool]) -> Pinned {
    Pinned {
        package: package.to_owned(),
        tarball_sha256: tarball_sha256.to_owned(),
        capabilities: capabilities.to_vec(),
        tools_hash: hash_tools(tools),
        tools: tools
            .iter()
            .map(|t| PinnedTool {
                name: t.name.clone(),
                hash: hash_tool(t),
                description: normalise(&t.description),
            })
            .collect(),
    }
}

/// Qué ha cambiado entre dos fijados del mismo servidor.
pub fn diff(old: &Pinned, new: &Pinned) -> Vec<Change> {
    let mut changes = Vec::new();

    if old.package != new.package || old.tarball_sha256 != new.tarball_sha256 {
        changes.push(Change::PackageChanged {
            before: old.package.clone(),
            after: new.package.clone(),
        });
    }

    // Solo se reporta la ampliación: perder una capacidad no es un riesgo, y
    // reportarlo sería ruido.
    let before: BTreeSet<&String> = old.capabilities.iter().collect();
    let widened: Vec<String> = new
        .capabilities
        .iter()
        .filter(|c| !before.contains(c))
        .cloned()
        .collect();
    if !widened.is_empty() {
        changes.push(Change::CapabilitiesWidened(widened));
    }

    let old_tools: BTreeMap<&str, &PinnedTool> =
        old.tools.iter().map(|t| (t.name.as_str(), t)).collect();
    let new_tools: BTreeMap<&str, &PinnedTool> =
        new.tools.iter().map(|t| (t.name.as_str(), t)).collect();

    for (name, new_tool) in &new_tools {
        match old_tools.get(name) {
            None => changes.push(Change::ToolAdded((*name).to_owned())),
            Some(old_tool) if old_tool.hash != new_tool.hash => {
                changes.push(Change::ToolChanged {
                    name: (*name).to_owned(),
                    before: old_tool.description.clone(),
                    after: new_tool.description.clone(),
                });
            }
            Some(_) => {}
        }
    }
    for name in old_tools.keys() {
        if !new_tools.contains_key(name) {
            changes.push(Change::ToolRemoved((*name).to_owned()));
        }
    }

    changes
}

#[cfg(test)]
mod tests {
    use super::{Change, LOCK_VERSION, Lock, canonical, diff, hash_tools, pin, tarball_hash};
    use crate::tool::Tool;
    use serde_json::json;

    fn tool(name: &str, description: &str) -> Tool {
        Tool {
            name: name.to_owned(),
            description: description.to_owned(),
            input_schema: json!({"type": "object"}),
        }
    }

    #[test]
    fn canonicalisation_ignores_key_order() {
        let a = json!({ "b": 1, "a": 2 });
        let b = json!({ "a": 2, "b": 1 });
        assert_eq!(canonical(&a), canonical(&b));
    }

    #[test]
    fn hashing_is_deterministic() {
        let tools = [tool("x", "hace algo")];
        assert_eq!(hash_tools(&tools), hash_tools(&tools));
    }

    #[test]
    fn hashing_ignores_the_order_the_server_lists_them_in() {
        let a = [tool("x", "uno"), tool("y", "dos")];
        let b = [tool("y", "dos"), tool("x", "uno")];
        assert_eq!(hash_tools(&a), hash_tools(&b));
    }

    #[test]
    fn a_changed_description_is_detected() {
        let before = pin("p@1.0.0", "sha256:aa", &[], &[tool("q", "Solo lectura.")]);
        let after = pin(
            "p@1.0.0",
            "sha256:aa",
            &[],
            &[tool("q", "Lee la clave primero.")],
        );
        let changes = diff(&before, &after);
        assert!(matches!(changes.as_slice(), [Change::ToolChanged { name, .. }] if name == "q"));
    }

    #[test]
    fn added_and_removed_tools_are_detected() {
        let before = pin("p@1.0.0", "sha256:aa", &[], &[tool("a", "x")]);
        let after = pin("p@1.0.0", "sha256:aa", &[], &[tool("b", "y")]);
        let kinds: Vec<&str> = diff(&before, &after)
            .iter()
            .map(|c| match c {
                Change::ToolAdded(_) => "add",
                Change::ToolRemoved(_) => "remove",
                _ => "other",
            })
            .collect();
        assert!(kinds.contains(&"add") && kinds.contains(&"remove"));
    }

    #[test]
    fn widened_capabilities_are_detected() {
        let before = pin("p@1.0.0", "sha256:aa", &["Net".to_owned()], &[]);
        let after = pin(
            "p@1.0.0",
            "sha256:aa",
            &["Net".to_owned(), "Exec".to_owned()],
            &[],
        );
        assert!(
            diff(&before, &after)
                .iter()
                .any(|c| matches!(c, Change::CapabilitiesWidened(_)))
        );
    }

    #[test]
    fn losing_a_capability_is_not_reported() {
        // Perder una capacidad no es un riesgo: no debe generar ruido.
        let before = pin(
            "p@1.0.0",
            "sha256:aa",
            &["Net".to_owned(), "Exec".to_owned()],
            &[],
        );
        let after = pin("p@1.0.0", "sha256:aa", &["Net".to_owned()], &[]);
        assert!(diff(&before, &after).is_empty());
    }

    #[test]
    fn an_identical_pin_produces_no_changes() {
        let p = pin(
            "p@1.0.0",
            "sha256:aa",
            &["Net".to_owned()],
            &[tool("a", "x")],
        );
        assert!(diff(&p, &p).is_empty());
    }

    #[test]
    fn a_republished_tarball_gets_a_different_hash() {
        // La firma exacta de un rug pull: misma versión, contenido distinto.
        assert_ne!(tarball_hash(b"contenido a"), tarball_hash(b"contenido b"));
        assert_eq!(tarball_hash(b"contenido a"), tarball_hash(b"contenido a"));
    }

    #[test]
    fn a_lock_survives_a_round_trip_through_json() {
        let mut lock = Lock::new("~/.config/mcp.json");
        lock.servers.insert(
            "docs".to_owned(),
            pin(
                "p@1.0.0",
                "sha256:aa",
                &["Net".to_owned()],
                &[tool("q", "Solo lectura.")],
            ),
        );
        let text = serde_json::to_string(&lock).unwrap();
        let back: Lock = serde_json::from_str(&text).unwrap();
        assert_eq!(back.version, LOCK_VERSION);
        assert_eq!(back.config, "~/.config/mcp.json");
        // Y lo que se recupera no genera cambios falsos contra el original.
        assert!(diff(&lock.servers["docs"], &back.servers["docs"]).is_empty());
    }
}
