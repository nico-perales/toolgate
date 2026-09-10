//! Render del informe en texto.
//!
//! La regla que evita que la herramienta grite en casos normales: **las
//! capacidades se presentan como información, nunca como hallazgo**. Un servidor
//! de git tiene `Exec` legítimamente. Solo son hallazgo si aparecen en un script
//! de instalación o si han cambiado respecto a lo fijado.

use std::fmt::Write as _;

use crate::audit::Audit;
use crate::lock::Change;
use crate::poison::Severity;

/// Informe legible de una auditoría.
pub fn render(report: &Audit) -> String {
    let mut out = String::new();

    let _ = write!(out, "Paquete: {}", report.package);
    if report.bundled {
        let _ = write!(out, "  (empaquetado: el inventario es aproximado)");
    }
    out.push('\n');

    // --- capacidades: información ---
    let caps = report.capability_names();
    out.push('\n');
    out.push_str("Capacidades (información, no hallazgos)\n");
    if caps.is_empty() {
        out.push_str("  ninguna detectada\n");
    } else {
        let _ = writeln!(out, "  {}", caps.join(", "));
    }

    // --- scripts de instalación: esto sí importa ---
    for hook in ["preinstall", "install", "postinstall"] {
        if let Some(command) = report.scripts.get(hook) {
            let _ = writeln!(out, "  ! script {hook}: {command}");
        }
    }

    // --- el veto corta aquí ---
    if let Some(reason) = &report.vetoed {
        let _ = writeln!(out, "\nNO se arrancó el servidor: {reason}");
        out.push_str("Las herramientas no se han enumerado, así que no se puede\n");
        out.push_str("afirmar nada sobre lo que este servidor inyecta en el contexto.\n");
        return out;
    }

    // --- herramientas ---
    let _ = writeln!(out, "\nHerramientas: {}", report.tools.len());
    let mut critical = 0usize;
    let mut warnings = 0usize;
    for signal in &report.signals {
        match signal.severity {
            Severity::Critical => {
                critical += 1;
                let _ = writeln!(out, "  x CRITICO  {} — {}", signal.tool, signal.detail);
            }
            Severity::Warning => {
                warnings += 1;
                let _ = writeln!(out, "  ! aviso    {} — {}", signal.tool, signal.detail);
            }
        }
    }
    if report.signals.is_empty() && !report.tools.is_empty() {
        out.push_str("  sin señales\n");
    }

    let _ = writeln!(out, "\n{critical} crítico(s) · {warnings} aviso(s)");
    out
}

/// Una descripción en una sola línea, acotada, para poder enseñar el antes y el
/// después sin volcar un payload de relleno entero en la terminal.
fn one_line(text: &str) -> String {
    const MAX: usize = 300;
    let collapsed: Vec<&str> = text.split_whitespace().collect();
    let collapsed = collapsed.join(" ");
    let total = collapsed.chars().count();
    if total <= MAX {
        return collapsed;
    }
    let head: String = collapsed.chars().take(MAX).collect();
    format!("{head}… (+{} caracteres)", total - MAX)
}

/// Informe legible de un `check`: qué cambió respecto a lo fijado.
///
/// Aquí no hay heurística. Cada línea es un hecho comprobable, así que todas
/// son hallazgos de pleno derecho.
pub fn render_changes(changes: &[Change]) -> String {
    let mut out = String::new();
    if changes.is_empty() {
        out.push_str("Sin cambios respecto a lo fijado.\n");
        return out;
    }

    let _ = writeln!(out, "{} cambio(s) respecto a lo fijado:", changes.len());
    for change in changes {
        match change {
            Change::PackageChanged { before, after } => {
                if before == after {
                    // Mismo nombre y misma versión, pero otro tarball. npm no
                    // debería reescribir una versión publicada: esto es lo más
                    // parecido a una prueba de rug pull que existe.
                    let _ = writeln!(
                        out,
                        "  x {before} cambió de contenido SIN cambiar de versión"
                    );
                } else {
                    let _ = writeln!(out, "  x el paquete cambió: {before} -> {after}");
                }
            }
            Change::CapabilitiesWidened(caps) => {
                let _ = writeln!(out, "  x capacidades nuevas: {}", caps.join(", "));
            }
            Change::ToolAdded(name) => {
                let _ = writeln!(out, "  x herramienta nueva: {name}");
            }
            Change::ToolRemoved(name) => {
                let _ = writeln!(out, "  ! herramienta desaparecida: {name}");
            }
            Change::ToolChanged {
                name,
                before,
                after,
            } => {
                let _ = writeln!(out, "  x cambió la descripción de {name}");
                let _ = writeln!(out, "      antes: {}", one_line(before));
                let _ = writeln!(out, "      ahora: {}", one_line(after));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{render, render_changes};
    use crate::audit::Audit;
    use crate::lock::Change;
    use std::collections::BTreeMap;

    fn empty(vetoed: Option<String>) -> Audit {
        Audit {
            package: "x@1.0.0".to_owned(),
            bundled: false,
            capabilities: Vec::new(),
            scripts: BTreeMap::new(),
            tools: Vec::new(),
            signals: Vec::new(),
            vetoed,
        }
    }

    #[test]
    fn a_veto_explains_that_nothing_was_enumerated() {
        let text = render(&empty(Some("script postinstall: node s.js".to_owned())));
        assert!(text.contains("NO se arrancó el servidor"));
        assert!(text.contains("no se puede"));
        // No debe hablar de herramientas si no las enumeró.
        assert!(!text.contains("Herramientas:"));
    }

    #[test]
    fn capabilities_are_labelled_as_information() {
        let text = render(&empty(None));
        assert!(text.contains("información, no hallazgos"));
    }

    #[test]
    fn no_changes_says_so_plainly() {
        assert!(render_changes(&[]).contains("Sin cambios"));
    }

    #[test]
    fn a_silent_republish_is_named_as_such() {
        let text = render_changes(&[Change::PackageChanged {
            before: "p@1.0.0".to_owned(),
            after: "p@1.0.0".to_owned(),
        }]);
        assert!(text.contains("SIN cambiar de versión"));
    }

    #[test]
    fn a_version_bump_is_not_confused_with_a_republish() {
        let text = render_changes(&[Change::PackageChanged {
            before: "p@1.0.0".to_owned(),
            after: "p@1.1.0".to_owned(),
        }]);
        assert!(text.contains("p@1.0.0 -> p@1.1.0"));
        assert!(!text.contains("SIN cambiar de versión"));
    }

    #[test]
    fn a_padded_description_is_shown_on_one_line_and_bounded() {
        let padding = "x ".repeat(400);
        let text = render_changes(&[Change::ToolChanged {
            name: "q".to_owned(),
            before: "Solo lectura.".to_owned(),
            after: padding,
        }]);
        assert!(text.contains("caracteres)"));
        // Cuatro líneas: la cabecera, el titular del cambio, el antes y el ahora.
        assert_eq!(text.lines().count(), 4);
    }
}
