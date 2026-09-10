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

    let _ = write!(out, "Package: {}", report.package);
    if report.bundled {
        let _ = write!(out, "  (bundled: the inventory is approximate)");
    }
    out.push('\n');

    // --- capacidades: información ---
    let caps = report.capability_names();
    out.push('\n');
    out.push_str("Capabilities (information, not findings)\n");
    if caps.is_empty() {
        out.push_str("  none detected\n");
    } else {
        let _ = writeln!(out, "  {}", caps.join(", "));
    }

    // --- scripts de instalación: esto sí importa ---
    for hook in ["preinstall", "install", "postinstall"] {
        if let Some(command) = report.scripts.get(hook) {
            let _ = writeln!(out, "  ! {hook} script: {command}");
        }
    }

    // --- el veto corta aquí ---
    if let Some(reason) = &report.vetoed {
        let _ = writeln!(out, "\nServer NOT started: {reason}");
        out.push_str("Its tools were never enumerated, so nothing can be claimed\n");
        out.push_str("about what this server injects into the model's context.\n");
        return out;
    }

    // --- herramientas ---
    let _ = writeln!(out, "\nTools: {}", report.tools.len());
    let mut critical = 0usize;
    let mut warnings = 0usize;
    for signal in &report.signals {
        match signal.severity {
            Severity::Critical => {
                critical += 1;
                let _ = writeln!(out, "  x CRITICAL  {} — {}", signal.tool, signal.detail);
            }
            Severity::Warning => {
                warnings += 1;
                let _ = writeln!(out, "  ! warning   {} — {}", signal.tool, signal.detail);
            }
        }
    }
    if report.signals.is_empty() && !report.tools.is_empty() {
        out.push_str("  no signals\n");
    }

    let _ = writeln!(out, "\n{critical} critical · {warnings} warning(s)");
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
    format!("{head}… (+{} more characters)", total - MAX)
}

/// Informe legible de un `check`: qué cambió respecto a lo fijado.
///
/// Aquí no hay heurística. Cada línea es un hecho comprobable, así que todas
/// son hallazgos de pleno derecho.
pub fn render_changes(changes: &[Change]) -> String {
    let mut out = String::new();
    if changes.is_empty() {
        out.push_str("No changes since the pinned baseline.\n");
        return out;
    }

    let _ = writeln!(
        out,
        "{} change(s) since the pinned baseline:",
        changes.len()
    );
    for change in changes {
        match change {
            Change::PackageChanged { before, after } => {
                if before == after {
                    // Mismo nombre y misma versión, pero otro tarball. npm no
                    // debería reescribir una versión publicada: esto es lo más
                    // parecido a una prueba de rug pull que existe.
                    let _ = writeln!(out, "  x {before} changed content WITHOUT changing version");
                } else {
                    let _ = writeln!(out, "  x the package changed: {before} -> {after}");
                }
            }
            Change::CapabilitiesWidened(caps) => {
                let _ = writeln!(out, "  x new capabilities: {}", caps.join(", "));
            }
            Change::ToolAdded(name) => {
                let _ = writeln!(out, "  x new tool: {name}");
            }
            Change::ToolRemoved(name) => {
                let _ = writeln!(out, "  ! tool gone: {name}");
            }
            Change::ToolChanged {
                name,
                before,
                after,
            } => {
                let _ = writeln!(out, "  x the description of {name} changed");
                let _ = writeln!(out, "      before: {}", one_line(before));
                let _ = writeln!(out, "      after:  {}", one_line(after));
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
        let text = render(&empty(Some("postinstall script: node s.js".to_owned())));
        assert!(text.contains("Server NOT started"));
        assert!(text.contains("nothing can be claimed"));
        // No debe hablar de herramientas si no las enumeró.
        assert!(!text.contains("Tools:"));
    }

    #[test]
    fn capabilities_are_labelled_as_information() {
        let text = render(&empty(None));
        assert!(text.contains("information, not findings"));
    }

    #[test]
    fn no_changes_says_so_plainly() {
        assert!(render_changes(&[]).contains("No changes"));
    }

    #[test]
    fn a_silent_republish_is_named_as_such() {
        let text = render_changes(&[Change::PackageChanged {
            before: "p@1.0.0".to_owned(),
            after: "p@1.0.0".to_owned(),
        }]);
        assert!(text.contains("WITHOUT changing version"));
    }

    #[test]
    fn a_version_bump_is_not_confused_with_a_republish() {
        let text = render_changes(&[Change::PackageChanged {
            before: "p@1.0.0".to_owned(),
            after: "p@1.1.0".to_owned(),
        }]);
        assert!(text.contains("p@1.0.0 -> p@1.1.0"));
        assert!(!text.contains("WITHOUT changing version"));
    }

    #[test]
    fn a_padded_description_is_shown_on_one_line_and_bounded() {
        let padding = "x ".repeat(400);
        let text = render_changes(&[Change::ToolChanged {
            name: "q".to_owned(),
            before: "Read only.".to_owned(),
            after: padding,
        }]);
        assert!(text.contains("more characters)"));
        // Cuatro líneas: la cabecera, el titular del cambio, el antes y el ahora.
        assert_eq!(text.lines().count(), 4);
    }
}
