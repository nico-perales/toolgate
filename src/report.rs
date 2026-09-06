//! Render del informe en texto.
//!
//! La regla que evita que la herramienta grite en casos normales: **las
//! capacidades se presentan como información, nunca como hallazgo**. Un servidor
//! de git tiene `Exec` legítimamente. Solo son hallazgo si aparecen en un script
//! de instalación o si han cambiado respecto a lo fijado.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::audit::Audit;
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
    let caps: BTreeSet<String> = report
        .capabilities
        .iter()
        .map(|e| format!("{:?}", e.capability))
        .collect();
    out.push('\n');
    out.push_str("Capacidades (información, no hallazgos)\n");
    if caps.is_empty() {
        out.push_str("  ninguna detectada\n");
    } else {
        let list: Vec<String> = caps.into_iter().collect();
        let _ = writeln!(out, "  {}", list.join(", "));
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

#[cfg(test)]
mod tests {
    use super::render;
    use crate::audit::Audit;
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
}
