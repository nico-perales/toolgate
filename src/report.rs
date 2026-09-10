//! Rendering the report as text.
//!
//! The rule that stops the tool from shouting in normal cases: **capabilities
//! are presented as information, never as a finding**. A git server has `Exec`
//! legitimately. They are only a finding when they appear in an install script,
//! or when they changed against a pin.

use std::fmt::Write as _;

use crate::audit::Audit;
use crate::lock::Change;
use crate::poison::Severity;

/// A readable report for an audit.
pub fn render(report: &Audit) -> String {
    let mut out = String::new();

    let _ = write!(out, "Package: {}", report.package);
    if report.bundled {
        let _ = write!(out, "  (bundled: the inventory is approximate)");
    }
    out.push('\n');

    // --- capabilities: information ---
    let caps = report.capability_names();
    out.push('\n');
    out.push_str("Capabilities (information, not findings)\n");
    if caps.is_empty() {
        out.push_str("  none detected\n");
    } else {
        let _ = writeln!(out, "  {}", caps.join(", "));
    }

    // --- install scripts: these do matter ---
    for hook in ["preinstall", "install", "postinstall"] {
        if let Some(command) = report.scripts.get(hook) {
            let _ = writeln!(out, "  ! {hook} script: {command}");
        }
    }

    // --- the veto cuts things off here ---
    if let Some(reason) = &report.vetoed {
        let _ = writeln!(out, "\nServer NOT started: {reason}");
        out.push_str("Its tools were never enumerated, so nothing can be claimed\n");
        out.push_str("about what this server injects into the model's context.\n");
        return out;
    }

    // --- tools ---
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

/// A description on a single bounded line, so before/after can be shown without
/// dumping an entire padding payload into the terminal.
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

/// A readable report for a `check`: what changed against the pin.
///
/// There is no heuristic here. Every line is a checkable fact, so all of them
/// are findings in their own right.
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
                    // Same name and same version, but a different tarball. npm
                    // should never rewrite a published version, so this is as
                    // close to proof of a rug pull as it gets.
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
        // It must not talk about tools it never enumerated.
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
        // Four lines: the header, the change headline, the before and the after.
        assert_eq!(text.lines().count(), 4);
    }
}
