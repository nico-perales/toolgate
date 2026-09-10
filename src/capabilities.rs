//! Capability inventory from the AST.
//!
//! It answers "what can this code do", not "what does it do". It is an
//! inventory, not an accusation: a git server has `Exec` legitimately. It only
//! becomes a finding when it changes against a pin, or when it shows up in an
//! install script.

use std::collections::BTreeSet;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, CallExpression, Expression, ImportDeclaration, ImportExpression, NewExpression,
    StaticMemberExpression,
};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_span::SourceType;

use crate::pkg::Package;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Capability {
    Net,
    Fs,
    Exec,
    Env,
    /// `eval`, `new Function` or a computed `require`: from here on the static
    /// inventory is **no longer complete**, and the report has to say so.
    Dynamic,
}

#[derive(Clone, Debug)]
pub struct Evidence {
    pub capability: Capability,
    pub file: String,
}

// Node module -> capability. The `node:` prefix is accepted.
fn module_capability(name: &str) -> Option<Capability> {
    let base = name.strip_prefix("node:").unwrap_or(name);
    let root = base.split('/').next().unwrap_or(base);
    match root {
        "fs" => Some(Capability::Fs),
        "child_process" => Some(Capability::Exec),
        "http" | "https" | "net" | "dgram" | "tls" | "dns" => Some(Capability::Net),
        _ => None,
    }
}

fn identifier_name<'a>(expr: &Expression<'a>) -> Option<&'a str> {
    match expr {
        Expression::Identifier(ident) => Some(ident.name.as_str()),
        _ => None,
    }
}

fn first_string_argument<'a>(args: &[Argument<'a>]) -> Option<&'a str> {
    match args.first() {
        Some(Argument::StringLiteral(lit)) => Some(lit.value.as_str()),
        _ => None,
    }
}

#[derive(Default)]
struct CapabilityVisitor {
    caps: BTreeSet<Capability>,
}

impl<'a> Visit<'a> for CapabilityVisitor {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Some(name) = identifier_name(&it.callee) {
            match name {
                "require" => match first_string_argument(&it.arguments) {
                    Some(module) => {
                        if let Some(cap) = module_capability(module) {
                            self.caps.insert(cap);
                        }
                    }
                    // require(variable): the inventory stops being complete.
                    None => {
                        self.caps.insert(Capability::Dynamic);
                    }
                },
                "eval" => {
                    self.caps.insert(Capability::Dynamic);
                }
                _ => {}
            }
        }
        walk::walk_call_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if identifier_name(&it.callee) == Some("Function") {
            self.caps.insert(Capability::Dynamic);
        }
        walk::walk_new_expression(self, it);
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        if let Some(cap) = module_capability(it.source.value.as_str()) {
            self.caps.insert(cap);
        }
        walk::walk_import_declaration(self, it);
    }

    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        match &it.source {
            Expression::StringLiteral(lit) => {
                if let Some(cap) = module_capability(lit.value.as_str()) {
                    self.caps.insert(cap);
                }
            }
            _ => {
                self.caps.insert(Capability::Dynamic);
            }
        }
        walk::walk_import_expression(self, it);
    }

    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        if identifier_name(&it.object) == Some("process") && it.property.name == "env" {
            self.caps.insert(Capability::Env);
        }
        walk::walk_static_member_expression(self, it);
    }
}

/// Capabilities of one source file.
pub fn capabilities(source: &str) -> BTreeSet<Capability> {
    let allocator = Allocator::default();
    // The widest superset, so CommonJS, ESM and TS all parse.
    let source_type = SourceType::default().with_typescript(true).with_jsx(true);
    let parsed = Parser::new(&allocator, source, source_type).parse();

    let mut visitor = CapabilityVisitor::default();
    visitor.visit_program(&parsed.program);
    visitor.caps
}

/// Capabilities of the whole package, with the file each one came from.
pub fn scan(pkg: &Package) -> Vec<Evidence> {
    let mut out = Vec::new();
    for file in &pkg.sources {
        for capability in capabilities(&file.text) {
            out.push(Evidence {
                capability,
                file: file.path.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Capability, capabilities};

    fn caps(src: &str) -> Vec<Capability> {
        let mut v: Vec<Capability> = capabilities(src).into_iter().collect();
        v.sort();
        v
    }

    #[test]
    fn detects_require_of_dangerous_modules() {
        assert_eq!(
            caps("const cp = require('child_process');"),
            vec![Capability::Exec]
        );
        assert_eq!(caps("const fs = require('fs');"), vec![Capability::Fs]);
        assert_eq!(
            caps("const h = require('node:https');"),
            vec![Capability::Net]
        );
    }

    #[test]
    fn detects_esm_imports() {
        assert_eq!(
            caps("import { spawn } from 'child_process';"),
            vec![Capability::Exec]
        );
        assert_eq!(
            caps("const m = await import('fs/promises');"),
            vec![Capability::Fs]
        );
    }

    #[test]
    fn detects_env_access() {
        assert_eq!(caps("const k = process.env.SECRET;"), vec![Capability::Env]);
    }

    #[test]
    fn detects_dynamic_evaluation() {
        assert_eq!(caps("eval(payload);"), vec![Capability::Dynamic]);
        assert_eq!(
            caps("const f = new Function('a', 'return a');"),
            vec![Capability::Dynamic]
        );
        // A computed require makes the static inventory incomplete.
        assert_eq!(caps("require(mod);"), vec![Capability::Dynamic]);
    }

    #[test]
    fn plain_code_has_no_capabilities() {
        assert!(caps("const a = 1 + 2; export default a;").is_empty());
    }
}
