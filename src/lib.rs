//! `toolgate`: auditoría de seguridad para servidores MCP.
//!
//! Un servidor MCP es código de terceros con acceso a tus datos que inyecta
//! texto directamente en el contexto del modelo. `toolgate` audita qué puede
//! hacer ese código, qué texto va a recibir el modelo, y si algo ha cambiado
//! desde la última vez.

mod capabilities;
mod error;
mod launch;
mod pkg;
mod poison;
mod tool;

pub use capabilities::{Capability, Evidence, capabilities, scan};
pub use error::Error;
pub use launch::Contained;
pub use pkg::{Package, SourceFile, read_tarball};
pub use poison::{Severity, Signal, inspect};
pub use tool::Tool;
