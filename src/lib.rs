//! `toolgate`: auditoría de seguridad para servidores MCP.
//!
//! Un servidor MCP es código de terceros con acceso a tus datos que inyecta
//! texto directamente en el contexto del modelo. `toolgate` audita qué puede
//! hacer ese código, qué texto va a recibir el modelo, y si algo ha cambiado
//! desde la última vez.

mod audit;
mod capabilities;
mod error;
mod launch;
mod lock;
mod mcp;
mod pkg;
mod poison;
mod report;
mod tool;

pub use audit::{Audit, audit};
pub use capabilities::{Capability, Evidence, capabilities, scan};
pub use error::Error;
pub use launch::Contained;
pub use lock::{Change, Lock, Pinned, PinnedTool, canonical, diff, hash_tools, pin};
pub use mcp::list_tools;
pub use pkg::{Package, SourceFile, read_tarball};
pub use poison::{Severity, Signal, inspect};
pub use report::render;
pub use tool::Tool;
