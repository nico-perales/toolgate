//! `toolgate`: security auditing for MCP servers.
//!
//! An MCP server is third-party code with access to your data that injects text
//! straight into a model's context. `toolgate` audits what that code can do,
//! what text the model is going to receive, and whether any of it has changed
//! since the last time you looked.

mod audit;
mod capabilities;
mod error;
mod launch;
mod lock;
mod mcp;
mod pkg;
mod poison;
mod report;
mod resolve;
mod tool;

pub use audit::{Audit, audit};
pub use capabilities::{Capability, Evidence, capabilities, scan};
pub use error::Error;
pub use launch::Contained;
pub use lock::{
    Change, LOCK_VERSION, Lock, Pinned, PinnedTool, canonical, diff, hash_tools, pin, tarball_hash,
};
pub use mcp::list_tools;
pub use pkg::{Package, SourceFile, read_tarball};
pub use poison::{Severity, Signal, inspect};
pub use report::{render, render_changes};
pub use resolve::resolve_command;
pub use tool::Tool;
