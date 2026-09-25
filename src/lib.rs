//! `toolgate`: security auditing for MCP servers.
//!
//! An MCP server is third-party code with access to your data that injects text
//! straight into a model's context. `toolgate` audits what that code can do,
//! what text the model is going to receive, and whether any of it has changed
//! since the last time you looked.

mod audit;
mod capabilities;
mod error;
pub mod journal;
mod launch;
mod lock;
mod mcp;
mod pkg;
mod poison;
pub mod policy;
pub mod proxy;
pub mod relay;
mod report;
mod resolve;
pub mod store;
mod tool;

pub use audit::{Audit, audit};
pub use capabilities::{Capability, Evidence, capabilities, scan};
pub use error::Error;
pub use launch::Contained;
pub use lock::{
    Change, FieldChange, LOCK_VERSION, Lock, Pinned, PinnedTool, canonical, diff, field_changes,
    hash_tools, pin, read_lock, tarball_hash,
};
pub use mcp::list_tools;
pub use pkg::{Package, SourceFile, read_tarball};
pub use poison::{Severity, Signal, inspect, inspect_declaration, inspect_output};
pub use report::{escape, render, render_changes, render_review, veto_line};
pub use resolve::resolve_command;
pub use tool::Tool;
