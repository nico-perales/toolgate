//! The shared vocabulary: a tool as declared by an MCP server.
//!
//! Produced by `mcp`, inspected by `poison`, pinned by `lock`.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}
