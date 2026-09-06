//! El vocabulario compartido: una herramienta declarada por un servidor MCP.
//!
//! Lo producen `mcp`, lo inspecciona `poison` y lo fija `lock`.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}
