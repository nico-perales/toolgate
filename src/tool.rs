//! The shared vocabulary: a tool as declared by an MCP server.
//!
//! Produced by `mcp`, inspected by `poison`, pinned by `lock`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Value,
    /// Optional display name. It reaches the UI and the model, so it is
    /// inspected like the description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Every other field the server sent: `annotations`, `outputSchema`,
    /// `icons`, `_meta`, and whatever a later protocol revision adds. Kept so the
    /// pin covers the whole definition: a rug pull that only flips
    /// `annotations.destructiveHint` must not go unnoticed.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Tool {
    /// The whole definition as a JSON value.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}
