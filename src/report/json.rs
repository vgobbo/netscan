use crate::model::NetworkTopology;
use anyhow::{Context, Result};

pub struct JsonGenerator;

impl JsonGenerator {
    /// Serializes the abstract network topology into structured, pretty-printed JSON
    /// for integration with external tools, APIs, and dashboards.
    pub fn generate(topology: &NetworkTopology) -> Result<String> {
        serde_json::to_string_pretty(topology)
            .context("Failed to serialize network topology to JSON")
    }
}
