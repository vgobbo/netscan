use crate::fingerprint::findings::HostFindings;
use reqwest::Client;
use std::net::IpAddr;
use std::time::Duration;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct GoogleCastInfo {
    pub name: String,
    pub model_name: Option<String>,
}

impl GoogleCastInfo {
    /// Stores Cast metadata in the host findings attribute map for TOML rule matching.
    pub fn populate_findings(&self, findings: &mut HostFindings) {
        findings
            .attributes
            .insert("cast.name".to_string(), self.name.clone());
        if let Some(model) = &self.model_name {
            findings
                .attributes
                .insert("cast.model_name".to_string(), model.clone());
        }
    }
}

pub struct CastProber;

impl CastProber {
    /// Attempts to query Google Cast eureka_info API on port 8008.
    pub async fn probe(client: &Client, ip: IpAddr) -> Option<GoogleCastInfo> {
        let url = format!("http://{}:8008/setup/eureka_info", ip);
        let resp = client
            .get(&url)
            .timeout(Duration::from_millis(1500))
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            return None;
        }

        let json = resp.json::<serde_json::Value>().await.ok()?;
        let name = json
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())?;

        let model_name = json
            .get("model_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        debug!("Google Cast device discovered at {}: {}", ip, name);
        Some(GoogleCastInfo { name, model_name })
    }
}
