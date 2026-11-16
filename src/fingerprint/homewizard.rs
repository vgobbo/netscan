use crate::fingerprint::findings::HostFindings;
use reqwest::Client;
use std::net::IpAddr;
use std::time::Duration;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct HomeWizardInfo {
    pub product_name: String,
    pub product_type: String,
    pub serial: Option<String>,
    pub firmware_version: Option<String>,
}

impl HomeWizardInfo {
    /// Stores HomeWizard metadata in the host findings attribute map for TOML rule matching.
    pub fn populate_findings(&self, findings: &mut HostFindings) {
        findings.attributes.insert(
            "homewizard.product_name".to_string(),
            self.product_name.clone(),
        );
        findings.attributes.insert(
            "homewizard.product_type".to_string(),
            self.product_type.clone(),
        );
        if let Some(serial) = &self.serial {
            findings
                .attributes
                .insert("homewizard.serial".to_string(), serial.clone());
        }
        if let Some(ver) = &self.firmware_version {
            findings
                .attributes
                .insert("homewizard.firmware_version".to_string(), ver.clone());
        }
    }
}

pub struct HomeWizardProber;

impl HomeWizardProber {
    /// Attempts to query the HomeWizard Energy local REST API at /api.
    pub async fn probe(client: &Client, ip: IpAddr) -> Option<HomeWizardInfo> {
        let url = format!("http://{}/api", ip);
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
        let product_name = json
            .get("product_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())?;

        let product_type = json
            .get("product_type")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();

        let serial = json
            .get("serial")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let firmware_version = json
            .get("firmware_version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        debug!(
            "HomeWizard device found at {}: {} ({})",
            ip, product_name, product_type
        );

        Some(HomeWizardInfo {
            product_name,
            product_type,
            serial,
            firmware_version,
        })
    }
}
