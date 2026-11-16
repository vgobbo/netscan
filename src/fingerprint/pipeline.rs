use crate::fingerprint::cast::CastProber;
use crate::fingerprint::daikin::DaikinProber;
use crate::fingerprint::homewizard::HomeWizardProber;
use crate::fingerprint::http::HttpProber;
use crate::fingerprint::oui::OuiMatcher;
use crate::fingerprint::rules::RuleEngine;
use crate::model::Device;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::debug;

pub struct FingerprintPipeline {
    client: Client,
    concurrency: usize,
}

impl FingerprintPipeline {
    pub fn new(concurrency: usize) -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_millis(1500))
            .build()
            .unwrap_or_default();

        Self {
            client,
            concurrency,
        }
    }

    /// Enriches a collection of devices in parallel using Tokio tasks.
    pub async fn enrich_all(&self, devices: &mut [Device]) {
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let mut handles = Vec::new();

        for dev in devices.iter() {
            let mut device = dev.clone();
            let client = self.client.clone();
            let permit = sem.clone();

            handles.push(tokio::spawn(async move {
                let _p = permit.acquire().await;
                Self::enrich_device(&mut device, &client).await;
                device
            }));
        }

        let mut enriched = Vec::new();
        for h in handles {
            if let Ok(dev) = h.await {
                enriched.push(dev);
            }
        }

        // Reassign back to the slice
        for (idx, dev) in enriched.into_iter().enumerate() {
            if idx < devices.len() {
                devices[idx] = dev;
            }
        }
    }

    /// Enriches a single device using MAC, HTTP, Cast, HomeWizard, and Daikin probes.
    pub async fn enrich_device(device: &mut Device, client: &Client) {
        // 1. MAC Vendor Lookup
        if let Some(mac) = &device.mac
            && let Some(vendor) = OuiMatcher::lookup(mac)
        {
            device.vendor = Some(vendor);
        }

        // 2. HTTP / HTTPS Probing
        let http_fp = HttpProber::probe(client, device.ip, &device.open_ports).await;
        if let Some(title) = &http_fp.title {
            device.http_title = Some(title.clone());
        }
        if let Some(server) = &http_fp.server {
            device.http_server = Some(server.clone());
        }

        // 3. Google Cast Probing (if port 8008 open or unknown)
        let cast_info = if device.open_ports.contains(&8008) || device.open_ports.is_empty() {
            CastProber::probe(client, device.ip).await
        } else {
            None
        };

        // 4. HomeWizard Probing (if port 80 open)
        let hw_info = if device.open_ports.contains(&80) {
            HomeWizardProber::probe(client, device.ip).await
        } else {
            None
        };

        // 5. Daikin Probing (UDP discovery on port 30050 / HTTP /common/basic_info fallback)
        let vendor_matches_daikin = device.vendor.as_deref().is_some_and(|v| {
            let lower = v.to_lowercase();
            lower.contains("daikin") || lower.contains("murata")
        });
        let should_probe_daikin = http_fp.is_daikin
            || device.open_ports.contains(&80)
            || device.open_ports.is_empty()
            || vendor_matches_daikin;
        let daikin_info = if should_probe_daikin && cast_info.is_none() && hw_info.is_none() {
            DaikinProber::probe(client, device.ip, &device.open_ports).await
        } else {
            None
        };

        // 6. Apply Rules Engine
        RuleEngine::classify(
            device,
            &http_fp,
            cast_info.as_ref(),
            hw_info.as_ref(),
            daikin_info.as_ref(),
        );

        debug!(
            "Device {} fingerprinted as: {} ({})",
            device.ip, device.device_name, device.device_type
        );
    }
}
