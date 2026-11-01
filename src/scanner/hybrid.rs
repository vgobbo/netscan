use crate::model::Device;
use crate::scanner::NetworkScanner;
use crate::scanner::native::NativeScanner;
use crate::scanner::nmap::NmapScanner;
use anyhow::Result;
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::info;

pub struct HybridScanner {
    native: NativeScanner,
    nmap: NmapScanner,
}

impl HybridScanner {
    pub fn new(concurrency: usize, timeout_ms: u64) -> Self {
        Self {
            native: NativeScanner::new(concurrency, timeout_ms),
            nmap: NmapScanner::new(timeout_ms),
        }
    }
}

#[async_trait]
impl NetworkScanner for HybridScanner {
    async fn scan_network(&self, targets: &[IpNetwork]) -> Result<Vec<Device>> {
        info!("Running Hybrid scanning engine (Native async + Nmap)...");

        // 1. Run Native async sweep
        let native_devices = self.native.scan_network(targets).await?;

        // 2. If Nmap is available, run Nmap to discover any hosts that drop ICMP/standard TCP
        let mut device_map: HashMap<IpAddr, Device> =
            native_devices.into_iter().map(|d| (d.ip, d)).collect();

        if NmapScanner::is_available().await {
            info!("Enriching host discovery with Nmap backend...");
            if let Ok(nmap_devices) = self.nmap.scan_network(targets).await {
                for ndev in nmap_devices {
                    let entry = device_map.entry(ndev.ip).or_insert_with(|| ndev.clone());
                    if entry.mac.is_none() && ndev.mac.is_some() {
                        entry.mac = ndev.mac;
                    }
                    if entry.hostname.is_none() && ndev.hostname.is_some() {
                        entry.hostname = ndev.hostname;
                    }
                    for port in ndev.open_ports {
                        if !entry.open_ports.contains(&port) {
                            entry.open_ports.push(port);
                        }
                    }
                }
            }
        }

        let mut all_devices: Vec<Device> = device_map.into_values().collect();
        all_devices.sort_by_key(|a| a.ip);
        Ok(all_devices)
    }

    async fn scan_ports(&self, ip: IpAddr, ports: &[u16]) -> Result<Vec<u16>> {
        self.native.scan_ports(ip, ports).await
    }
}
