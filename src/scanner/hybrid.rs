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
    async fn enumerate_hosts(&self, targets: &[IpNetwork]) -> Result<Vec<Device>> {
        info!("Running Hybrid host enumeration (Native async + Nmap -sn)...");

        let native_devices = self.native.enumerate_hosts(targets).await?;
        let mut device_map: HashMap<IpAddr, Device> =
            native_devices.into_iter().map(|d| (d.ip, d)).collect();

        if NmapScanner::is_available().await {
            info!("Enriching host enumeration with Nmap (-sn)...");
            if let Ok(nmap_devices) = self.nmap.enumerate_hosts(targets).await {
                for ndev in nmap_devices {
                    let entry = device_map.entry(ndev.ip).or_insert_with(|| ndev.clone());
                    if entry.mac.is_none() && ndev.mac.is_some() {
                        entry.mac = ndev.mac;
                    }
                    if entry.hostname.is_none() && ndev.hostname.is_some() {
                        entry.hostname = ndev.hostname;
                    }
                    if entry.vendor.is_none() && ndev.vendor.is_some() {
                        entry.vendor = ndev.vendor;
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

    async fn scan_ports_batch(
        &self,
        ips: &[IpAddr],
        ports: &[u16],
    ) -> Result<HashMap<IpAddr, Vec<u16>>> {
        self.native.scan_ports_batch(ips, ports).await
    }

    async fn scan_extended_ports_batch(&self, ips: &[IpAddr]) -> Result<HashMap<IpAddr, Vec<u16>>> {
        let mut merged = self.native.scan_extended_ports_batch(ips).await?;
        if NmapScanner::is_available().await
            && let Ok(nmap_ports) = self.nmap.scan_extended_ports_batch(ips).await
        {
            for (ip, ports) in nmap_ports {
                let entry = merged.entry(ip).or_default();
                for p in ports {
                    if !entry.contains(&p) {
                        entry.push(p);
                    }
                }
                entry.sort_unstable();
            }
        }
        Ok(merged)
    }
}
