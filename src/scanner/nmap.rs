use crate::model::Device;
use crate::scanner::NetworkScanner;
use anyhow::{Context, Result};
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::process::Command;
use tracing::info;

pub struct NmapScanner {
    #[allow(dead_code)]
    timeout_ms: u64,
}

impl NmapScanner {
    pub fn new(timeout_ms: u64) -> Self {
        Self { timeout_ms }
    }

    /// Verifies if nmap binary is available in PATH.
    pub async fn is_available() -> bool {
        Command::new("nmap")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    async fn run_nmap_ports(
        &self,
        ips: &[IpAddr],
        ports: Option<&[u16]>,
    ) -> Result<HashMap<IpAddr, Vec<u16>>> {
        let mut results: HashMap<IpAddr, Vec<u16>> = HashMap::new();
        if ips.is_empty() {
            return Ok(results);
        }

        let ip_strs: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
        let mut cmd = Command::new("nmap");
        cmd.arg("-sT");
        if let Some(port_list) = ports {
            if port_list.is_empty() {
                return Ok(results);
            }
            let p_arg = port_list
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            cmd.args(["-p", &p_arg]);
        } else {
            cmd.arg("-F");
        }
        cmd.args(&ip_strs);

        let output = cmd.output().await.context("Failed to run nmap port scan")?;
        let text = String::from_utf8_lossy(&output.stdout);

        let report_re =
            Regex::new(r"Nmap scan report for (?:([^\s()]+)\s+\()?([0-9.]+)\)?").unwrap();
        let port_re = Regex::new(r"^(\d+)/tcp\s+open").unwrap();

        let mut cur_ip: Option<IpAddr> = None;
        for line in text.lines() {
            if let Some(caps) = report_re.captures(line) {
                cur_ip = caps.get(2).and_then(|m| m.as_str().parse::<IpAddr>().ok());
            } else if let Some(caps) = port_re.captures(line)
                && let (Some(ip), Some(p_str)) = (cur_ip, caps.get(1))
                && let Ok(p) = p_str.as_str().parse::<u16>()
            {
                let entry = results.entry(ip).or_default();
                if !entry.contains(&p) {
                    entry.push(p);
                }
            }
        }

        for list in results.values_mut() {
            list.sort_unstable();
        }
        Ok(results)
    }
}

#[async_trait]
impl NetworkScanner for NmapScanner {
    async fn enumerate_hosts(&self, targets: &[IpNetwork]) -> Result<Vec<Device>> {
        info!("Executing Nmap host enumeration (-sn)...");
        let target_strs: Vec<String> = targets.iter().map(|t| t.to_string()).collect();

        let mut cmd = Command::new("nmap");
        cmd.arg("-sn");
        cmd.args(&target_strs);

        let output = cmd.output().await.context("Failed to run nmap -sn")?;
        let text = String::from_utf8_lossy(&output.stdout);

        let report_re =
            Regex::new(r"Nmap scan report for (?:([^\s()]+)\s+\()?([0-9.]+)\)?").unwrap();
        let mac_re = Regex::new(r"MAC Address: ([0-9A-Fa-f:]{17})\s*(?:\((.*?)\))?").unwrap();

        let mut discovered = Vec::new();
        let mut current_ip: Option<IpAddr> = None;
        let mut current_hostname: Option<String> = None;
        let mut current_mac: Option<String> = None;
        let mut current_vendor: Option<String> = None;

        let flush = |discovered: &mut Vec<Device>,
                     ip: IpAddr,
                     hostname: Option<String>,
                     mac: Option<String>,
                     vendor: Option<String>| {
            let zone = targets
                .iter()
                .find(|t| t.contains(ip))
                .map(|t| t.to_string())
                .unwrap_or_else(|| "LAN".to_string());
            let mut dev = Device::new(ip, zone);
            dev.hostname = hostname.clone();
            dev.mac = mac;
            dev.vendor = vendor;
            if let Some(h) = hostname {
                dev.device_name = h;
            }
            discovered.push(dev);
        };

        for line in text.lines() {
            if let Some(caps) = report_re.captures(line) {
                if let Some(ip) = current_ip {
                    flush(
                        &mut discovered,
                        ip,
                        current_hostname.clone(),
                        current_mac.clone(),
                        current_vendor.clone(),
                    );
                }

                current_hostname = caps.get(1).map(|m| m.as_str().to_string());
                current_ip = caps.get(2).and_then(|m| m.as_str().parse::<IpAddr>().ok());
                current_mac = None;
                current_vendor = None;
            } else if let Some(caps) = mac_re.captures(line) {
                current_mac = caps.get(1).map(|m| m.as_str().to_lowercase());
                current_vendor = caps.get(2).map(|m| m.as_str().to_string());
            }
        }

        if let Some(ip) = current_ip {
            flush(
                &mut discovered,
                ip,
                current_hostname,
                current_mac,
                current_vendor,
            );
        }

        discovered.sort_by_key(|a| a.ip);
        Ok(discovered)
    }

    async fn scan_ports_batch(
        &self,
        ips: &[IpAddr],
        ports: &[u16],
    ) -> Result<HashMap<IpAddr, Vec<u16>>> {
        self.run_nmap_ports(ips, Some(ports)).await
    }

    async fn scan_extended_ports_batch(&self, ips: &[IpAddr]) -> Result<HashMap<IpAddr, Vec<u16>>> {
        self.run_nmap_ports(ips, None).await
    }
}
