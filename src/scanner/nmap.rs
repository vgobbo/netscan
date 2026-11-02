use crate::model::Device;
use crate::net::ArpReader;
use crate::scanner::NetworkScanner;
use anyhow::{Context, Result};
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use regex::Regex;
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
}

#[async_trait]
impl NetworkScanner for NmapScanner {
    async fn scan_network(&self, targets: &[IpNetwork]) -> Result<Vec<Device>> {
        info!("Executing Nmap ping and port discovery...");
        let target_strs: Vec<String> = targets.iter().map(|t| t.to_string()).collect();

        // 1. Run nmap -sn to discover hosts
        let mut cmd = Command::new("nmap");
        cmd.arg("-sn");
        cmd.args(&target_strs);

        let output = cmd.output().await.context("Failed to run nmap")?;
        let text = String::from_utf8_lossy(&output.stdout);

        let report_re =
            Regex::new(r"Nmap scan report for (?:([^\s()]+)\s+\()?([0-9.]+)\)?").unwrap();
        let mac_re = Regex::new(r"MAC Address: ([0-9A-Fa-f:]{17})\s*(?:\((.*?)\))?").unwrap();

        let mut discovered = Vec::new();
        let mut current_ip: Option<IpAddr> = None;
        let mut current_hostname: Option<String> = None;
        let mut current_mac: Option<String> = None;
        let mut current_vendor: Option<String> = None;

        for line in text.lines() {
            if let Some(caps) = report_re.captures(line) {
                if let Some(ip) = current_ip {
                    let zone = targets
                        .iter()
                        .find(|t| t.contains(ip))
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "LAN".to_string());
                    let mut dev = Device::new(ip, zone);
                    dev.hostname = current_hostname.clone();
                    dev.mac = current_mac.clone();
                    dev.vendor = current_vendor.clone();
                    if let Some(h) = current_hostname.clone() {
                        dev.device_name = h;
                    }
                    discovered.push(dev);
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
            let zone = targets
                .iter()
                .find(|t| t.contains(ip))
                .map(|t| t.to_string())
                .unwrap_or_else(|| "LAN".to_string());
            let mut dev = Device::new(ip, zone);
            dev.hostname = current_hostname.clone();
            dev.mac = current_mac.clone();
            dev.vendor = current_vendor.clone();
            if let Some(h) = current_hostname {
                dev.device_name = h;
            }
            discovered.push(dev);
        }

        // Fill any missing MAC addresses from ARP table
        let arp = ArpReader::get_table();
        for dev in &mut discovered {
            if dev.mac.is_none()
                && let Some(m) = arp.get(&dev.ip)
            {
                dev.mac = Some(m.clone());
            }
        }

        // 2. Scan ports for discovered devices
        if !discovered.is_empty() {
            let ips: Vec<String> = discovered.iter().map(|d| d.ip.to_string()).collect();
            let mut port_cmd = Command::new("nmap");
            port_cmd.args(["-sT", "-F"]);
            port_cmd.args(&ips);

            if let Ok(port_output) = port_cmd.output().await {
                let port_text = String::from_utf8_lossy(&port_output.stdout);
                let port_re = Regex::new(r"^(\d+)/tcp\s+open").unwrap();

                let mut cur_ip: Option<IpAddr> = None;
                for line in port_text.lines() {
                    if let Some(caps) = report_re.captures(line) {
                        cur_ip = caps.get(2).and_then(|m| m.as_str().parse::<IpAddr>().ok());
                    } else if let Some(caps) = port_re.captures(line)
                        && let (Some(ip), Some(p_str)) = (cur_ip, caps.get(1))
                        && let Ok(p) = p_str.as_str().parse::<u16>()
                        && let Some(dev) = discovered.iter_mut().find(|d| d.ip == ip)
                        && !dev.open_ports.contains(&p)
                    {
                        dev.open_ports.push(p);
                    }
                }
            }
        }

        discovered.sort_by_key(|a| a.ip);
        Ok(discovered)
    }

    async fn scan_ports(&self, ip: IpAddr, _ports: &[u16]) -> Result<Vec<u16>> {
        let mut cmd = Command::new("nmap");
        cmd.args(["-sT", "-F", &ip.to_string()]);
        let output = cmd.output().await.context("Failed to run nmap")?;
        let text = String::from_utf8_lossy(&output.stdout);

        let port_re = Regex::new(r"^(\d+)/tcp\s+open").unwrap();
        let mut open = Vec::new();
        for line in text.lines() {
            if let Some(caps) = port_re.captures(line)
                && let Ok(p) = caps[1].parse::<u16>()
            {
                open.push(p);
            }
        }
        Ok(open)
    }
}
