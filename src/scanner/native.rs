use crate::model::Device;
use crate::net::ArpReader;
use crate::scanner::{DEFAULT_PROBE_PORTS, NetworkScanner};
use anyhow::Result;
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::info;

pub struct NativeScanner {
    concurrency: usize,
    timeout_ms: u64,
}

impl NativeScanner {
    pub fn new(concurrency: usize, timeout_ms: u64) -> Self {
        Self {
            concurrency,
            timeout_ms,
        }
    }

    /// Tests if a host is reachable via a fast ICMP ping subprocess.
    async fn is_host_alive_ping(ip: IpAddr) -> bool {
        let res = Command::new("ping")
            .args(["-c", "1", "-W", "1", &ip.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;

        match res {
            Ok(status) => status.success(),
            Err(_) => false,
        }
    }

    /// Tests if a TCP port is open on the target host.
    async fn test_tcp_port(ip: IpAddr, port: u16, timeout_duration: Duration) -> bool {
        let addr = SocketAddr::new(ip, port);
        matches!(
            timeout(timeout_duration, TcpStream::connect(addr)).await,
            Ok(Ok(_))
        )
    }

    /// Resolves the hostname for a given IP address via getent hosts.
    async fn resolve_hostname(ip: IpAddr) -> Option<String> {
        let output = Command::new("getent")
            .args(["hosts", &ip.to_string()])
            .output()
            .await
            .ok()?;

        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return Some(parts[1].to_string());
                }
            }
        }
        None
    }
}

#[async_trait]
impl NetworkScanner for NativeScanner {
    async fn scan_network(&self, targets: &[IpNetwork]) -> Result<Vec<Device>> {
        info!("Starting native async host discovery across target networks...");
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let probe_timeout = Duration::from_millis(self.timeout_ms);

        let mut ip_list = Vec::new();
        for target in targets {
            let zone = if target.to_string().starts_with("192.168.0.") {
                "WAN Interconnect"
            } else {
                "Local LAN"
            };

            for ip in target.iter() {
                // Skip broadcast and network IDs for /24 subnets
                if let IpAddr::V4(v4) = ip {
                    let octets = v4.octets();
                    if octets[3] == 0 || octets[3] == 255 {
                        continue;
                    }
                }
                ip_list.push((ip, zone.to_string()));
            }
        }

        // Phase 1: Ping sweep and initial port probe across all candidate IPs
        let mut sweep_tasks = Vec::new();
        for (ip, zone) in ip_list {
            let permit = sem.clone();
            sweep_tasks.push(tokio::spawn(async move {
                let _p = permit.acquire().await;
                // Ping first
                if Self::is_host_alive_ping(ip).await {
                    return Some((ip, zone));
                }

                // If ICMP ping is blocked or ignored, check critical common ports
                for &port in &[80, 443, 8080, 22, 8008, 8883] {
                    if Self::test_tcp_port(ip, port, Duration::from_millis(400)).await {
                        return Some((ip, zone));
                    }
                }

                None
            }));
        }

        let mut alive_hosts = Vec::new();
        for t in sweep_tasks {
            if let Ok(Some((ip, zone))) = t.await {
                alive_hosts.push((ip, zone));
            }
        }

        info!(
            "Discovered {} active hosts. Reading ARP table and fingerprinting ports...",
            alive_hosts.len()
        );

        // Refresh ARP table to capture hardware MAC addresses
        let arp_table = ArpReader::get_table();

        // Phase 2: Concurrent port scanning and hostname resolution on alive hosts
        let mut dev_tasks = Vec::new();
        for (ip, zone) in alive_hosts {
            let permit = sem.clone();
            let mac = arp_table.get(&ip).cloned();

            dev_tasks.push(tokio::spawn(async move {
                let _p = permit.acquire().await;
                let hostname = Self::resolve_hostname(ip).await;

                // Port scan DEFAULT_PROBE_PORTS
                let mut open_ports = Vec::new();
                for &port in DEFAULT_PROBE_PORTS {
                    if Self::test_tcp_port(ip, port, probe_timeout).await {
                        open_ports.push(port);
                    }
                }

                let mut device = Device::new(ip, zone);
                device.mac = mac;
                device.hostname = hostname.clone();
                if let Some(h) = hostname {
                    device.device_name = h;
                }
                device.open_ports = open_ports;
                device
            }));
        }

        let mut devices = Vec::new();
        for t in dev_tasks {
            if let Ok(dev) = t.await {
                devices.push(dev);
            }
        }

        // Sort devices by IP address
        devices.sort_by_key(|a| a.ip);
        Ok(devices)
    }

    async fn scan_ports(&self, ip: IpAddr, ports: &[u16]) -> Result<Vec<u16>> {
        let probe_timeout = Duration::from_millis(self.timeout_ms);
        let mut open = Vec::new();
        for &port in ports {
            if Self::test_tcp_port(ip, port, probe_timeout).await {
                open.push(port);
            }
        }
        Ok(open)
    }
}
