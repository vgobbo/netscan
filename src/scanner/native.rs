use crate::model::Device;
use crate::scanner::{EXTENDED_PROBE_PORTS, NetworkScanner};
use anyhow::Result;
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use std::collections::HashMap;
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

        matches!(res, Ok(status) if status.success())
    }

    /// Tests if a TCP port is open on the target host.
    async fn test_tcp_port(ip: IpAddr, port: u16, timeout_duration: Duration) -> bool {
        let addr = SocketAddr::new(ip, port);
        matches!(
            timeout(timeout_duration, TcpStream::connect(addr)).await,
            Ok(Ok(_))
        )
    }

    /// Resolves the hostname for a given IP address via `getent hosts`.
    pub async fn resolve_hostname(ip: IpAddr) -> Option<String> {
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
    async fn enumerate_hosts(&self, targets: &[IpNetwork]) -> Result<Vec<Device>> {
        info!("Starting native async host enumeration across target networks...");
        let sem = Arc::new(Semaphore::new(self.concurrency));

        let mut ip_list = Vec::new();
        for target in targets {
            let zone = target.to_string();

            for ip in target.iter() {
                if let IpAddr::V4(v4) = ip {
                    let octets = v4.octets();
                    if octets[3] == 0 || octets[3] == 255 {
                        continue;
                    }
                }
                ip_list.push((ip, zone.clone()));
            }
        }

        let mut sweep_tasks = Vec::new();
        for (ip, zone) in ip_list {
            let permit = sem.clone();
            sweep_tasks.push(tokio::spawn(async move {
                let _p = permit.acquire().await;
                if Self::is_host_alive_ping(ip).await {
                    return Some(Device::new(ip, zone));
                }

                // Fallback TCP knock if ICMP ping is ignored
                for &port in &[80, 443, 8080, 22, 8008, 8883] {
                    if Self::test_tcp_port(ip, port, Duration::from_millis(400)).await {
                        let mut dev = Device::new(ip, zone);
                        dev.open_ports.push(port);
                        return Some(dev);
                    }
                }

                None
            }));
        }

        let mut devices = Vec::new();
        for t in sweep_tasks {
            if let Ok(Some(dev)) = t.await {
                devices.push(dev);
            }
        }

        devices.sort_by_key(|a| a.ip);
        info!(
            "Native enumeration discovered {} active host(s)",
            devices.len()
        );
        Ok(devices)
    }

    async fn scan_ports_batch(
        &self,
        ips: &[IpAddr],
        ports: &[u16],
    ) -> Result<HashMap<IpAddr, Vec<u16>>> {
        let mut results = HashMap::new();
        if ips.is_empty() || ports.is_empty() {
            return Ok(results);
        }

        let sem = Arc::new(Semaphore::new(self.concurrency));
        let probe_timeout = Duration::from_millis(self.timeout_ms.min(600));
        let mut tasks = Vec::new();

        for &ip in ips {
            for &port in ports {
                let permit = sem.clone();
                tasks.push(tokio::spawn(async move {
                    let _p = permit.acquire().await;
                    let open = Self::test_tcp_port(ip, port, probe_timeout).await;
                    (ip, port, open)
                }));
            }
        }

        for t in tasks {
            if let Ok((ip, port, true)) = t.await {
                results.entry(ip).or_insert_with(Vec::new).push(port);
            }
        }

        for list in results.values_mut() {
            list.sort_unstable();
            list.dedup();
        }

        Ok(results)
    }

    async fn scan_extended_ports_batch(&self, ips: &[IpAddr]) -> Result<HashMap<IpAddr, Vec<u16>>> {
        self.scan_ports_batch(ips, EXTENDED_PROBE_PORTS).await
    }
}
