use crate::model::{UpstreamHop, UpstreamPath};
use anyhow::Result;
use ipnetwork::IpNetwork;
use regex::Regex;
use reqwest::Client;
use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

pub struct UpstreamTracer {
    client: Client,
}

impl UpstreamTracer {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self { client }
    }

    /// Traces the upstream network path from the local gateway to the public Internet,
    /// dynamically identifying intermediate subnets (such as double-NAT/modem links) and carrier hops.
    pub async fn trace(
        &self,
        primary_subnet: Option<&IpNetwork>,
        default_gateway: Option<IpAddr>,
    ) -> Result<UpstreamPath> {
        info!("Tracing upstream network hops between gateway and Internet...");
        let mut path = UpstreamPath::default();

        // 1. Fetch Public IP and ISP Information via Reqwest
        self.fetch_public_ip_info(&mut path).await;

        // 2. Execute tracepath asynchronously
        self.trace_route_hops(&mut path, primary_subnet, default_gateway)
            .await;

        info!(
            "Upstream path mapped: Public IP: {:?}, Intermediate Subnets: {:?}",
            path.public_ip, path.intermediate_subnets
        );

        Ok(path)
    }

    /// Queries public IP service using reqwest.
    async fn fetch_public_ip_info(&self, path: &mut UpstreamPath) {
        if let Ok(resp) = self.client.get("https://ipinfo.io/json").send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(ip_str) = json.get("ip").and_then(|v| v.as_str())
                    && let Ok(ip) = ip_str.parse::<IpAddr>()
                {
                    path.public_ip = Some(ip);
                }
                if let Some(hostname) = json.get("hostname").and_then(|v| v.as_str()) {
                    path.reverse_dns = Some(hostname.to_string());
                }
                if let Some(org) = json.get("org").and_then(|v| v.as_str()) {
                    path.carrier_as = Some(org.to_string());
                }
            }
        } else if let Ok(resp) = self.client.get("https://api.ipify.org").send().await
            && let Ok(text) = resp.text().await
            && let Ok(ip) = text.trim().parse::<IpAddr>()
        {
            path.public_ip = Some(ip);
        }
    }

    /// Executes tracepath to inspect each intermediate hop dynamically.
    async fn trace_route_hops(
        &self,
        path: &mut UpstreamPath,
        primary_subnet: Option<&IpNetwork>,
        default_gateway: Option<IpAddr>,
    ) {
        let output = tokio::time::timeout(
            Duration::from_secs(6),
            Command::new("tracepath")
                .args(["-m", "6", "-n", "8.8.8.8"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output(),
        )
        .await;

        let hop_re = Regex::new(r"^\s*(\d+):\s+([0-9.]+)\s+([0-9.]+)ms").unwrap();

        if let Ok(Ok(out)) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut hops = Vec::new();
            let mut reached_public = false;

            for line in text.lines() {
                if let Some(caps) = hop_re.captures(line) {
                    let hop_num: u8 = caps[1].parse().unwrap_or(0);
                    let ip: Option<IpAddr> = caps[2].parse().ok();
                    let rtt_str = &caps[3];
                    let rtt: Option<f32> = rtt_str.trim_end_matches("ms").parse().ok();

                    if let Some(hop_ip) = ip {
                        let is_priv = is_private_ip(hop_ip);
                        let in_primary = primary_subnet
                            .map(|net| net.contains(hop_ip))
                            .unwrap_or(false);

                        if !is_priv && !is_cgnat(hop_ip) {
                            reached_public = true;
                        }

                        // If private, not in primary local subnet, and BEFORE reaching public internet:
                        // It is an intermediate interconnect subnet!
                        if is_priv && !in_primary && !reached_public {
                            let subnet_str = derive_subnet_cidr(hop_ip);
                            if !path.intermediate_subnets.contains(&subnet_str) {
                                path.intermediate_subnets.push(subnet_str.clone());
                            }
                        }

                        // Categorize hop dynamically
                        let (network_label, description) =
                            if hop_num == 1 && (in_primary || Some(hop_ip) == default_gateway) {
                                (
                                    "Local LAN Gateway".to_string(),
                                    "Primary Default Gateway".to_string(),
                                )
                            } else if is_priv && !in_primary && !reached_public {
                                let sub = derive_subnet_cidr(hop_ip);
                                (
                                    format!("WAN Interconnect ({})", sub),
                                    "Intermediate Upstream Gateway / CPE Modem".to_string(),
                                )
                            } else if is_priv || is_cgnat(hop_ip) {
                                (
                                    "Carrier Core / CGNAT Transit".to_string(),
                                    "Carrier Internal Core Routing".to_string(),
                                )
                            } else if hop_num <= 3 {
                                let isp_label = path
                                    .carrier_as
                                    .as_deref()
                                    .unwrap_or("Broadband Network Gateway");
                                (
                                    format!("Carrier Edge ({})", isp_label),
                                    "Broadband Network Gateway Termination".to_string(),
                                )
                            } else {
                                (
                                    "Public Internet Transit".to_string(),
                                    "Upstream Internet Backbone Hop".to_string(),
                                )
                            };

                        if !hops.iter().any(|h: &UpstreamHop| h.hop_number == hop_num) {
                            hops.push(UpstreamHop {
                                hop_number: hop_num,
                                ip: Some(hop_ip),
                                hostname: None,
                                rtt_ms: rtt,
                                is_private: is_priv,
                                network_label,
                                description,
                            });
                        }
                    }
                }
            }

            if !hops.is_empty() {
                path.hops = hops;
                return;
            }
        }

        // Fallback: If tracepath is unavailable or blocked, synthesize from verified system info
        let mut fallback_hops = Vec::new();
        if let Some(gw) = default_gateway {
            fallback_hops.push(UpstreamHop {
                hop_number: 1,
                ip: Some(gw),
                hostname: None,
                rtt_ms: None,
                is_private: true,
                network_label: "Local LAN Gateway".to_string(),
                description: "Primary Default Gateway".to_string(),
            });
        }
        if let Some(pub_ip) = path.public_ip {
            let isp_label = path.carrier_as.as_deref().unwrap_or("Public Internet");
            fallback_hops.push(UpstreamHop {
                hop_number: 2,
                ip: Some(pub_ip),
                hostname: path.reverse_dns.clone(),
                rtt_ms: None,
                is_private: false,
                network_label: format!("Internet Egress ({})", isp_label),
                description: "Public Internet Egress".to_string(),
            });
        }
        path.hops = fallback_hops;
    }
}

/// Checks if an IP is in RFC 1918 private IPv4 space.
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
        }
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Checks if an IP is in RFC 6598 CGNAT space (100.64.0.0/10).
fn is_cgnat(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 100 && (64..=127).contains(&octets[1])
        }
        IpAddr::V6(_) => false,
    }
}

/// Derives a standard /24 CIDR representation from a private IP.
fn derive_subnet_cidr(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => format!("{}/64", v6),
    }
}
