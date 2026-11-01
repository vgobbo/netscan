use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use tracing::info;

/// Information about a detected network interface and its subnet.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct LocalInterfaceInfo {
    pub interface_name: String,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub network: IpNetwork,
    pub gateway: Option<Ipv4Addr>,
}

pub struct InterfaceDetector;

impl InterfaceDetector {
    /// Detects the primary active LAN subnet and default gateway.
    pub fn detect_primary() -> Result<LocalInterfaceInfo> {
        let (gateway, iface) = Self::detect_default_route()
            .context("Could not determine default route")?;

        let (ip, prefix_len) = Self::detect_ip_for_interface(&iface)
            .context(format!("Could not determine IP for interface {}", iface))?;

        let network = IpNetwork::new(IpAddr::V4(ip), prefix_len)
            .map_err(|e| anyhow::anyhow!("Invalid network CIDR: {}", e))?;

        info!(
            "Auto-detected primary interface: {} ({}/{}, default gateway: {:?})",
            iface, ip, prefix_len, gateway
        );

        Ok(LocalInterfaceInfo {
            interface_name: iface,
            ip,
            prefix_len,
            network,
            gateway,
        })
    }

    /// Detects the default gateway IPv4 and outgoing network interface name.
    pub fn detect_default_route() -> Result<(Option<Ipv4Addr>, String)> {
        // Try `ip -j route`
        if let Ok(output) = Command::new("ip").args(["-j", "route"]).output() {
            if output.status.success() {
                if let Ok(json_str) = String::from_utf8(output.stdout) {
                    if let Ok(routes) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
                        for route in routes {
                            if route.get("dst").and_then(|v| v.as_str()) == Some("default") {
                                let dev = route
                                    .get("dev")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("eth0")
                                    .to_string();
                                let gateway = route
                                    .get("gateway")
                                    .and_then(|v| v.as_str())
                                    .and_then(|g| g.parse::<Ipv4Addr>().ok());
                                return Ok((gateway, dev));
                            }
                        }
                    }
                }
            }
        }

        // Fallback: standard `ip route`
        if let Ok(output) = Command::new("ip").args(["route"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 && parts[0] == "default" && parts[1] == "via" {
                        let gw = parts[2].parse::<Ipv4Addr>().ok();
                        let dev = parts[4].to_string();
                        return Ok((gw, dev));
                    }
                }
            }
        }

        anyhow::bail!("No default route found");
    }

    /// Retrieves IPv4 address and prefix length for a given interface.
    pub fn detect_ip_for_interface(interface_name: &str) -> Result<(Ipv4Addr, u8)> {
        // Try `ip -j addr show dev <interface_name>`
        if let Ok(output) = Command::new("ip")
            .args(["-j", "addr", "show", "dev", interface_name])
            .output()
        {
            if output.status.success() {
                if let Ok(json_str) = String::from_utf8(output.stdout) {
                    if let Ok(ifaces) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
                        for iface in ifaces {
                            if let Some(addr_infos) = iface.get("addr_info").and_then(|v| v.as_array()) {
                                for addr in addr_infos {
                                    if addr.get("family").and_then(|v| v.as_str()) == Some("inet") {
                                        if let (Some(local), Some(prefixlen)) = (
                                            addr.get("local").and_then(|v| v.as_str()),
                                            addr.get("prefixlen").and_then(|v| v.as_u64()),
                                        ) {
                                            if let Ok(ipv4) = local.parse::<Ipv4Addr>() {
                                                return Ok((ipv4, prefixlen as u8));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        anyhow::bail!("Interface {} not found or has no IPv4 address", interface_name)
    }
}
