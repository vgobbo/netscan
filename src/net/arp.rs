use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::process::Command;
use tracing::debug;

/// Represents an entry in the ARP neighbor table.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: IpAddr,
    pub mac: String,
    pub interface: String,
}

/// Reads the local ARP/neighbor table to map IP addresses to hardware MAC addresses.
pub struct ArpReader;

impl ArpReader {
    /// Retrieves a mapping of IP addresses to MAC addresses.
    /// Tries `/proc/net/arp` first, then falls back to `ip -j neigh` or `ip neigh`.
    pub fn get_table() -> HashMap<IpAddr, String> {
        let mut map = HashMap::new();

        // 1. Try parsing /proc/net/arp (fast Linux virtual file)
        if let Ok(file) = File::open("/proc/net/arp") {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok).skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Format: IP address | HW type | Flags | HW address | Mask | Device
                if parts.len() >= 6 {
                    if let Ok(ip) = parts[0].parse::<IpAddr>() {
                        let mac = parts[3].to_lowercase();
                        if mac != "00:00:00:00:00:00" && mac.contains(':') {
                            map.insert(ip, mac);
                        }
                    }
                }
            }
        }

        if map.is_empty() {
            // 2. Fall back to `ip -j neigh`
            if let Ok(output) = Command::new("ip").args(["-j", "neigh"]).output() {
                if output.status.success() {
                    if let Ok(json_str) = String::from_utf8(output.stdout) {
                        if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
                            for entry in entries {
                                if let (Some(dst), Some(lladdr)) = (
                                    entry.get("dst").and_then(|v| v.as_str()),
                                    entry.get("lladdr").and_then(|v| v.as_str()),
                                ) {
                                    if let Ok(ip) = dst.parse::<IpAddr>() {
                                        let mac = lladdr.to_lowercase();
                                        if mac.contains(':') && mac != "00:00:00:00:00:00" {
                                            map.insert(ip, mac);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 3. Populate local machine's own interfaces (local IPs are not in kernel ARP table)
        if let Ok(output) = Command::new("ip").args(["-j", "addr"]).output() {
            if output.status.success() {
                if let Ok(json_str) = String::from_utf8(output.stdout) {
                    if let Ok(ifaces) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
                        for iface in ifaces {
                            if let Some(mac) = iface.get("address").and_then(|v| v.as_str()) {
                                if mac.contains(':') && mac != "00:00:00:00:00:00" {
                                    if let Some(addrs) = iface.get("addr_info").and_then(|v| v.as_array()) {
                                        for addr in addrs {
                                            if let Some(local_ip_str) = addr.get("local").and_then(|v| v.as_str()) {
                                                if let Ok(ip) = local_ip_str.parse::<IpAddr>() {
                                                    map.entry(ip).or_insert_with(|| mac.to_lowercase());
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
        }

        debug!("Total ARP entries resolved: {}", map.len());
        map
    }
}
