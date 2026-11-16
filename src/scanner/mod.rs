use crate::model::Device;
use anyhow::Result;
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::IpAddr;

pub mod hybrid;
pub mod native;
pub mod nmap;

pub use hybrid::HybridScanner;
pub use native::NativeScanner;
pub use nmap::NmapScanner;

/// High-signal TCP ports probed early during Stage 2 (`ports_fast`).
pub const FAST_PROBE_PORTS: &[u16] = &[
    80,   // HTTP
    443,  // HTTPS
    22,   // SSH
    8008, // Google Cast HTTP
    8080, // HTTP Alt / UniFi
    8443, // HTTPS Alt / AsusWRT
    8883, // Secure MQTT (Roomba / IoT)
    9100, // Prometheus Node Exporter / JetDirect
];

/// Secondary TCP ports probed only for unresolved hosts (or `--full`) in Stage 6.
pub const EXTENDED_PROBE_PORTS: &[u16] = &[
    53,    // DNS
    1400,  // UPnP Netgear / Sonos
    5432,  // PostgreSQL
    7788,  // ASUS AiMesh sync
    49152, // UPnP WPS
];

/// Abstract scanner trait enabling pluggable scanning engines with staged host enumeration
/// and targeted port scanning.
#[async_trait]
pub trait NetworkScanner: Send + Sync {
    /// Discovers active hosts in the given network CIDRs without running full port scans.
    async fn enumerate_hosts(&self, targets: &[IpNetwork]) -> Result<Vec<Device>>;

    /// Scans the specified TCP ports across a batch of target hosts.
    async fn scan_ports_batch(
        &self,
        ips: &[IpAddr],
        ports: &[u16],
    ) -> Result<HashMap<IpAddr, Vec<u16>>>;

    /// Runs extended/fallback port discovery (including Nmap `-sT -F` when supported)
    /// across a batch of unresolved hosts.
    async fn scan_extended_ports_batch(&self, ips: &[IpAddr]) -> Result<HashMap<IpAddr, Vec<u16>>>;
}
