use crate::model::Device;
use anyhow::Result;
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use std::net::IpAddr;

pub mod hybrid;
pub mod native;
pub mod nmap;

pub use hybrid::HybridScanner;
pub use native::NativeScanner;
pub use nmap::NmapScanner;

/// Common ports probed during rapid network sweeps.
pub const DEFAULT_PROBE_PORTS: &[u16] = &[
    80,    // HTTP
    443,   // HTTPS
    22,    // SSH
    53,    // DNS
    8080,  // HTTP Alt / UniFi
    8443,  // HTTPS Alt / AsusWRT
    8008,  // Google Cast HTTP
    8009,  // Google Cast AJP
    8883,  // Secure MQTT (Roomba / IoT)
    9100,  // Prometheus Node Exporter / JetDirect
    5432,  // PostgreSQL
    1400,  // UPnP Netgear / Sonos
    7788,  // ASUS AiMesh sync
    49152, // UPnP WPS
];

/// Abstract scanner trait enabling pluggable scanning engines.
#[async_trait]
pub trait NetworkScanner: Send + Sync {
    /// Discovers active hosts in the given network CIDRs.
    async fn scan_network(&self, targets: &[IpNetwork]) -> Result<Vec<Device>>;

    /// Identifies open TCP ports on a given host.
    #[allow(dead_code)]
    async fn scan_ports(&self, ip: IpAddr, ports: &[u16]) -> Result<Vec<u16>>;
}
