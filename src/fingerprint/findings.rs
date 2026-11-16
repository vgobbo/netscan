use crate::model::Device;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

/// Ordered discovery/probing stages executed from fastest to slowest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerKind {
    ArpOuiRdns,
    PortsFast,
    UdpDiscovery,
    Http,
    ApiProtocols,
    PortsExtendedNmap,
}

impl ScannerKind {
    /// Returns the canonical fastest-to-slowest scanner execution order.
    pub const fn ordered_stages() -> &'static [Self] {
        &[
            Self::ArpOuiRdns,
            Self::PortsFast,
            Self::UdpDiscovery,
            Self::Http,
            Self::ApiProtocols,
            Self::PortsExtendedNmap,
        ]
    }
}

impl fmt::Display for ScannerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArpOuiRdns => write!(f, "arp_oui_rdns"),
            Self::PortsFast => write!(f, "ports_fast"),
            Self::UdpDiscovery => write!(f, "udp_discovery"),
            Self::Http => write!(f, "http"),
            Self::ApiProtocols => write!(f, "api_protocols"),
            Self::PortsExtendedNmap => write!(f, "ports_extended_nmap"),
        }
    }
}

/// Optional HTTP sub-path probe declared in TOML rules (e.g., `/metrics` on port 9100).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpEndpointSpec {
    pub port: u16,
    pub path: String,
}

/// Raw protocol-agnostic observations accumulated for a discovered host across scanner stages.
#[derive(Debug, Clone)]
pub struct HostFindings {
    pub ip: IpAddr,
    pub network_zone: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub is_gateway: bool,
    pub open_ports: Vec<u16>,
    pub http_title: Option<String>,
    pub http_server: Option<String>,
    pub http_bodies: Vec<String>,
    pub http_endpoints: BTreeMap<String, String>,
    pub attributes: BTreeMap<String, String>,
    pub completed_scanners: BTreeSet<ScannerKind>,
}

impl HostFindings {
    pub fn from_device(device: &Device) -> Self {
        let mut findings = Self {
            ip: device.ip,
            network_zone: device.network_zone.clone(),
            mac: device.mac.clone(),
            hostname: device.hostname.clone(),
            vendor: device.vendor.clone(),
            is_gateway: device.is_gateway,
            open_ports: Vec::new(),
            http_title: device.http_title.clone(),
            http_server: device.http_server.clone(),
            http_bodies: Vec::new(),
            http_endpoints: BTreeMap::new(),
            attributes: device.attributes.clone(),
            completed_scanners: BTreeSet::new(),
        };
        for &p in &device.open_ports {
            findings.add_port(p);
        }
        findings
    }

    pub fn add_port(&mut self, port: u16) {
        if !self.open_ports.contains(&port) {
            self.open_ports.push(port);
            self.open_ports.sort_unstable();
        }
    }

    pub fn has_completed(&self, scanner: ScannerKind) -> bool {
        self.completed_scanners.contains(&scanner)
    }

    /// Materializes a base `Device` preserving discovered network metadata.
    pub fn to_base_device(&self) -> Device {
        let mut dev = Device::new(self.ip, &self.network_zone);
        dev.mac = self.mac.clone();
        dev.hostname = self.hostname.clone();
        if let Some(h) = &self.hostname {
            dev.device_name = h.clone();
        }
        dev.vendor = self.vendor.clone();
        dev.open_ports = self.open_ports.clone();
        dev.http_title = self.http_title.clone();
        dev.http_server = self.http_server.clone();
        dev.is_gateway = self.is_gateway;
        dev.attributes = self.attributes.clone();
        dev
    }
}
