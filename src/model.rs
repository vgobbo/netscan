use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

/// Categorization of discovered devices for topology visualization and reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DeviceType {
    Router,
    AccessPoint,
    Switch,
    Workstation,
    Server,
    SmartHomeHub,
    Surveillance,
    EnergySolar,
    Appliance,
    Entertainment,
    Mobile,
    Unknown,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Router => write!(f, "Router / Gateway"),
            Self::AccessPoint => write!(f, "Wireless Access Point"),
            Self::Switch => write!(f, "Network Switch"),
            Self::Workstation => write!(f, "Workstation / PC"),
            Self::Server => write!(f, "Server / Host"),
            Self::SmartHomeHub => write!(f, "Smart Home Hub"),
            Self::Surveillance => write!(f, "Surveillance / Camera"),
            Self::EnergySolar => write!(f, "Smart Energy / Solar"),
            Self::Appliance => write!(f, "Smart Appliance"),
            Self::Entertainment => write!(f, "Audio / Entertainment"),
            Self::Mobile => write!(f, "Mobile Device"),
            Self::Unknown => write!(f, "Generic Device"),
        }
    }
}

impl DeviceType {
    /// Returns the Mermaid subgraph name grouping this device type.
    pub fn subgraph_name(&self) -> &'static str {
        match self {
            Self::Router => "Core_Routing [\"Security & Routing\"]",
            Self::AccessPoint | Self::Switch => "Infra_Zone [\"Network Infrastructure\"]",
            Self::Workstation | Self::Server => "Workstations_Zone [\"Computers & Servers\"]",
            Self::SmartHomeHub => "SmartHome_Hubs [\"Smart Home Hubs & Gateways\"]",
            Self::Surveillance => "Security_Zone [\"Surveillance & Security\"]",
            Self::EnergySolar => "Energy_Solar [\"Smart Energy & Solar Monitoring\"]",
            Self::Appliance => "Appliances_Zone [\"Smart Home Appliances\"]",
            Self::Entertainment => "Media_Zone [\"Audio & Entertainment\"]",
            Self::Mobile => "Mobile_Zone [\"Mobile Devices\"]",
            Self::Unknown => "Other_Devices [\"Connected Devices\"]",
        }
    }

    /// Returns a short human-readable category badge.
    pub fn category_badge(&self) -> &'static str {
        match self {
            Self::Router => "Router",
            Self::AccessPoint => "Wi-Fi AP",
            Self::Switch => "Switch",
            Self::Workstation => "Workstation",
            Self::Server => "Server",
            Self::SmartHomeHub => "Smart Hub",
            Self::Surveillance => "Surveillance",
            Self::EnergySolar => "Energy/Solar",
            Self::Appliance => "Appliance",
            Self::Entertainment => "Entertainment",
            Self::Mobile => "Mobile",
            Self::Unknown => "Device",
        }
    }
}

/// A discovered and fingerprinted network device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub device_name: String,
    pub device_type: DeviceType,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub network_zone: String,
    pub open_ports: Vec<u16>,
    pub http_title: Option<String>,
    pub http_server: Option<String>,
    pub notes: Option<String>,
    pub is_gateway: bool,
    pub attributes: BTreeMap<String, String>,
}

impl Device {
    pub fn new(ip: IpAddr, network_zone: impl Into<String>) -> Self {
        Self {
            ip,
            mac: None,
            hostname: None,
            device_name: ip.to_string(),
            device_type: DeviceType::Unknown,
            vendor: None,
            model: None,
            network_zone: network_zone.into(),
            open_ports: Vec::new(),
            http_title: None,
            http_server: None,
            notes: None,
            is_gateway: false,
            attributes: BTreeMap::new(),
        }
    }

    /// Generates a sanitized Mermaid node identifier.
    pub fn node_id(&self) -> String {
        let clean: String = self
            .device_name
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect();
        let ip_suffix = self.ip.to_string().replace(['.', ':'], "_");
        format!("dev_{}_{}", clean, ip_suffix)
    }

    /// Generates the node label strictly conforming to user instructions:
    /// Displays device type and device name, WITHOUT IP or MAC address.
    pub fn mermaid_label(&self) -> String {
        let label = format!("{} ({})", self.device_type, self.device_name);
        // Escape quotes to prevent mermaid syntax errors
        label.replace('"', "'")
    }
}

/// A network hop between the local gateway and the Internet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamHop {
    pub hop_number: u8,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub rtt_ms: Option<f32>,
    pub is_private: bool,
    pub network_label: String,
    pub description: String,
}

/// Complete upstream path analysis to public Internet.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpstreamPath {
    pub public_ip: Option<IpAddr>,
    pub reverse_dns: Option<String>,
    pub carrier_as: Option<String>,
    pub hops: Vec<UpstreamHop>,
    pub intermediate_subnets: Vec<String>,
}

/// Aggregated network topology data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopology {
    pub timestamp: DateTime<Local>,
    pub devices: Vec<Device>,
    pub upstream: UpstreamPath,
    pub local_subnets: Vec<String>,
    pub primary_gateway: Option<IpAddr>,
}

impl NetworkTopology {
    pub fn new(local_subnets: Vec<String>) -> Self {
        Self {
            timestamp: Local::now(),
            devices: Vec::new(),
            upstream: UpstreamPath::default(),
            local_subnets,
            primary_gateway: None,
        }
    }

    /// Returns devices that act as routers or gateways.
    pub fn routers(&self) -> Vec<&Device> {
        self.devices
            .iter()
            .filter(|d| d.device_type == DeviceType::Router || d.is_gateway)
            .collect()
    }

    /// Returns devices identified as network switches.
    pub fn switches(&self) -> Vec<&Device> {
        self.devices
            .iter()
            .filter(|d| d.device_type == DeviceType::Switch)
            .collect()
    }

    /// Returns devices identified as wireless access points.
    pub fn access_points(&self) -> Vec<&Device> {
        self.devices
            .iter()
            .filter(|d| d.device_type == DeviceType::AccessPoint)
            .collect()
    }

    /// Identifies the primary local LAN gateway / router.
    pub fn primary_router(&self) -> Option<&Device> {
        if let Some(gw_ip) = self.primary_gateway
            && let Some(dev) = self.devices.iter().find(|d| d.ip == gw_ip)
        {
            return Some(dev);
        }
        self.routers().into_iter().next()
    }
}
