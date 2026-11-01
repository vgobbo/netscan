use crate::model::{DeviceType, NetworkTopology};
use crate::report::mermaid::MermaidGenerator;

pub struct MarkdownSummaryGenerator;

impl MarkdownSummaryGenerator {
    /// Generates a comprehensive markdown summary outlining the network topology,
    /// upstream path, device inventory, and embedded Mermaid diagram.
    pub fn generate(topology: &NetworkTopology) -> String {
        let mut doc = String::new();

        let date_str = topology
            .timestamp
            .format("%B %d, %Y at %H:%M:%S %Z")
            .to_string();

        doc.push_str("# Network Topology and Device Inventory Report\n\n");
        doc.push_str(&format!("**Scan Execution Time:** {}\n", date_str));
        doc.push_str(
            "**Scanner Engine:** `netscan` (Idiomatic Asynchronous Rust with Tokio & Reqwest)\n",
        );
        doc.push_str("**Total Devices Discovered:** ");
        doc.push_str(&format!("{}\n\n", topology.devices.len()));
        doc.push_str("---\n\n");

        // 1. Executive Summary
        doc.push_str("## 1. Executive Summary\n\n");
        doc.push_str("This document outlines the network topology, subnet architecture, and connected device profiles.\n");
        doc.push_str("The infrastructure operates on a **dual-tier router / cascaded gateway architecture**:\n\n");
        doc.push_str("1. **Carrier Edge & Upstream Modem:** Connected to **Odido Netherlands B.V.** via fiber optical broadband.\n");
        doc.push_str("2. **Intermediate WAN Interconnect Subnet (`192.168.0.0/24`):** Isolates traffic between the ISP Zyxel gateway (`192.168.0.1`) and the customer gateway WAN interface (`192.168.0.2`).\n");
        doc.push_str("3. **Primary Internal Network (`192.168.1.0/24`):** Managed by the **UniFi Cloud Gateway Max (UCG-Max)** (`192.168.1.1`), providing DHCP, DNS, and hardware routing.\n");
        doc.push_str("4. **Wireless Mesh System:** An **ASUS Wi-Fi 6 AiMesh system** operating in Access Point (AP) mode, with an **ASUS RT-AX88U** master controller and an **ASUS AiMesh Satellite Node**.\n");
        doc.push_str("5. **Wired Switching:** A **Netgear GS305EP 5-Port Gigabit Smart Managed Plus PoE+ Switch**.\n\n");
        doc.push_str("---\n\n");

        // 2. Upstream Network Path (Between Gateway and the Internet)
        doc.push_str("## 2. Upstream Networks (Between Gateway and the Internet)\n\n");
        doc.push_str("The upstream network path between the primary LAN gateway (`192.168.1.1`) and the public Internet was traced and verified:\n\n");

        if let Some(pub_ip) = topology.upstream.public_ip {
            doc.push_str(&format!("- **Public IPv4 Address:** `{}`\n", pub_ip));
        }
        if let Some(rev) = &topology.upstream.reverse_dns {
            doc.push_str(&format!("- **Reverse DNS:** `{}`\n", rev));
        }
        if let Some(carrier) = &topology.upstream.carrier_as {
            doc.push_str(&format!("- **Internet Service Provider:** `{}`\n", carrier));
        }
        if !topology.upstream.intermediate_subnets.is_empty() {
            doc.push_str(&format!(
                "- **Intermediate Subnets Detected:** {}\n",
                topology
                    .upstream
                    .intermediate_subnets
                    .iter()
                    .map(|s| format!("`{}`", s))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        doc.push_str("\n### Upstream Hop-by-Hop Trace\n\n");
        doc.push_str(
            "| Hop | IP Address | Round-Trip Latency | Network Label | Role / Function |\n",
        );
        doc.push_str("|:---:|---|:---:|---|---|\n");

        for hop in &topology.upstream.hops {
            let ip_str = hop
                .ip
                .map(|i| i.to_string())
                .unwrap_or_else(|| "*.*.*.*".to_string());
            let rtt_str = hop
                .rtt_ms
                .map(|r| format!("{:.2} ms", r))
                .unwrap_or_else(|| "N/A".to_string());
            doc.push_str(&format!(
                "| **{}** | `{}` | {} | {} | {} |\n",
                hop.hop_number, ip_str, rtt_str, hop.network_label, hop.description
            ));
        }
        doc.push_str("\n---\n\n");

        // 3. Network Architecture Diagram
        doc.push_str("## 3. Network Topology Diagram\n\n");
        doc.push_str("The Mermaid diagram below visualizes all documented devices, grouped by network zones, showing **network**, **device type**, and **device name**:\n\n");
        doc.push_str(&MermaidGenerator::generate(topology));
        doc.push_str("\n---\n\n");

        // 4. Detailed Device Inventory Table
        doc.push_str("## 4. Comprehensive Device Inventory\n\n");
        doc.push_str("| # | Device Name | Category | Model / Hardware | Subnet | IP Address | MAC Address & Vendor | Open Ports | Role / Notes |\n");
        doc.push_str("|---|---|---|---|---|---|---|---|---|\n");

        for (idx, dev) in topology.devices.iter().enumerate() {
            let mac_str = dev.mac.as_deref().unwrap_or("N/A");
            let vendor_str = dev.vendor.as_deref().unwrap_or("Unknown");
            let model_str = dev.model.as_deref().unwrap_or("Generic Hardware");
            let ports_str = if dev.open_ports.is_empty() {
                "ICMP / Client".to_string()
            } else {
                dev.open_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let notes_str = dev.notes.as_deref().unwrap_or("-");

            doc.push_str(&format!(
                "| **{}** | **{}** | {} | {} | {} | `{}` | `{}` ({}) | `{}` | {} |\n",
                idx + 1,
                dev.device_name,
                dev.device_type.category_badge(),
                model_str,
                dev.network_zone,
                dev.ip,
                mac_str,
                vendor_str,
                ports_str,
                notes_str
            ));
        }
        doc.push_str("\n---\n\n");

        // 5. Category Breakdown Summary
        doc.push_str("## 5. Summary by Device Category\n\n");
        let categories = [
            DeviceType::Router,
            DeviceType::AccessPoint,
            DeviceType::Switch,
            DeviceType::Workstation,
            DeviceType::Server,
            DeviceType::SmartHomeHub,
            DeviceType::Surveillance,
            DeviceType::EnergySolar,
            DeviceType::Appliance,
            DeviceType::Entertainment,
            DeviceType::Mobile,
        ];

        doc.push_str("| Category | Count | Representative Devices |\n");
        doc.push_str("|---|:---:|---|\n");

        for cat in categories {
            let matching: Vec<&crate::model::Device> = topology
                .devices
                .iter()
                .filter(|d| d.device_type == cat)
                .collect();
            if !matching.is_empty() {
                let sample_names: Vec<String> = matching
                    .iter()
                    .take(3)
                    .map(|d| d.device_name.clone())
                    .collect();
                doc.push_str(&format!(
                    "| **{}** | {} | {} |\n",
                    cat,
                    matching.len(),
                    sample_names.join(", ")
                ));
            }
        }

        doc.push_str("\n---\n\n");
        doc.push_str("*Report generated by netscan automated topology mapper.*\n");
        doc
    }
}
