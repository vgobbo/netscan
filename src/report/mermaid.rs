use crate::model::{Device, DeviceType, NetworkTopology};
use std::collections::BTreeMap;

pub struct MermaidGenerator;

impl MermaidGenerator {
    /// Generates a Mermaid flowchart diagram mapping the network architecture.
    /// Strictly displays: network zones, device type, and device name.
    /// Strictly omits: IP addresses and MAC addresses.
    pub fn generate(topology: &NetworkTopology) -> String {
        let mut out = String::new();
        out.push_str("```mermaid\n");
        out.push_str("flowchart TD\n");

        // 1. Upstream Carrier & Internet Zone
        out.push_str("    %% Public Internet & Carrier Transit Zone\n");
        out.push_str("    subgraph WAN_Zone [\"Public Internet & Carrier Network\"]\n");
        out.push_str("        Internet[\"Public Internet\"]\n");
        out.push_str("        ISPCore[\"Odido Carrier Core & CGNAT Transit\"]\n");
        out.push_str("        ISPBng[\"Odido FTTH Broadband Gateway\"]\n");
        out.push_str("    end\n\n");

        // 2. Intermediate WAN Interconnect Subnet (Between Gateway and Internet)
        out.push_str("    %% Intermediate WAN Interconnect Subnet (Between Gateway & Internet)\n");
        out.push_str(
            "    subgraph Interconnect_Zone [\"WAN Interconnect Network (192.168.0.0/24)\"]\n",
        );
        out.push_str("        ZyxelModem[\"ISP Modem / Router (Zyxel Gateway)\"]\n");
        out.push_str("    end\n\n");

        // 3. Core Routing Gateway
        out.push_str("    %% Primary Gateway & Firewall\n");
        out.push_str("    subgraph Core_Routing [\"Security & Routing\"]\n");
        out.push_str(
            "        UniFiGateway[\"Security Gateway & Controller (UniFi Cloud Gateway Max)\"]\n",
        );
        out.push_str("    end\n\n");

        // 4. Distribution Infrastructure (Switches & APs)
        out.push_str("    %% Distribution Infrastructure\n");
        out.push_str("    subgraph Infra_Zone [\"Network Infrastructure\"]\n");
        out.push_str("        PoESwitch[\"Managed PoE+ Switch (Netgear GS305EP)\"]\n");
        out.push_str("        AsusAP[\"Wi-Fi 6 Master AP (ASUS RT-AX88U)\"]\n");
        out.push_str("        AsusNode[\"Wi-Fi Mesh Satellite (ASUS AiMesh Node)\"]\n");
        out.push_str("    end\n\n");

        // Helper: Check if device is one of the core infrastructure elements
        let is_core_infra = |dev: &Device| -> bool {
            let ip_str = dev.ip.to_string();
            ip_str == "192.168.0.1"
                || ip_str == "192.168.0.2"
                || ip_str == "192.168.1.1"
                || ip_str == "192.168.1.2"
                || ip_str == "192.168.1.151"
                || ip_str == "192.168.1.178"
                || dev.device_type == DeviceType::Router
                || dev.device_type == DeviceType::Switch
                || (dev.device_type == DeviceType::AccessPoint
                    && (dev.device_name.contains("RT-AX") || dev.device_name.contains("AiMesh")))
        };

        // 5. Group client devices by Subgraph Name
        let mut grouped: BTreeMap<&'static str, Vec<&Device>> = BTreeMap::new();
        for dev in &topology.devices {
            if is_core_infra(dev) {
                continue;
            }
            grouped
                .entry(dev.device_type.subgraph_name())
                .or_default()
                .push(dev);
        }

        for (subgraph_header, devs) in grouped {
            out.push_str(&format!("    subgraph {}\n", subgraph_header));
            for dev in devs {
                let node_id = dev.node_id();
                let label = dev.mermaid_label();
                out.push_str(&format!("        {}[\"{}\"]\n", node_id, label));
            }
            out.push_str("    end\n\n");
        }

        // 6. Logical Link Relationships
        out.push_str("    %% Upstream Routing Connections\n");
        out.push_str("    Internet --> ISPCore\n");
        out.push_str("    ISPCore --> ISPBng\n");
        out.push_str("    ISPBng --> ZyxelModem\n");
        out.push_str("    ZyxelModem --> UniFiGateway\n\n");

        out.push_str("    %% LAN Infrastructure Distribution\n");
        out.push_str("    UniFiGateway --> PoESwitch\n");
        out.push_str("    UniFiGateway --> AsusAP\n");
        out.push_str("    AsusAP -. Wireless Mesh Link .- AsusNode\n\n");

        out.push_str("    %% Client Associations\n");
        for dev in &topology.devices {
            if is_core_infra(dev) {
                continue;
            }

            let node_id = dev.node_id();
            // Wired devices connect to PoE Switch, wireless to AsusAP
            if dev.device_name.contains("v-linux")
                || dev.device_name.contains("rpi-102")
                || dev.device_name.contains("Hue Bridge")
            {
                out.push_str(&format!("    PoESwitch --> {}\n", node_id));
            } else {
                out.push_str(&format!("    AsusAP --> {}\n", node_id));
            }
        }

        out.push_str("```\n");
        out
    }
}
