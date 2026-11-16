use crate::model::{Device, DeviceType, NetworkTopology};
use std::collections::{BTreeMap, HashSet};

pub struct MermaidGenerator;

impl MermaidGenerator {
    /// Generates a Mermaid flowchart diagram dynamically mapping the discovered network architecture.
    /// Strictly displays: network zones, device type, and device name.
    /// Strictly omits: IP addresses and MAC addresses.
    pub fn generate(topology: &NetworkTopology) -> String {
        let mut out = String::new();
        out.push_str("```mermaid\n");
        out.push_str("flowchart TD\n");

        let mut rendered_node_ids = HashSet::new();

        // 1. Upstream Carrier & Public Internet Zone
        let has_upstream =
            topology.upstream.public_ip.is_some() || !topology.upstream.hops.is_empty();

        if has_upstream {
            out.push_str("    %% Public Internet & Carrier Transit Zone\n");
            out.push_str("    subgraph WAN_Zone [\"Public Internet & Carrier Network\"]\n");
            out.push_str("        Internet[\"Public Internet\"]\n");
            rendered_node_ids.insert("Internet".to_string());

            // Collect public / carrier transit hops (excluding private LAN hops)
            let carrier_hops: Vec<_> = topology
                .upstream
                .hops
                .iter()
                .filter(|h| !h.is_private)
                .collect();

            for hop in &carrier_hops {
                let hop_id = format!("CarrierHop_{}", hop.hop_number);
                let label = format!("{} ({})", hop.network_label, hop.description);
                let clean_label = label.replace('"', "'");
                out.push_str(&format!("        {}[\"{}\"]\n", hop_id, clean_label));
                rendered_node_ids.insert(hop_id);
            }

            out.push_str("    end\n\n");
        }

        // 2. Intermediate / Upstream Gateway Subnet (if any intermediate subnets exist)
        let intermediate_subnets = &topology.upstream.intermediate_subnets;
        let mut intermediate_router_nodes = Vec::new();

        for (idx, subnet) in intermediate_subnets.iter().enumerate() {
            let zone_id = format!("Interconnect_Zone_{}", idx);
            out.push_str(&format!(
                "    %% Intermediate WAN Interconnect Subnet\n    subgraph {} [\"WAN Interconnect Network ({})\"]\n",
                zone_id, subnet
            ));

            // Find routers / gateways located on this intermediate subnet
            let int_devices: Vec<&Device> = topology
                .devices
                .iter()
                .filter(|d| {
                    d.network_zone == *subnet
                        && (d.device_type == DeviceType::Router || d.is_gateway)
                })
                .collect();

            if int_devices.is_empty() {
                let node_id = format!("InterRouter_{}", idx);
                out.push_str(&format!(
                    "        {}[\"Broadband Gateway / Modem (ISP Gateway)\"]\n",
                    node_id
                ));
                intermediate_router_nodes.push(node_id);
            } else {
                for dev in int_devices {
                    let node_id = dev.node_id();
                    out.push_str(&format!(
                        "        {}[\"{}\"]\n",
                        node_id,
                        dev.mermaid_label()
                    ));
                    rendered_node_ids.insert(node_id.clone());
                    intermediate_router_nodes.push(node_id);
                }
            }

            out.push_str("    end\n\n");
        }

        // 3. Core Routing Gateway (Primary LAN)
        let mut core_gateway_node = None;

        let primary_routers: Vec<&Device> = topology
            .routers()
            .into_iter()
            .filter(|d| !intermediate_subnets.contains(&d.network_zone))
            .collect();

        if !primary_routers.is_empty() {
            out.push_str("    %% Primary Gateway & Firewall\n");
            out.push_str("    subgraph Core_Routing [\"Security & Routing\"]\n");
            for r in &primary_routers {
                let node_id = r.node_id();
                out.push_str(&format!("        {}[\"{}\"]\n", node_id, r.mermaid_label()));
                rendered_node_ids.insert(node_id.clone());
                if core_gateway_node.is_none() {
                    core_gateway_node = Some(node_id);
                }
            }
            out.push_str("    end\n\n");
        } else if let Some(int_node) = intermediate_router_nodes.first() {
            core_gateway_node = Some(int_node.clone());
        }

        // 4. Distribution Infrastructure (Switches and Wireless APs)
        let switches = topology.switches();
        let access_points = topology.access_points();
        let mut infra_nodes = Vec::new();

        if !switches.is_empty() || !access_points.is_empty() {
            out.push_str("    %% Distribution Infrastructure\n");
            out.push_str("    subgraph Infra_Zone [\"Network Infrastructure\"]\n");

            for sw in &switches {
                let node_id = sw.node_id();
                if !rendered_node_ids.contains(&node_id) {
                    out.push_str(&format!(
                        "        {}[\"{}\"]\n",
                        node_id,
                        sw.mermaid_label()
                    ));
                    rendered_node_ids.insert(node_id.clone());
                    infra_nodes.push((node_id, "switch"));
                }
            }

            for ap in &access_points {
                let node_id = ap.node_id();
                if !rendered_node_ids.contains(&node_id) {
                    out.push_str(&format!(
                        "        {}[\"{}\"]\n",
                        node_id,
                        ap.mermaid_label()
                    ));
                    rendered_node_ids.insert(node_id.clone());
                    infra_nodes.push((node_id, "ap"));
                }
            }

            out.push_str("    end\n\n");
        }

        // 5. Group client devices by Subgraph Name
        let mut client_subgraphs: BTreeMap<&'static str, Vec<&Device>> = BTreeMap::new();
        for dev in &topology.devices {
            if rendered_node_ids.contains(&dev.node_id()) {
                continue;
            }
            client_subgraphs
                .entry(dev.device_type.subgraph_name())
                .or_default()
                .push(dev);
        }

        for (subgraph_header, devs) in client_subgraphs {
            out.push_str(&format!("    subgraph {}\n", subgraph_header));
            for dev in devs {
                let node_id = dev.node_id();
                let label = dev.mermaid_label();
                out.push_str(&format!("        {}[\"{}\"]\n", node_id, label));
                rendered_node_ids.insert(node_id);
            }
            out.push_str("    end\n\n");
        }

        // 6. Dynamic Logical Link Relationships
        out.push_str("    %% Logical Connections & Data Flow\n");

        let carrier_hops: Vec<_> = topology
            .upstream
            .hops
            .iter()
            .filter(|h| !h.is_private)
            .collect();

        if has_upstream {
            let mut prev = "Internet".to_string();
            for hop in &carrier_hops {
                let hop_id = format!("CarrierHop_{}", hop.hop_number);
                out.push_str(&format!("    {} --> {}\n", prev, hop_id));
                prev = hop_id;
            }

            if let Some(int_node) = intermediate_router_nodes.first() {
                out.push_str(&format!("    {} --> {}\n", prev, int_node));
            } else if let Some(gw_node) = &core_gateway_node {
                out.push_str(&format!("    {} --> {}\n", prev, gw_node));
            }
        }

        // Link intermediate routers to core gateway
        if let Some(gw_node) = &core_gateway_node {
            for int_node in &intermediate_router_nodes {
                if int_node != gw_node {
                    out.push_str(&format!("    {} --> {}\n", int_node, gw_node));
                }
            }
        }

        // Link core gateway to switches and access points
        let primary_hub = core_gateway_node.as_deref().unwrap_or("Internet");
        let first_switch = infra_nodes
            .iter()
            .find(|(_, t)| *t == "switch")
            .map(|(id, _)| id.as_str());
        let first_ap = infra_nodes
            .iter()
            .find(|(_, t)| *t == "ap")
            .map(|(id, _)| id.as_str());

        for (infra_id, _) in &infra_nodes {
            out.push_str(&format!("    {} --> {}\n", primary_hub, infra_id));
        }

        // Link client devices to appropriate network distribution anchor
        for dev in &topology.devices {
            let dev_id = dev.node_id();
            if infra_nodes.iter().any(|(id, _)| id == &dev_id)
                || core_gateway_node.as_deref() == Some(&dev_id)
                || intermediate_router_nodes.contains(&dev_id)
            {
                continue;
            }

            let target_hub = match dev.device_type {
                DeviceType::Workstation | DeviceType::Server | DeviceType::SmartHomeHub => {
                    first_switch.or(first_ap).unwrap_or(primary_hub)
                }
                DeviceType::Mobile
                | DeviceType::Climate
                | DeviceType::Appliance
                | DeviceType::EnergySolar
                | DeviceType::Entertainment
                | DeviceType::Surveillance => first_ap.or(first_switch).unwrap_or(primary_hub),
                _ => first_ap.or(first_switch).unwrap_or(primary_hub),
            };

            out.push_str(&format!("    {} --> {}\n", target_hub, dev_id));
        }

        out.push_str("```\n");
        out
    }
}
