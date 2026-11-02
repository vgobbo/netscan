use crate::fingerprint::cast::GoogleCastInfo;
use crate::fingerprint::homewizard::HomeWizardInfo;
use crate::fingerprint::http::HttpFingerprint;
use crate::model::{Device, DeviceType};

pub struct RuleEngine;

impl RuleEngine {
    /// Applies dynamic, non-destructive classification heuristics to deduce the device type,
    /// friendly device name, hardware model, and operational notes.
    ///
    /// This implementation strictly avoids hardcoding static IP addresses, ensuring
    /// the scanner runs accurately across any network topology.
    pub fn classify(
        device: &mut Device,
        http_fp: &HttpFingerprint,
        cast_info: Option<&GoogleCastInfo>,
        hw_info: Option<&HomeWizardInfo>,
    ) {
        let hostname = device.hostname.clone().unwrap_or_default().to_lowercase();
        let vendor = device.vendor.clone().unwrap_or_default().to_lowercase();
        let ports = &device.open_ports;

        // 1. Google Cast Devices (Chromecast, Google TV, Nest Audio, Google Home)
        if let Some(cast) = cast_info {
            device.device_name = cast.name.clone();
            device.device_type = DeviceType::Entertainment;
            let name_lower = cast.name.to_lowercase();
            if name_lower.contains("tv") || name_lower.contains("streamer") {
                device.model = Some("Google TV / Chromecast Streaming Device".to_string());
                device.notes = Some("Media streaming device with Cast protocol".to_string());
            } else if name_lower.contains("speaker")
                || name_lower.contains("audio")
                || hostname.contains("nest")
            {
                device.model = Some("Google Nest / Home Smart Speaker".to_string());
                device.notes = Some("Voice assistant and multiroom audio speaker".to_string());
            } else {
                device.model = Some("Google Cast Device".to_string());
                device.notes = Some("Cast-enabled multimedia receiver".to_string());
            }
            return;
        }

        // 2. HomeWizard Smart Energy Devices (P1 meter, Wi-Fi Energy Sockets)
        if let Some(hw) = hw_info {
            device.device_type = DeviceType::EnergySolar;
            device.model = Some(format!(
                "HomeWizard {} ({})",
                hw.product_name, hw.product_type
            ));
            if hw.product_type.contains("P1") {
                device.device_name = "HomeWizard P1 Meter".to_string();
                device.notes = Some("Connected to utility smart meter P1 interface".to_string());
            } else {
                device.device_name = format!("HomeWizard {}", hw.product_name);
                device.notes = Some("Smart power plug with energy metering".to_string());
            }
            return;
        }

        // 3. Ubiquiti / UniFi Network Gear & Surveillance
        if http_fp.unifi_model.is_some()
            || vendor.contains("ubiquiti")
            || hostname.contains("unifi")
        {
            if let Some(model) = &http_fp.unifi_model {
                device.device_type = DeviceType::Router;
                device.device_name = format!("UniFi {}", model);
                device.model = Some(format!("Ubiquiti {}", model));
                device.notes = Some("Security gateway and network controller".to_string());
                return;
            }
            if hostname.contains("doorbell") {
                device.device_type = DeviceType::Surveillance;
                device.device_name = "UniFi Protect Doorbell".to_string();
                device.model = Some("Ubiquiti UniFi Protect Doorbell".to_string());
                device.notes = Some("Smart video doorbell and intercom".to_string());
                return;
            }
            if hostname.contains("chime")
                || hostname.contains("up-chime")
                || hostname.contains("espressif")
                || (!device.is_gateway && !ports.contains(&443) && ports.contains(&8080))
            {
                device.device_type = DeviceType::Surveillance;
                device.device_name = "UniFi Protect Smart Chime".to_string();
                device.model = Some("Ubiquiti UP-Chime".to_string());
                device.notes = Some("Wireless smart indoor chime".to_string());
                return;
            }
            if device.is_gateway || ports.contains(&443) || ports.contains(&8443) {
                device.device_type = DeviceType::Router;
                device.device_name = "UniFi Gateway / Controller".to_string();
                device.model = Some("Ubiquiti UniFi Routing Hardware".to_string());
                device.notes = Some("Primary security gateway, router, and controller".to_string());
                return;
            }
        }

        // 4. Zyxel or ISP CPE / Modems
        if http_fp.is_zyxel || vendor.contains("zyxel") || hostname.contains("zyxel") {
            device.device_type = DeviceType::Router;
            device.device_name = "Zyxel ISP Gateway / Modem".to_string();
            device.model = Some("Zyxel VMG/EX Series Broadband Gateway".to_string());
            device.notes = Some("Broadband modem and optical network gateway".to_string());
            return;
        }

        // 5. ASUS Networking Hardware (AiMesh Master / AP / Satellite Nodes)
        if let Some(asus_mode) = &http_fp.asus_mode {
            device.device_type = DeviceType::AccessPoint;
            if asus_mode.contains("Master") {
                device.device_name = "ASUS Wireless Access Point / Master AP".to_string();
                device.model = Some("ASUS RT Series Wi-Fi 6 AP".to_string());
                device.notes = Some("Operating in AP mode; AiMesh master controller".to_string());
            } else {
                device.device_name = "ASUS AiMesh Satellite Node".to_string();
                device.model = Some("ASUS Wi-Fi 6 Mesh Node".to_string());
                device.notes = Some("Wireless mesh node extending property coverage".to_string());
            }
            return;
        }
        if hostname.contains("rt-ax") || hostname.contains("aimesh") {
            device.device_type = DeviceType::AccessPoint;
            device.device_name = "ASUS Wireless Access Point".to_string();
            device.model = Some("ASUS Wi-Fi 6 AP / Mesh Node".to_string());
            device.notes = Some("Wireless access point or mesh satellite".to_string());
            return;
        }

        // 6. Network Switches (Netgear, Cisco, TP-Link, etc.)
        if hostname.contains("gs305")
            || (vendor.contains("netgear") && (hostname.contains("switch") || ports.contains(&80)))
        {
            device.device_type = DeviceType::Switch;
            device.device_name = "Netgear Managed Switch".to_string();
            device.model = Some("Netgear Smart Managed Gigabit PoE+ Switch".to_string());
            device.notes =
                Some("Layer 2 Ethernet switch distributing wired connectivity".to_string());
            return;
        }
        if vendor.contains("cisco") && !device.is_gateway {
            device.device_type = DeviceType::Switch;
            device.device_name = "Cisco Network Switch".to_string();
            device.model = Some("Cisco Ethernet Switch".to_string());
            return;
        }

        // 7. Smart Home Hubs & Bridges (Philips Hue, X-Sense, Tuya)
        if vendor.contains("signify")
            || vendor.contains("philips")
            || hostname.contains("ecb5fa")
            || hostname.contains("hue")
        {
            device.device_type = DeviceType::SmartHomeHub;
            device.device_name = "Philips Hue Bridge".to_string();
            device.model = Some("Philips Hue Zigbee Bridge".to_string());
            device.notes =
                Some("Zigbee-to-Ethernet bridge controlling indoor lighting".to_string());
            return;
        }
        if hostname.contains("sbs50") || hostname.contains("x-sense") {
            device.device_type = DeviceType::SmartHomeHub;
            device.device_name = "X-Sense Smart Gateway".to_string();
            device.model = Some("X-Sense SBS50 Base Station".to_string());
            device.notes =
                Some("RF bridge for smoke, CO, water leak, and thermo sensors".to_string());
            return;
        }

        // 8. Solar Inverters and Energy Loggers
        if http_fp.is_mongoose_elinter
            || hostname.contains("e-linter")
            || hostname.contains("inverter")
            || hostname.contains("solar")
        {
            device.device_type = DeviceType::EnergySolar;
            device.device_name = "Solar Inverter Datalogger".to_string();
            device.model = Some("Solar PV Inverter Wi-Fi Stick".to_string());
            device.notes = Some("Solar PV telemetry and monitoring datalogger".to_string());
            return;
        }

        // 9. Smart Home Kitchen & Cleaning Appliances
        if hostname.contains("bosch")
            || hostname.contains("oven")
            || hostname.contains("dishwasher")
            || vendor.contains("bsgh")
        {
            device.device_type = DeviceType::Appliance;
            if hostname.contains("oven") || hostname.contains("hbg") {
                device.device_name = "Bosch Smart Oven".to_string();
                device.model = Some("Bosch Oven (Home Connect)".to_string());
            } else if hostname.contains("dishwasher") {
                device.device_name = "Bosch Smart Dishwasher".to_string();
                device.model = Some("Bosch Dishwasher (Home Connect)".to_string());
            } else {
                device.device_name = "Bosch Smart Home Appliance".to_string();
                device.model = Some("Bosch Home Connect Appliance".to_string());
            }
            device.notes = Some("Smart kitchen appliance integrated with Home Connect".to_string());
            return;
        }
        if hostname.contains("roomba") || vendor.contains("irobot") {
            device.device_type = DeviceType::Appliance;
            device.device_name = "iRobot Roomba Vacuum".to_string();
            device.model = Some("iRobot Roomba Robotic Vacuum".to_string());
            device.notes = Some("Automated robotic vacuum cleaner".to_string());
            return;
        }

        // 10. Multimedia, Audio & Gaming
        if let Some(model) = &http_fp.is_yamaha {
            device.device_type = DeviceType::Entertainment;
            device.device_name = "Yamaha Soundbar".to_string();
            device.model = Some(format!("Yamaha {} (MusicCast)", model));
            device.notes =
                Some("Living room TV sound projector with AirPlay and Spotify".to_string());
            return;
        }
        if hostname.contains("yamaha") || vendor.contains("yamaha") {
            device.device_type = DeviceType::Entertainment;
            device.device_name = "Yamaha Audio System".to_string();
            device.model = Some("Yamaha MusicCast Receiver / Speaker".to_string());
            return;
        }
        if hostname.contains("ps5")
            || hostname.contains("playstation")
            || vendor.contains("sony interactive")
            || (vendor.contains("sony") && ports.contains(&9295))
        {
            device.device_type = DeviceType::Entertainment;
            device.device_name = "Sony PlayStation 5".to_string();
            device.model = Some("Sony PlayStation 5".to_string());
            device.notes = Some("Gaming console and multimedia entertainment station".to_string());
            return;
        }

        // 11. Servers, Workstations & Single Board Computers
        if hostname.contains("rpi") || vendor.contains("raspberry") {
            device.device_type = DeviceType::Server;
            device.device_name = "Raspberry Pi Server".to_string();
            device.model = Some("Raspberry Pi Single Board Computer".to_string());
            device.notes = Some("Local Linux server host".to_string());
            return;
        }
        if http_fp.is_prometheus && ports.contains(&22) {
            device.device_type = DeviceType::Server;
            device.device_name = "Linux Host (Prometheus Node Exporter)".to_string();
            device.notes = Some("Server host with SSH and node telemetry exporter".to_string());
            return;
        }
        if vendor.contains("apple")
            || hostname.contains("mac")
            || hostname.contains("iphone")
            || hostname.contains("ipad")
        {
            if hostname.contains("iphone") {
                device.device_type = DeviceType::Mobile;
                device.device_name = "Apple iPhone".to_string();
                device.model = Some("Apple iPhone (iOS)".to_string());
                return;
            }
            if hostname.contains("ipad") {
                device.device_type = DeviceType::Mobile;
                device.device_name = "Apple iPad".to_string();
                device.model = Some("Apple iPad (iPadOS)".to_string());
                return;
            }
            device.device_type = DeviceType::Workstation;
            device.device_name = "Apple Mac".to_string();
            device.model = Some("Apple Mac (macOS Workstation)".to_string());
            device.notes = Some("Workstation computer connected to LAN".to_string());
            return;
        }
        if hostname.contains("pixel") || hostname.contains("android") {
            device.device_type = DeviceType::Mobile;
            device.device_name = "Android Smartphone".to_string();
            device.model = Some("Android Mobile Device".to_string());
            device.notes = Some("Personal mobile smartphone connected via Wi-Fi".to_string());
            return;
        }
        if ports.contains(&22) && !hostname.is_empty() && hostname != device.ip.to_string() {
            device.device_type = DeviceType::Workstation;
            device.device_name = format!("Workstation ({})", device.hostname.as_deref().unwrap());
            device.notes = Some("Linux / Unix workstation with active SSH service".to_string());
            return;
        }

        // 12. Generic Gateway / Router Fallback
        if device.is_gateway {
            device.device_type = DeviceType::Router;
            let vendor_title = device.vendor.as_deref().unwrap_or("Network");
            device.device_name = format!("{} Gateway / Router", vendor_title);
            device.notes = Some("Default gateway routing traffic for the subnet".to_string());
            return;
        }

        // 13. Dynamic Fallback for Unclassified Hosts
        if let Some(title) = &device.http_title {
            if !title.is_empty() && title.len() < 40 {
                device.device_name = title.clone();
            }
        } else if !hostname.is_empty() && hostname != device.ip.to_string() {
            device.device_name = hostname.clone();
        } else if let Some(v) = &device.vendor {
            device.device_name = format!("{} Device", v);
        }
    }
}
