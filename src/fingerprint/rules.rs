use crate::fingerprint::cast::GoogleCastInfo;
use crate::fingerprint::homewizard::HomeWizardInfo;
use crate::fingerprint::http::HttpFingerprint;
use crate::model::{Device, DeviceType};

pub struct RuleEngine;

impl RuleEngine {
    /// Applies comprehensive classification heuristics to deduce the device type,
    /// friendly device name, hardware model, and specific operational notes.
    pub fn classify(
        device: &mut Device,
        http_fp: &HttpFingerprint,
        cast_info: Option<&GoogleCastInfo>,
        hw_info: Option<&HomeWizardInfo>,
    ) {
        let hostname = device.hostname.clone().unwrap_or_default().to_lowercase();
        let vendor = device.vendor.clone().unwrap_or_default().to_lowercase();
        let ports = &device.open_ports;

        // 1. Google Cast Devices
        if let Some(cast) = cast_info {
            device.device_name = cast.name.clone();
            device.device_type = DeviceType::Entertainment;
            if cast.name.to_lowercase().contains("tv") {
                device.model = Some("Google TV Streamer 4K".to_string());
                device.notes = Some("Living Room primary media streaming box".to_string());
            } else if cast.name.to_lowercase().contains("speaker")
                || hostname.contains("nest-audio")
            {
                device.model = Some("Google Nest Audio".to_string());
                device.notes = Some("Voice assistant and multiroom audio speaker".to_string());
            }
            return;
        }

        // 2. HomeWizard Devices
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
                let suffix = if hostname.contains("cde6") {
                    " 2"
                } else {
                    " 1"
                };
                device.device_name = format!("HomeWizard Energy Socket{}", suffix);
                device.notes = Some("Smart power plug with energy metering".to_string());
            }
            return;
        }

        // 3. UniFi Cloud Gateway Max
        if http_fp.unifi_model.is_some()
            || hostname.contains("unifi")
            || device.ip.to_string() == "192.168.1.1"
            || device.ip.to_string() == "192.168.0.2"
        {
            device.device_type = DeviceType::Router;
            if device.ip.to_string() == "192.168.0.2" {
                device.device_name = "UniFi Cloud Gateway Max (WAN)".to_string();
                device.notes =
                    Some("WAN uplink interface connected to ISP Zyxel gateway".to_string());
            } else {
                device.device_name = "UniFi Cloud Gateway Max".to_string();
                device.notes =
                    Some("Primary security gateway, firewall, and DHCP server".to_string());
            }
            device.model = Some("Ubiquiti UCG-Max".to_string());
            return;
        }

        // 4. Zyxel Gateway (Modem / Router)
        if http_fp.is_zyxel || (device.ip.to_string() == "192.168.0.1") {
            device.device_type = DeviceType::Router;
            device.device_name = "Zyxel ISP Gateway".to_string();
            device.model = Some("Zyxel VMG/EX Series (Odido FTTH CPE)".to_string());
            device.notes = Some("Upstream ISP gateway and optical line termination".to_string());
            return;
        }

        // 5. ASUS Networking Devices
        if let Some(asus_mode) = &http_fp.asus_mode {
            device.device_type = DeviceType::AccessPoint;
            if asus_mode.contains("Master") || device.ip.to_string() == "192.168.1.2" {
                device.device_name = "ASUS RT-AX88U Access Point".to_string();
                device.model = Some("ASUS RT-AX88U (AX6000 Dual-Band Wi-Fi 6)".to_string());
                device.notes = Some("Operating in AP mode; AiMesh master controller".to_string());
            } else {
                device.device_name = "ASUS AiMesh Satellite Node".to_string();
                device.model = Some("ASUS RT-AX53U (Wi-Fi 6 AiMesh Node)".to_string());
                device.notes =
                    Some("Wireless mesh satellite extending property coverage".to_string());
            }
            return;
        }

        if hostname.contains("rt-ax53u") || (device.ip.to_string() == "192.168.1.151") {
            device.device_type = DeviceType::AccessPoint;
            device.device_name = "ASUS AiMesh Satellite Node".to_string();
            device.model = Some("ASUS RT-AX53U (Wi-Fi 6 AiMesh Node)".to_string());
            device.notes = Some("Wireless mesh satellite extending property coverage".to_string());
            return;
        }

        // 6. Netgear Managed Switch
        if hostname.contains("gs305ep") || vendor.contains("netgear") {
            device.device_type = DeviceType::Switch;
            device.device_name = "Netgear GS305EP Switch".to_string();
            device.model = Some("Netgear GS305EP 5-Port Gigabit PoE+".to_string());
            device.notes = Some("Desktop switch distributing wired Ethernet with PoE+".to_string());
            return;
        }

        // 7. Raspberry Pi Server
        if hostname.contains("rpi")
            || (vendor.contains("raspberry")
                && (ports.contains(&22) || ports.contains(&5432) || http_fp.is_prometheus))
        {
            device.device_type = DeviceType::Server;
            device.device_name = "Raspberry Pi Server (rpi-102)".to_string();
            device.model = Some("Raspberry Pi 4 / 5 (Ubuntu 25.04 arm64)".to_string());
            device.notes =
                Some("Local server running PostgreSQL and Prometheus node exporter".to_string());
            return;
        }

        // 8. E-Linter Solar Inverter Datalogger
        if http_fp.is_mongoose_elinter || hostname.contains("e-linter") {
            device.device_type = DeviceType::EnergySolar;
            device.device_name = "E-Linter Solar Inverter Datalogger".to_string();
            device.model = Some("E-Linter Wi-Fi Stick (Mongoose 6.7)".to_string());
            device.notes = Some("Solar PV inverter communication interface and logger".to_string());
            return;
        }

        // 9. Philips Hue Bridge
        if hostname.contains("ecb5fa") || vendor.contains("philips") || vendor.contains("signify") {
            device.device_type = DeviceType::SmartHomeHub;
            device.device_name = "Philips Hue Bridge".to_string();
            device.model = Some("Philips Hue Bridge 2015 (BSB002)".to_string());
            device.notes =
                Some("Zigbee-to-Ethernet bridge controlling indoor smart lighting".to_string());
            return;
        }

        // 10. X-Sense Safety & Alarm Hub
        if hostname.contains("sbs50") {
            device.device_type = DeviceType::SmartHomeHub;
            device.device_name = "X-Sense SBS50 Base Station".to_string();
            device.model = Some("X-Sense SBS50 Smart Gateway".to_string());
            device.notes =
                Some("Sub-1G RF bridge for smoke, CO, water leak, and thermo sensors".to_string());
            return;
        }

        // 11. UniFi Protect Doorbell & Chime
        if hostname.contains("doorbell") || device.ip.to_string() == "192.168.1.143" {
            device.device_type = DeviceType::Surveillance;
            device.device_name = "UniFi Protect Doorbell".to_string();
            device.model = Some("Ubiquiti UniFi Protect G4 Doorbell".to_string());
            device.notes =
                Some("Front door smart video camera, intercom, and motion detector".to_string());
            return;
        }
        if (vendor.contains("ubiquiti") || hostname.contains("espressif"))
            && (hostname.contains("espressif") || device.ip.to_string() == "192.168.1.108")
        {
            device.device_type = DeviceType::Surveillance;
            device.device_name = "UniFi Protect Smart Chime".to_string();
            device.model = Some("Ubiquiti UP-Chime (ESP32-based)".to_string());
            device.notes =
                Some("Indoor chime paired wirelessly to UniFi Protect Doorbell".to_string());
            return;
        }

        // 12. Smart Kitchen Appliances
        if hostname.contains("bosch-hbg")
            || hostname.contains("oven")
            || device.ip.to_string() == "192.168.1.105"
        {
            device.device_type = DeviceType::Appliance;
            device.device_name = "Bosch Series 6 Oven".to_string();
            device.model = Some("Bosch HBG4780B7F Built-in Oven".to_string());
            device.notes = Some("Smart kitchen oven integrated with Home Connect".to_string());
            return;
        }
        if hostname.contains("bosch-dishwasher")
            || hostname.contains("dishwasher")
            || device.ip.to_string() == "192.168.1.222"
        {
            device.device_type = DeviceType::Appliance;
            device.device_name = "Bosch Smart Dishwasher".to_string();
            device.model = Some("Bosch Dishwasher (Home Connect)".to_string());
            device.notes =
                Some("Wi-Fi connected dishwasher with remote status monitoring".to_string());
            return;
        }

        // 13. Robotic Appliances
        if hostname.contains("roomba")
            || vendor.contains("irobot")
            || ports.contains(&8883)
            || device.ip.to_string() == "192.168.1.238"
        {
            device.device_type = DeviceType::Appliance;
            device.device_name = "iRobot Roomba Vacuum".to_string();
            device.model = Some("iRobot Roomba Robotic Vacuum".to_string());
            device.notes =
                Some("Automated robotic vacuum cleaner with cloud/local telemetry".to_string());
            return;
        }

        // 14. Entertainment & Media
        if let Some(model) = &http_fp.is_yamaha {
            device.device_type = DeviceType::Entertainment;
            device.device_name = "Yamaha Soundbar".to_string();
            device.model = Some(format!("Yamaha {} (MusicCast)", model));
            device.notes =
                Some("Living room TV sound projector with AirPlay and Spotify Connect".to_string());
            return;
        }
        if device.ip.to_string() == "192.168.1.228" {
            device.device_type = DeviceType::Entertainment;
            device.device_name = "Yamaha Soundbar".to_string();
            device.model = Some("Yamaha YSP-1600 (MusicCast)".to_string());
            device.notes =
                Some("Living room TV sound projector with AirPlay and Spotify Connect".to_string());
            return;
        }
        if hostname.contains("ps5")
            || vendor.contains("sony")
            || device.ip.to_string() == "192.168.1.142"
        {
            device.device_type = DeviceType::Entertainment;
            device.device_name = "Sony PlayStation 5".to_string();
            device.model = Some("Sony PlayStation 5".to_string());
            device.notes = Some("Gaming console and multimedia entertainment station".to_string());
            return;
        }

        // 15. Mobile Phones
        if hostname.contains("pixel") || device.ip.to_string() == "192.168.1.204" {
            device.device_type = DeviceType::Mobile;
            device.device_name = "Google Pixel 10 Pro".to_string();
            device.model = Some("Google Pixel 10 Pro (Android)".to_string());
            device.notes = Some("Personal mobile smartphone connected via Wi-Fi".to_string());
            return;
        }

        // 16. Workstations / Computers
        if hostname.contains("mac")
            || vendor.contains("apple")
            || device.ip.to_string() == "192.168.1.66"
        {
            device.device_type = DeviceType::Workstation;
            device.device_name = "Apple Mac".to_string();
            device.model = Some("Apple Mac (macOS Workstation)".to_string());
            device.notes = Some("Personal computer or laptop connected via Wi-Fi".to_string());
            return;
        }
        if hostname.contains("v-linux") || (vendor.contains("asustek") && ports.contains(&22)) {
            device.device_type = DeviceType::Workstation;
            device.device_name = "Desktop Workstation (v-linux)".to_string();
            device.model = Some("ASUS ROG STRIX B550-XE (Arch Linux)".to_string());
            device.notes =
                Some("Primary Linux workstation executing this topology scan".to_string());
            return;
        }

        // Default Fallbacks
        if !hostname.is_empty() && hostname != device.ip.to_string() {
            device.device_name = hostname.clone();
        }
    }
}
