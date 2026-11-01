use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::OnceLock;

static OUI_DATABASE: OnceLock<HashMap<String, &'static str>> = OnceLock::new();

/// Initializes static built-in OUIs for common manufacturers.
fn build_builtin_oui() -> HashMap<String, &'static str> {
    let mut m = HashMap::new();
    // Ubiquiti Networks
    m.insert("1C6A1B".to_string(), "Ubiquiti");
    m.insert("6E63F8".to_string(), "Ubiquiti");
    m.insert("245A4C".to_string(), "Ubiquiti");
    m.insert("002722".to_string(), "Ubiquiti");
    m.insert("602232".to_string(), "Ubiquiti");
    m.insert("784558".to_string(), "Ubiquiti");
    m.insert("B4FBE4".to_string(), "Ubiquiti");

    // ASUS
    m.insert("FC3497".to_string(), "ASUSTek Computer");
    m.insert("60CF84".to_string(), "ASUSTek Computer");
    m.insert("3C7C3F".to_string(), "ASUSTek Computer");
    m.insert("04D9F5".to_string(), "ASUSTek Computer");
    m.insert("107B44".to_string(), "ASUSTek Computer");
    m.insert("2C4D54".to_string(), "ASUSTek Computer");

    // Raspberry Pi
    m.insert("2CCF67".to_string(), "Raspberry Pi");
    m.insert("B827EB".to_string(), "Raspberry Pi");
    m.insert("DCA632".to_string(), "Raspberry Pi");
    m.insert("E45F01".to_string(), "Raspberry Pi");

    // HomeWizard
    m.insert("5C2FAF".to_string(), "HomeWizard");

    // Google
    m.insert("82BEC0".to_string(), "Google");
    m.insert("D88C79".to_string(), "Google");
    m.insert("3C5A37".to_string(), "Google");
    m.insert("BA0623".to_string(), "Google");
    m.insert("F4F5DB".to_string(), "Google");
    m.insert("546009".to_string(), "Google");

    // Signify / Philips
    m.insert("ECB5FA".to_string(), "Philips Lighting / Signify");
    m.insert("001788".to_string(), "Philips Lighting / Signify");

    // BSH (Bosch / Siemens)
    m.insert("68A40E".to_string(), "BSH Hausgeräte (Bosch)");
    m.insert("48264C".to_string(), "BSH Electrical (Bosch)");

    // Sony
    m.insert("9C37CB".to_string(), "Sony Interactive Entertainment");
    m.insert("F8461C".to_string(), "Sony Interactive Entertainment");
    m.insert("00D9D1".to_string(), "Sony Interactive Entertainment");

    // Netgear
    m.insert("289401".to_string(), "Netgear");
    m.insert("C40415".to_string(), "Netgear");
    m.insert("A00460".to_string(), "Netgear");

    // Espressif
    m.insert("A0A3B3".to_string(), "Espressif");
    m.insert("E83DC1".to_string(), "Espressif");
    m.insert("2462AB".to_string(), "Espressif");
    m.insert("30AEA4".to_string(), "Espressif");
    m.insert("84CCA8".to_string(), "Espressif");

    // Texas Instruments / Audio
    m.insert("C4F312".to_string(), "Texas Instruments / Audio");

    // AzureWave / iRobot
    m.insert("D0C5D3".to_string(), "AzureWave / iRobot");
    m.insert("501479".to_string(), "iRobot");

    // Apple
    m.insert("F01898".to_string(), "Apple");
    m.insert("ACBC32".to_string(), "Apple");
    m.insert("3C0630".to_string(), "Apple");
    m.insert("A483E7".to_string(), "Apple");

    // Zyxel
    m.insert("404A03".to_string(), "Zyxel Communications");
    m.insert("5C353B".to_string(), "Zyxel Communications");
    m.insert("CC5D4E".to_string(), "Zyxel Communications");

    m
}

pub struct OuiMatcher;

impl OuiMatcher {
    /// Look up the vendor name for a given MAC address string (e.g. "6e:63:f8:3f:a1:bb").
    pub fn lookup(mac: &str) -> Option<String> {
        let clean: String = mac
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .map(|c| c.to_ascii_uppercase())
            .take(6)
            .collect();

        if clean.len() < 6 {
            return None;
        }

        let db = OUI_DATABASE.get_or_init(build_builtin_oui);
        if let Some(vendor) = db.get(&clean) {
            return Some((*vendor).to_string());
        }

        // Try reading external nmap prefix file if present on system
        for path in [
            "/usr/share/nmap/nmap-mac-prefixes",
            "/var/lib/misc/nmap-mac-prefixes",
        ] {
            if Path::new(path).exists()
                && let Ok(file) = File::open(path)
            {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 && parts[0].eq_ignore_ascii_case(&clean) {
                        return Some(parts[1..].join(" "));
                    }
                }
            }
        }

        // Check if locally administered address (randomized MAC)
        if let Ok(first_byte) = u8::from_str_radix(&clean[0..2], 16)
            && (first_byte & 0x02) != 0
        {
            return Some("Locally Administered / Randomized MAC".to_string());
        }

        None
    }
}
