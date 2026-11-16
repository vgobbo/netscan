use regex::Regex;
use reqwest::Client;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Default, Clone)]
pub struct HttpFingerprint {
    pub title: Option<String>,
    pub server: Option<String>,
    pub unifi_model: Option<String>,
    pub asus_mode: Option<String>,
    pub is_zyxel: bool,
    pub is_mongoose_elinter: bool,
    pub is_yamaha: Option<String>,
    pub is_prometheus: bool,
    pub is_daikin: bool,
}

pub struct HttpProber;

impl HttpProber {
    /// Inspects HTTP and HTTPS endpoints on common web ports for device identification.
    pub async fn probe(client: &Client, ip: IpAddr, open_ports: &[u16]) -> HttpFingerprint {
        let mut fp = HttpFingerprint::default();

        let candidate_ports: Vec<u16> = [80, 443, 8080, 8443, 9100]
            .into_iter()
            .filter(|p| open_ports.contains(p))
            .collect();

        if candidate_ports.is_empty() {
            return fp;
        }

        let title_re = Regex::new(r"(?i)<title[^>]*>(.*?)</title>").unwrap();
        let unifi_re = Regex::new(r#"window\.UNIFI_OS_MANIFEST\s*=\s*(\{[^}]+\})"#).unwrap();
        let yamaha_re = Regex::new(r"Network_Module/[0-9.]+\s*\(([A-Za-z0-9_-]+)\)").unwrap();

        for port in candidate_ports {
            let schemes = if port == 443 || port == 8443 {
                vec!["https", "http"]
            } else {
                vec!["http", "https"]
            };

            for scheme in schemes {
                let url = format!("{}://{}:{}", scheme, ip, port);
                let resp = match client
                    .get(&url)
                    .timeout(Duration::from_millis(1500))
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                // Check Server header
                if let Some(srv) = resp.headers().get(reqwest::header::SERVER)
                    && let Ok(s) = srv.to_str()
                {
                    if fp.server.is_none() {
                        fp.server = Some(s.to_string());
                    }

                    if let Some(caps) = yamaha_re.captures(s) {
                        fp.is_yamaha = Some(caps[1].to_string());
                    }

                    if s.contains("Mongoose") {
                        fp.is_mongoose_elinter = true;
                    }
                }

                // Check body text (up to 32KB)
                if let Ok(body) = resp.text().await {
                    let truncated = if body.len() > 32768 {
                        &body[..32768]
                    } else {
                        &body
                    };

                    // Title tag
                    if fp.title.is_none()
                        && let Some(caps) = title_re.captures(truncated)
                    {
                        let title = caps[1].trim().to_string();
                        if !title.is_empty() {
                            fp.title = Some(title);
                        }
                    }

                    // UniFi OS manifest
                    if let Some(caps) = unifi_re.captures(truncated)
                        && let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&caps[1])
                        && let Some(short_name) = manifest
                            .get("model")
                            .and_then(|m| m.get("shortName"))
                            .and_then(|s| s.as_str())
                    {
                        fp.unifi_model = Some(short_name.to_string());
                    }

                    // ASUSWRT detection
                    if truncated.contains("Main_Login.asp") || truncated.contains("router.asus.com")
                    {
                        if truncated.contains("isAMeshRE = ('1' == '1')")
                            || truncated.contains("AiMesh router detect")
                        {
                            fp.asus_mode = Some("AiMesh Satellite Node".to_string());
                        } else {
                            fp.asus_mode = Some("AiMesh Master / AP".to_string());
                        }
                    }

                    // Zyxel detection
                    if truncated.contains("FaviconZyxel.png")
                        || truncated.contains("Welcome to the Web-Based Configurator")
                        || truncated.contains("zyxel-icon")
                    {
                        fp.is_zyxel = true;
                    }

                    // E-Linter solar inverter
                    if truncated.contains("Inverter firmware") || truncated.contains("staset.cgi") {
                        fp.is_mongoose_elinter = true;
                    }

                    // Daikin DGC / BRP069C4x embedded open-source software notice page
                    if truncated.contains("<hrml lang=\"en\">")
                        && truncated
                            .contains("This software is included following open source software.")
                    {
                        fp.is_daikin = true;
                    }
                }

                // Check Prometheus node_exporter metrics
                if port == 9100 {
                    let metrics_url = format!("http://{}:9100/metrics", ip);
                    if let Ok(m_resp) = client
                        .get(&metrics_url)
                        .timeout(Duration::from_millis(1000))
                        .send()
                        .await
                        && let Ok(m_text) = m_resp.text().await
                        && (m_text.contains("node_os_info") || m_text.contains("node_uname_info"))
                    {
                        fp.is_prometheus = true;
                    }
                }
            }
        }

        fp
    }
}
