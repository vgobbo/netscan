use crate::fingerprint::findings::HttpEndpointSpec;
use regex::Regex;
use reqwest::Client;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

static TITLE_RE: OnceLock<Regex> = OnceLock::new();

#[derive(Debug, Default, Clone)]
pub struct HttpFindings {
    pub title: Option<String>,
    pub server: Option<String>,
    pub bodies: Vec<String>,
    pub endpoints: BTreeMap<String, String>,
}

pub struct HttpProber;

impl HttpProber {
    /// Inspects HTTP/HTTPS root endpoints and any rule-declared sub-paths on open web ports.
    pub async fn probe(
        client: &Client,
        ip: IpAddr,
        open_ports: &[u16],
        extra_endpoints: &[HttpEndpointSpec],
    ) -> HttpFindings {
        let mut fp = HttpFindings::default();

        let candidate_ports: Vec<u16> = [80, 443, 8080, 8443, 9100]
            .into_iter()
            .filter(|p| open_ports.contains(p))
            .collect();

        if candidate_ports.is_empty() && extra_endpoints.is_empty() {
            return fp;
        }

        let title_re =
            TITLE_RE.get_or_init(|| Regex::new(r"(?i)<title[^>]*>(.*?)</title>").unwrap());

        for port in candidate_ports {
            let schemes = if port == 443 || port == 8443 {
                ["https", "http"]
            } else {
                ["http", "https"]
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

                if fp.server.is_none()
                    && let Some(srv) = resp.headers().get(reqwest::header::SERVER)
                    && let Ok(s) = srv.to_str()
                {
                    fp.server = Some(s.to_string());
                }

                if let Ok(body) = resp.text().await {
                    let truncated = truncate_utf8(&body, 32768);

                    if fp.title.is_none()
                        && let Some(caps) = title_re.captures(truncated)
                    {
                        let title = caps[1].trim().to_string();
                        if !title.is_empty() {
                            fp.title = Some(title);
                        }
                    }

                    if !truncated.is_empty() {
                        fp.bodies.push(truncated.to_string());
                    }
                }
            }
        }

        for ep in extra_endpoints {
            if !open_ports.contains(&ep.port) {
                continue;
            }
            let scheme = if ep.port == 443 || ep.port == 8443 {
                "https"
            } else {
                "http"
            };
            let path = if ep.path.starts_with('/') {
                ep.path.clone()
            } else {
                format!("/{}", ep.path)
            };
            let url = format!("{}://{}:{}{}", scheme, ip, ep.port, path);
            if let Ok(resp) = client
                .get(&url)
                .timeout(Duration::from_millis(1000))
                .send()
                .await
                && let Ok(text) = resp.text().await
            {
                fp.endpoints
                    .insert(ep.path.clone(), truncate_utf8(&text, 262_144).to_string());
            }
        }

        fp
    }
}

fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}
