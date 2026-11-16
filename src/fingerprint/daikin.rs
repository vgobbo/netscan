use crate::fingerprint::findings::HostFindings;
use reqwest::Client;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::debug;

const DAIKIN_UDP_PORT: u16 = 30050;
const DAIKIN_UDP_QUERY: &[u8] = b"DAIKIN_UDP/common/basic_info";

/// Metadata extracted from a Daikin Wi-Fi adapter via read-only discovery probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaikinInfo {
    pub name: Option<String>,
    pub unit_type: Option<String>,
    pub cdev: Option<String>,
    pub protocol: Option<String>,
    pub firmware_version: Option<String>,
    pub ssid: Option<String>,
    pub adapter_kind: Option<String>,
}

impl DaikinInfo {
    /// Stores Daikin metadata in the host findings attribute map for TOML rule matching.
    pub fn populate_findings(&self, findings: &mut HostFindings) {
        if let Some(v) = &self.name {
            findings
                .attributes
                .insert("daikin.name".to_string(), v.clone());
        }
        if let Some(v) = &self.unit_type {
            findings
                .attributes
                .insert("daikin.unit_type".to_string(), v.clone());
        }
        if let Some(v) = &self.cdev {
            findings
                .attributes
                .insert("daikin.cdev".to_string(), v.clone());
        }
        if let Some(v) = &self.protocol {
            findings
                .attributes
                .insert("daikin.protocol".to_string(), v.clone());
        }
        if let Some(v) = &self.firmware_version {
            findings
                .attributes
                .insert("daikin.ver".to_string(), v.clone());
        }
        if let Some(v) = &self.ssid {
            findings
                .attributes
                .insert("daikin.ssid".to_string(), v.clone());
        }
        if let Some(v) = &self.adapter_kind {
            findings
                .attributes
                .insert("daikin.adp_kind".to_string(), v.clone());
        }
    }
}

pub struct DaikinProber;

impl DaikinProber {
    /// Sends a read-only `DAIKIN_UDP/common/basic_info` probe to UDP port 30050.
    pub async fn probe_udp(ip: IpAddr) -> Option<DaikinInfo> {
        let bind_addr = match ip {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_addr).await.ok()?;
        let target = SocketAddr::new(ip, DAIKIN_UDP_PORT);

        socket.send_to(DAIKIN_UDP_QUERY, target).await.ok()?;

        let mut buf = [0u8; 2048];
        let (len, _src) = timeout(Duration::from_millis(1000), socket.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;

        let payload = std::str::from_utf8(&buf[..len]).ok()?;
        let info = Self::parse_response(payload)?;
        debug!(
            "Daikin UDP device discovered at {}: name={:?}, ssid={:?}",
            ip, info.name, info.ssid
        );
        Some(info)
    }

    /// Queries the legacy Daikin `/common/basic_info` HTTP endpoint on port 80.
    pub async fn probe_http(client: &Client, ip: IpAddr) -> Option<DaikinInfo> {
        let url = format!("http://{}/common/basic_info", ip);
        let resp = client
            .get(&url)
            .timeout(Duration::from_millis(1200))
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            return None;
        }

        let body = resp.text().await.ok()?;
        let info = Self::parse_response(&body)?;
        debug!(
            "Daikin HTTP device discovered at {}: name={:?}, ssid={:?}",
            ip, info.name, info.ssid
        );
        Some(info)
    }

    /// Parses Daikin's comma-separated `key=value` basic_info response format.
    pub fn parse_response(raw: &str) -> Option<DaikinInfo> {
        let mut fields = HashMap::new();
        for pair in raw.trim().split(',') {
            if let Some((k, v)) = pair.split_once('=') {
                fields.insert(k.trim(), v.trim());
            }
        }

        if fields.get("ret").copied() != Some("OK") {
            return None;
        }

        let ssid = fields
            .get("ssid")
            .filter(|s| !s.is_empty())
            .map(|s| (*s).to_string());
        let unit_type = fields
            .get("type")
            .filter(|s| !s.is_empty())
            .map(|s| (*s).to_string());
        let cdev = fields
            .get("cdev")
            .filter(|s| !s.is_empty())
            .map(|s| (*s).to_string());
        let protocol = fields
            .get("protocol")
            .filter(|s| !s.is_empty())
            .map(|s| (*s).to_string());
        let adapter_kind = fields
            .get("adp_kind")
            .filter(|s| !s.is_empty())
            .map(|s| (*s).to_string());

        let is_daikin_payload = ssid
            .as_deref()
            .is_some_and(|s| s.to_ascii_lowercase().starts_with("daikin"))
            || protocol.as_deref() == Some("DGC")
            || unit_type.as_deref() == Some("aircon")
            || (cdev.is_some() && adapter_kind.is_some());

        if !is_daikin_payload {
            return None;
        }

        let name = fields
            .get("name")
            .map(|v| percent_decode(v))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let firmware_version = fields
            .get("ver")
            .filter(|s| !s.is_empty())
            .map(|s| s.replace('_', "."));

        Some(DaikinInfo {
            name,
            unit_type,
            cdev,
            protocol,
            firmware_version,
            ssid,
            adapter_kind,
        })
    }
}

/// Decodes percent-encoded UTF-8 strings (e.g. `%4c%69%76%69%6e%67%20%72%6f%6f%6d` -> `"Living room"`).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(val) = u8::from_str_radix(hex, 16)
        {
            out.push(val);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_daikin_udp_dgc_payloads() {
        let living = "ret=OK,type=GPF,cdev=RA,protocol=DGC,reg=eu,ver=2_6_2,rev=AA16E9E6,comm_err=0,lpw_flag=0,adp_kind=4,mac=24CD8D8D724E,ssid=DaikinAP41424,adp_mode=ap_run,method=polling,name=%4c%69%76%69%6e%67%20%72%6f%6f%6d,icon=1,edid=0000000009020830,sw_id=1900295E";
        let info = DaikinProber::parse_response(living).expect("valid Daikin DGC payload");
        assert_eq!(info.name.as_deref(), Some("Living room"));
        assert_eq!(info.unit_type.as_deref(), Some("GPF"));
        assert_eq!(info.cdev.as_deref(), Some("RA"));
        assert_eq!(info.protocol.as_deref(), Some("DGC"));
        assert_eq!(info.firmware_version.as_deref(), Some("2.6.2"));
        assert_eq!(info.ssid.as_deref(), Some("DaikinAP41424"));
        assert_eq!(info.adapter_kind.as_deref(), Some("4"));

        let office = "ret=OK,type=GPF,cdev=RA,protocol=DGC,reg=eu,ver=2_6_2,ssid=DaikinAP03732,adp_kind=4,name=%4f%66%66%69%63%65";
        let office_info = DaikinProber::parse_response(office).unwrap();
        assert_eq!(office_info.name.as_deref(), Some("Office"));

        let bedroom = "ret=OK,type=GPF,cdev=RA,protocol=DGC,reg=eu,ver=2_6_2,ssid=DaikinAP06020,adp_kind=4,name=%42%65%64%72%6f%6f%6d";
        let bedroom_info = DaikinProber::parse_response(bedroom).unwrap();
        assert_eq!(bedroom_info.name.as_deref(), Some("Bedroom"));
    }

    #[test]
    fn parses_legacy_http_aircon_payload() {
        let legacy = "ret=OK,type=aircon,reg=eu,dst=1,ver=1_14_88,rev=D6A8A05,pow=1,err=0,location=0,name=%4b%69%74%63%68%65%6e,icon=0,method=polling,port=30050,id=,pw=,lpw_flag=0,adp_kind=3";
        let info = DaikinProber::parse_response(legacy).expect("valid legacy Daikin HTTP payload");
        assert_eq!(info.name.as_deref(), Some("Kitchen"));
        assert_eq!(info.unit_type.as_deref(), Some("aircon"));
        assert_eq!(info.firmware_version.as_deref(), Some("1.14.88"));
        assert_eq!(info.adapter_kind.as_deref(), Some("3"));
    }

    #[test]
    fn rejects_non_daikin_payloads() {
        assert!(DaikinProber::parse_response("Page Not Found\r\n/common/basic_info").is_none());
        assert!(DaikinProber::parse_response("ret=OK,foo=bar").is_none());
        assert!(DaikinProber::parse_response("ret=PARAM NG,type=aircon").is_none());
    }
}
