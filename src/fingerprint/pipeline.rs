use crate::fingerprint::cast::CastProber;
use crate::fingerprint::daikin::DaikinProber;
use crate::fingerprint::findings::{HostFindings, ScannerKind};
use crate::fingerprint::homewizard::HomeWizardProber;
use crate::fingerprint::http::HttpProber;
use crate::fingerprint::oui::OuiMatcher;
use crate::fingerprint::rule_engine::{EvaluationOutcome, RuleEngine};
use crate::fingerprint::rule_schema::CompiledRuleset;
use crate::model::Device;
use crate::net::ArpReader;
use crate::scanner::{FAST_PROBE_PORTS, NativeScanner, NetworkScanner};
use reqwest::Client;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, info};

struct HostState {
    findings: HostFindings,
    conclusive: Option<EvaluationOutcome>,
}

pub struct FingerprintPipeline {
    client: Client,
    concurrency: usize,
    engine: RuleEngine,
    full_scan: bool,
}

impl FingerprintPipeline {
    pub fn new(concurrency: usize, ruleset: CompiledRuleset, full_scan: bool) -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_millis(1500))
            .build()
            .unwrap_or_default();

        Self {
            client,
            concurrency,
            engine: RuleEngine::new(ruleset),
            full_scan,
        }
    }

    /// Executes ordered discovery and fingerprinting stages from fastest to slowest,
    /// short-circuiting per host once conclusively identified unless `--full` is enabled.
    pub async fn run(
        &self,
        enumerated_devices: &[Device],
        scanner: &dyn NetworkScanner,
    ) -> Vec<Device> {
        let mut states: Vec<HostState> = enumerated_devices
            .iter()
            .map(|d| HostState {
                findings: HostFindings::from_device(d),
                conclusive: None,
            })
            .collect();

        let stages = ScannerKind::ordered_stages();

        for (stage_idx, &stage) in stages.iter().enumerate() {
            let active_indices: Vec<usize> = states
                .iter()
                .enumerate()
                .filter(|(_, s)| self.full_scan || s.conclusive.is_none())
                .map(|(i, _)| i)
                .collect();

            if active_indices.is_empty() {
                info!(
                    "All {} hosts conclusively identified; skipping remaining scanner stages",
                    states.len()
                );
                break;
            }

            info!(
                "Stage {}/{}: running '{}' on {}/{} host(s)",
                stage_idx + 1,
                stages.len(),
                stage,
                active_indices.len(),
                states.len()
            );

            self.execute_stage(stage, &mut states, &active_indices, scanner)
                .await;

            let remaining = &stages[stage_idx + 1..];
            let mut newly_conclusive = 0usize;

            for idx in active_indices {
                states[idx].findings.completed_scanners.insert(stage);
                if states[idx].conclusive.is_none() {
                    let outcome = self.engine.evaluate(&states[idx].findings, remaining);
                    if let EvaluationOutcome::Conclusive { ref rule_id, .. } = outcome {
                        debug!(
                            "Host {} conclusively matched rule '{}' at stage '{}'",
                            states[idx].findings.ip, rule_id, stage
                        );
                        states[idx].conclusive = Some(outcome);
                        newly_conclusive += 1;
                    }
                }
            }

            if newly_conclusive > 0 {
                info!(
                    "Stage '{}' conclusively identified {} additional host(s)",
                    stage, newly_conclusive
                );
            }
        }

        let mut devices: Vec<Device> = states
            .into_iter()
            .map(|state| {
                let mut dev = state.findings.to_base_device();
                let outcome = match state.conclusive {
                    Some(c) if !self.full_scan => c,
                    _ => self.engine.evaluate(&state.findings, &[]),
                };
                RuleEngine::apply_outcome(&mut dev, &outcome);
                debug!(
                    "Host {} finalized: {} ({}) [{} {}%]",
                    dev.ip,
                    dev.device_name,
                    dev.device_type,
                    dev.identification_status,
                    dev.certainty
                );
                dev
            })
            .collect();

        devices.sort_by_key(|d| d.ip);
        devices
    }

    async fn execute_stage(
        &self,
        stage: ScannerKind,
        states: &mut [HostState],
        active_indices: &[usize],
        scanner: &dyn NetworkScanner,
    ) {
        match stage {
            ScannerKind::ArpOuiRdns => self.run_arp_oui_rdns(states, active_indices).await,
            ScannerKind::PortsFast => {
                let ips: Vec<IpAddr> = active_indices
                    .iter()
                    .map(|&i| states[i].findings.ip)
                    .collect();
                if let Ok(port_map) = scanner.scan_ports_batch(&ips, FAST_PROBE_PORTS).await {
                    for &idx in active_indices {
                        if let Some(ports) = port_map.get(&states[idx].findings.ip) {
                            for &p in ports {
                                states[idx].findings.add_port(p);
                            }
                        }
                    }
                }
            }
            ScannerKind::UdpDiscovery => self.run_udp_discovery(states, active_indices).await,
            ScannerKind::Http => self.run_http_stage(states, active_indices).await,
            ScannerKind::ApiProtocols => self.run_api_protocols(states, active_indices).await,
            ScannerKind::PortsExtendedNmap => {
                let ips: Vec<IpAddr> = active_indices
                    .iter()
                    .map(|&i| states[i].findings.ip)
                    .collect();
                if let Ok(port_map) = scanner.scan_extended_ports_batch(&ips).await {
                    for &idx in active_indices {
                        if let Some(ports) = port_map.get(&states[idx].findings.ip) {
                            for &p in ports {
                                states[idx].findings.add_port(p);
                            }
                        }
                    }
                }
            }
        }
    }

    async fn run_arp_oui_rdns(&self, states: &mut [HostState], active_indices: &[usize]) {
        let arp_table = ArpReader::get_table();
        let custom_oui = Arc::new(self.engine.ruleset().custom_oui.clone());
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let mut tasks = Vec::new();

        for &idx in active_indices {
            let ip = states[idx].findings.ip;
            let mut mac = states[idx].findings.mac.clone();
            if mac.is_none() {
                mac = arp_table.get(&ip).cloned();
            }
            let existing_hostname = states[idx].findings.hostname.clone();
            let existing_vendor = states[idx].findings.vendor.clone();
            let custom = custom_oui.clone();
            let permit = sem.clone();

            tasks.push(tokio::spawn(async move {
                let _p = permit.acquire().await;
                let hostname = match existing_hostname {
                    Some(h) => Some(h),
                    None => NativeScanner::resolve_hostname(ip).await,
                };
                let vendor = match existing_vendor {
                    Some(v) => Some(v),
                    None => mac
                        .as_deref()
                        .and_then(|m| OuiMatcher::lookup_with_custom(m, &custom)),
                };
                (idx, mac, hostname, vendor)
            }));
        }

        for t in tasks {
            if let Ok((idx, mac, hostname, vendor)) = t.await {
                let f = &mut states[idx].findings;
                if f.mac.is_none() {
                    f.mac = mac;
                }
                if f.hostname.is_none() {
                    f.hostname = hostname;
                }
                if f.vendor.is_none() {
                    f.vendor = vendor;
                }
            }
        }
    }

    async fn run_udp_discovery(&self, states: &mut [HostState], active_indices: &[usize]) {
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let mut tasks = Vec::new();

        for &idx in active_indices {
            let ip = states[idx].findings.ip;
            let permit = sem.clone();
            tasks.push(tokio::spawn(async move {
                let _p = permit.acquire().await;
                let daikin = DaikinProber::probe_udp(ip).await;
                (idx, daikin)
            }));
        }

        for t in tasks {
            if let Ok((idx, Some(daikin))) = t.await {
                daikin.populate_findings(&mut states[idx].findings);
            }
        }
    }

    async fn run_http_stage(&self, states: &mut [HostState], active_indices: &[usize]) {
        let extra_endpoints = Arc::new(self.engine.ruleset().http_endpoints.clone());
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let mut tasks = Vec::new();

        for &idx in active_indices {
            let open_ports = states[idx].findings.open_ports.clone();
            let has_web_port = open_ports
                .iter()
                .any(|p| matches!(p, 80 | 443 | 8080 | 8443 | 9100))
                || extra_endpoints
                    .iter()
                    .any(|ep| open_ports.contains(&ep.port));
            if !has_web_port {
                continue;
            }

            let ip = states[idx].findings.ip;
            let client = self.client.clone();
            let eps = extra_endpoints.clone();
            let permit = sem.clone();

            tasks.push(tokio::spawn(async move {
                let _p = permit.acquire().await;
                let fp = HttpProber::probe(&client, ip, &open_ports, &eps).await;
                (idx, fp)
            }));
        }

        for t in tasks {
            if let Ok((idx, fp)) = t.await {
                let f = &mut states[idx].findings;
                if f.http_title.is_none() {
                    f.http_title = fp.title;
                }
                if f.http_server.is_none() {
                    f.http_server = fp.server;
                }
                f.http_bodies.extend(fp.bodies);
                f.http_endpoints.extend(fp.endpoints);
            }
        }
    }

    async fn run_api_protocols(&self, states: &mut [HostState], active_indices: &[usize]) {
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let mut tasks = Vec::new();

        for &idx in active_indices {
            let open_ports = states[idx].findings.open_ports.clone();
            let has_cast_port = open_ports.contains(&8008);
            let has_http_port = open_ports.contains(&80);
            let needs_daikin_http = !states[idx]
                .findings
                .attributes
                .contains_key("daikin.unit_type");

            if !has_cast_port && !has_http_port {
                continue;
            }

            let ip = states[idx].findings.ip;
            let client = self.client.clone();
            let permit = sem.clone();

            tasks.push(tokio::spawn(async move {
                let _p = permit.acquire().await;
                let cast = if has_cast_port {
                    CastProber::probe(&client, ip).await
                } else {
                    None
                };
                let hw = if has_http_port {
                    HomeWizardProber::probe(&client, ip).await
                } else {
                    None
                };
                let daikin_http = if has_http_port && needs_daikin_http && hw.is_none() {
                    DaikinProber::probe_http(&client, ip).await
                } else {
                    None
                };
                (idx, cast, hw, daikin_http)
            }));
        }

        for t in tasks {
            if let Ok((idx, cast, hw, daikin_http)) = t.await {
                let f = &mut states[idx].findings;
                if let Some(c) = cast {
                    c.populate_findings(f);
                }
                if let Some(h) = hw {
                    h.populate_findings(f);
                }
                if let Some(d) = daikin_http {
                    d.populate_findings(f);
                }
            }
        }
    }
}
