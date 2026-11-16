use crate::fingerprint::findings::{HostFindings, ScannerKind};
use crate::fingerprint::rule_schema::{CompiledRule, CompiledRuleset, ExtractSource};
use crate::model::{Device, DeviceType, IdentificationStatus};
use std::collections::BTreeMap;

const FAST_CORE_PORTS: &[u16] = &[80, 443, 22, 8008, 8080, 8443, 8883, 9100];

/// Materialized device metadata produced by a matching rule and template substitution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedOutput {
    pub device_type: DeviceType,
    pub device_name: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub notes: Option<String>,
}

/// Result of evaluating the TOML ruleset against a host's accumulated findings.
#[derive(Debug, Clone)]
pub enum EvaluationOutcome {
    /// Exactly one conclusive rule matched at the top tier and no higher-priority rule can still match.
    Conclusive {
        rule_id: String,
        output: MaterializedOutput,
    },
    /// More scanners are needed (either no conclusive match yet, tied top rules, or a higher tier is still eligible).
    Pending,
    /// All scanners finished without a unique conclusive match; carries best-guess metadata and certainty.
    Finalized {
        status: IdentificationStatus,
        certainty: u8,
        output: Option<MaterializedOutput>,
        matched_rules: Vec<String>,
        notes_suffix: Option<String>,
    },
}

enum PredicateStatus {
    Matched,
    Contradicted,
    Unresolved,
}

struct RuleEval<'a> {
    rule: &'a CompiledRule,
    full_match: bool,
    contradicted: bool,
    satisfied: usize,
    total: usize,
    captures: BTreeMap<String, String>,
}

pub struct RuleEngine {
    ruleset: CompiledRuleset,
}

impl RuleEngine {
    pub fn new(ruleset: CompiledRuleset) -> Self {
        Self { ruleset }
    }

    pub fn ruleset(&self) -> &CompiledRuleset {
        &self.ruleset
    }

    /// Evaluates the ruleset at the current pipeline stage.
    /// When `remaining_scanners` is empty, always returns `Conclusive` or `Finalized` (never `Pending`).
    pub fn evaluate(
        &self,
        findings: &HostFindings,
        remaining_scanners: &[ScannerKind],
    ) -> EvaluationOutcome {
        let evals: Vec<RuleEval<'_>> = self
            .ruleset
            .rules
            .iter()
            .map(|r| evaluate_rule(r, findings))
            .collect();

        // Collect all conclusive rules that fully matched
        let full_conclusive: Vec<&RuleEval<'_>> = evals
            .iter()
            .filter(|e| e.full_match && e.rule.conclusive)
            .collect();

        let top_prio = full_conclusive.iter().map(|e| e.rule.priority).max();
        let top_matches: Vec<&RuleEval<'_>> = match top_prio {
            Some(p) => full_conclusive
                .into_iter()
                .filter(|e| e.rule.priority == p)
                .collect(),
            None => Vec::new(),
        };

        // Lookahead guard: if any unmatched higher-priority conclusive rule still needs a remaining
        // scanner and has NOT been contradicted by already-completed scanners, keep scanning.
        if !remaining_scanners.is_empty() {
            let min_pending_prio = top_prio.unwrap_or(0);
            let higher_pending = evals.iter().any(|e| {
                !e.full_match
                    && e.rule.conclusive
                    && !e.contradicted
                    && (top_prio.is_none() || e.rule.priority > min_pending_prio)
                    && e.rule
                        .requires_scanners
                        .iter()
                        .any(|s| remaining_scanners.contains(s))
            });

            if top_matches.len() == 1 && !higher_pending {
                let winner = top_matches[0];
                return EvaluationOutcome::Conclusive {
                    rule_id: winner.rule.id.clone(),
                    output: materialize_output(winner.rule, findings, &winner.captures),
                };
            }

            return EvaluationOutcome::Pending;
        }

        // All scanners finished: produce final Conclusive or Finalized classification.
        if top_matches.len() == 1 {
            let winner = top_matches[0];
            return EvaluationOutcome::Conclusive {
                rule_id: winner.rule.id.clone(),
                output: materialize_output(winner.rule, findings, &winner.captures),
            };
        }

        if top_matches.len() > 1 {
            let ids: Vec<String> = top_matches.iter().map(|e| e.rule.id.clone()).collect();
            let winner = top_matches
                .iter()
                .max_by_key(|e| e.total)
                .unwrap_or(&top_matches[0]);
            let certainty = (85 / top_matches.len()).clamp(30, 75) as u8;
            return EvaluationOutcome::Finalized {
                status: IdentificationStatus::Ambiguous,
                certainty,
                output: Some(materialize_output(winner.rule, findings, &winner.captures)),
                matched_rules: ids.clone(),
                notes_suffix: Some(format!("Ambiguous match across rules: {}", ids.join(", "))),
            };
        }

        // Check non-conclusive fallback rules (sorted descending by priority already)
        if let Some(fallback) = evals.iter().find(|e| e.full_match && !e.rule.conclusive) {
            let certainty = (20 + fallback.rule.priority.min(55)) as u8;
            return EvaluationOutcome::Finalized {
                status: IdentificationStatus::BestGuess,
                certainty,
                output: Some(materialize_output(
                    fallback.rule,
                    findings,
                    &fallback.captures,
                )),
                matched_rules: vec![fallback.rule.id.clone()],
                notes_suffix: None,
            };
        }

        // Check partial predicate matches across multi-condition conclusive rules
        let best_partial = evals
            .iter()
            .filter(|e| e.rule.conclusive && e.total >= 2 && e.satisfied > 0)
            .max_by_key(|e| (e.satisfied * 100 / e.total, e.rule.priority));

        if let Some(partial) = best_partial {
            let certainty = (15 + (40 * partial.satisfied / partial.total)) as u8;
            return EvaluationOutcome::Finalized {
                status: IdentificationStatus::BestGuess,
                certainty,
                output: Some(materialize_output(
                    partial.rule,
                    findings,
                    &partial.captures,
                )),
                matched_rules: vec![partial.rule.id.clone()],
                notes_suffix: Some(format!(
                    "Partial match ({}/{} predicates)",
                    partial.satisfied, partial.total
                )),
            };
        }

        EvaluationOutcome::Finalized {
            status: IdentificationStatus::Unidentified,
            certainty: if findings.vendor.is_some() { 10 } else { 0 },
            output: None,
            matched_rules: Vec::new(),
            notes_suffix: None,
        }
    }

    /// Applies an evaluation result onto a `Device`.
    pub fn apply_outcome(device: &mut Device, outcome: &EvaluationOutcome) {
        match outcome {
            EvaluationOutcome::Conclusive { rule_id, output } => {
                apply_materialized(device, output);
                device.certainty = 100;
                device.identification_status = IdentificationStatus::Conclusive;
                device.matched_rules = vec![rule_id.clone()];
            }
            EvaluationOutcome::Finalized {
                status,
                certainty,
                output,
                matched_rules,
                notes_suffix,
            } => {
                if let Some(out) = output {
                    apply_materialized(device, out);
                }
                device.certainty = *certainty;
                device.identification_status = *status;
                device.matched_rules = matched_rules.clone();
                if let Some(suffix) = notes_suffix {
                    device.notes = Some(match &device.notes {
                        Some(existing) if !existing.is_empty() => {
                            format!("{}; {}", existing, suffix)
                        }
                        _ => suffix.clone(),
                    });
                }
            }
            EvaluationOutcome::Pending => {}
        }
    }
}

fn apply_materialized(device: &mut Device, output: &MaterializedOutput) {
    device.device_type = output.device_type;
    if let Some(name) = &output.device_name
        && !name.is_empty()
    {
        device.device_name = name.clone();
    }
    if let Some(vendor) = &output.vendor
        && !vendor.is_empty()
    {
        device.vendor = Some(vendor.clone());
    }
    if let Some(model) = &output.model
        && !model.is_empty()
    {
        device.model = Some(model.clone());
    }
    if let Some(notes) = &output.notes
        && !notes.is_empty()
    {
        device.notes = Some(notes.clone());
    }
}

fn evaluate_rule<'a>(rule: &'a CompiledRule, f: &HostFindings) -> RuleEval<'a> {
    let mut statuses: Vec<PredicateStatus> = Vec::new();
    let arp_done = f.has_completed(ScannerKind::ArpOuiRdns);
    let http_done = f.has_completed(ScannerKind::Http);
    let api_done = f.has_completed(ScannerKind::ApiProtocols);
    let udp_done = f.has_completed(ScannerKind::UdpDiscovery);

    if let Some(m) = &rule.hostname {
        statuses.push(match &f.hostname {
            Some(h) if m.matches(h) => PredicateStatus::Matched,
            _ if arp_done => PredicateStatus::Contradicted,
            _ => PredicateStatus::Unresolved,
        });
    }

    if !rule.hostname_contains.is_empty() {
        let matched = f
            .hostname
            .as_deref()
            .map(|h| h.to_lowercase())
            .is_some_and(|h| rule.hostname_contains.iter().any(|pat| h.contains(pat)));
        statuses.push(if matched {
            PredicateStatus::Matched
        } else if arp_done {
            PredicateStatus::Contradicted
        } else {
            PredicateStatus::Unresolved
        });
    }

    if let Some(want_non_empty) = rule.hostname_not_empty {
        let is_non_empty = f
            .hostname
            .as_deref()
            .is_some_and(|h| !h.is_empty() && h != f.ip.to_string());
        statuses.push(if is_non_empty == want_non_empty {
            PredicateStatus::Matched
        } else if arp_done {
            PredicateStatus::Contradicted
        } else {
            PredicateStatus::Unresolved
        });
    }

    if let Some(m) = &rule.vendor {
        statuses.push(match &f.vendor {
            Some(v) if m.matches(v) => PredicateStatus::Matched,
            _ if arp_done => PredicateStatus::Contradicted,
            _ => PredicateStatus::Unresolved,
        });
    }

    if !rule.vendor_contains.is_empty() {
        let matched = f
            .vendor
            .as_deref()
            .map(|v| v.to_lowercase())
            .is_some_and(|v| rule.vendor_contains.iter().any(|pat| v.contains(pat)));
        statuses.push(if matched {
            PredicateStatus::Matched
        } else if arp_done {
            PredicateStatus::Contradicted
        } else {
            PredicateStatus::Unresolved
        });
    }

    if let Some(want_gw) = rule.is_gateway {
        statuses.push(if f.is_gateway == want_gw {
            PredicateStatus::Matched
        } else if arp_done {
            PredicateStatus::Contradicted
        } else {
            PredicateStatus::Unresolved
        });
    }

    if !rule.ports_any.is_empty() {
        let any_open = rule.ports_any.iter().any(|p| f.open_ports.contains(p));
        let ready = ports_known(&rule.ports_any, f);
        statuses.push(if any_open {
            PredicateStatus::Matched
        } else if ready {
            PredicateStatus::Contradicted
        } else {
            PredicateStatus::Unresolved
        });
    }

    if !rule.ports_all.is_empty() {
        let all_open = rule.ports_all.iter().all(|p| f.open_ports.contains(p));
        let ready = ports_known(&rule.ports_all, f);
        statuses.push(if all_open {
            PredicateStatus::Matched
        } else if ready {
            PredicateStatus::Contradicted
        } else {
            PredicateStatus::Unresolved
        });
    }

    if !rule.ports_none.is_empty() {
        let any_forbidden_open = rule.ports_none.iter().any(|p| f.open_ports.contains(p));
        let ready = ports_known(&rule.ports_none, f);
        statuses.push(if any_forbidden_open {
            PredicateStatus::Contradicted
        } else if ready {
            PredicateStatus::Matched
        } else {
            PredicateStatus::Unresolved
        });
    }

    if let Some(m) = &rule.http_title {
        statuses.push(match &f.http_title {
            Some(t) if m.matches(t) => PredicateStatus::Matched,
            _ if http_done => PredicateStatus::Contradicted,
            _ => PredicateStatus::Unresolved,
        });
    }

    if !rule.http_title_contains.is_empty() {
        let matched = f
            .http_title
            .as_deref()
            .map(|t| t.to_lowercase())
            .is_some_and(|t| rule.http_title_contains.iter().any(|pat| t.contains(pat)));
        statuses.push(if matched {
            PredicateStatus::Matched
        } else if http_done {
            PredicateStatus::Contradicted
        } else {
            PredicateStatus::Unresolved
        });
    }

    if let Some(m) = &rule.http_server {
        statuses.push(match &f.http_server {
            Some(s) if m.matches(s) => PredicateStatus::Matched,
            _ if http_done => PredicateStatus::Contradicted,
            _ => PredicateStatus::Unresolved,
        });
    }

    if !rule.http_server_contains.is_empty() {
        let matched = f
            .http_server
            .as_deref()
            .map(|s| s.to_lowercase())
            .is_some_and(|s| rule.http_server_contains.iter().any(|pat| s.contains(pat)));
        statuses.push(if matched {
            PredicateStatus::Matched
        } else if http_done {
            PredicateStatus::Contradicted
        } else {
            PredicateStatus::Unresolved
        });
    }

    if !rule.http_body_contains.is_empty() {
        let matched = f.http_bodies.iter().any(|b| {
            let lower = b.to_lowercase();
            rule.http_body_contains
                .iter()
                .any(|pat| lower.contains(pat))
        });
        statuses.push(if matched {
            PredicateStatus::Matched
        } else if http_done {
            PredicateStatus::Contradicted
        } else {
            PredicateStatus::Unresolved
        });
    }

    if !rule.http_body_all.is_empty() {
        let matched = f.http_bodies.iter().any(|b| {
            let lower = b.to_lowercase();
            rule.http_body_all.iter().all(|pat| lower.contains(pat))
        });
        statuses.push(if matched {
            PredicateStatus::Matched
        } else if http_done {
            PredicateStatus::Contradicted
        } else {
            PredicateStatus::Unresolved
        });
    }

    if let Some(re) = &rule.http_body_regex {
        let matched = f.http_bodies.iter().any(|b| re.is_match(b));
        statuses.push(if matched {
            PredicateStatus::Matched
        } else if http_done {
            PredicateStatus::Contradicted
        } else {
            PredicateStatus::Unresolved
        });
    }

    if let Some(ep) = &rule.http_endpoint {
        let matched = f.http_endpoints.get(&ep.path).is_some_and(|body| {
            let lower = body.to_lowercase();
            ep.contains.is_empty()
                || ep
                    .contains
                    .iter()
                    .any(|pat| lower.contains(&pat.to_lowercase()))
        });
        statuses.push(if matched {
            PredicateStatus::Matched
        } else if http_done {
            PredicateStatus::Contradicted
        } else {
            PredicateStatus::Unresolved
        });
    }

    for key in &rule.attributes_present {
        let done = attribute_scanners_done(key, udp_done, api_done);
        statuses.push(if f.attributes.contains_key(key) {
            PredicateStatus::Matched
        } else if done {
            PredicateStatus::Contradicted
        } else {
            PredicateStatus::Unresolved
        });
    }

    for (key, m) in &rule.attributes {
        let done = attribute_scanners_done(key, udp_done, api_done);
        statuses.push(match f.attributes.get(key) {
            Some(val) if m.matches(val) => PredicateStatus::Matched,
            _ if done => PredicateStatus::Contradicted,
            _ => PredicateStatus::Unresolved,
        });
    }

    let total = statuses.len();
    let satisfied = statuses
        .iter()
        .filter(|s| matches!(s, PredicateStatus::Matched))
        .count();
    let contradicted = statuses
        .iter()
        .any(|s| matches!(s, PredicateStatus::Contradicted));
    let full_match = total > 0 && satisfied == total;

    let captures = if full_match {
        run_extractors(rule, f)
    } else {
        BTreeMap::new()
    };

    RuleEval {
        rule,
        full_match,
        contradicted,
        satisfied,
        total,
        captures,
    }
}

fn ports_known(ports: &[u16], f: &HostFindings) -> bool {
    if f.has_completed(ScannerKind::PortsExtendedNmap) {
        return true;
    }
    f.has_completed(ScannerKind::PortsFast) && ports.iter().all(|p| FAST_CORE_PORTS.contains(p))
}

fn attribute_scanners_done(key: &str, udp_done: bool, api_done: bool) -> bool {
    if key.starts_with("daikin.") {
        udp_done && api_done
    } else {
        api_done
    }
}

fn run_extractors(rule: &CompiledRule, f: &HostFindings) -> BTreeMap<String, String> {
    let mut captures = BTreeMap::new();
    for ex in &rule.extractors {
        let extracted = match ex.source {
            ExtractSource::HttpBody => f.http_bodies.iter().find_map(|body| {
                ex.regex
                    .captures(body)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().trim().to_string())
            }),
            ExtractSource::HttpServer => f.http_server.as_deref().and_then(|s| {
                ex.regex
                    .captures(s)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().trim().to_string())
            }),
            ExtractSource::HttpTitle => f.http_title.as_deref().and_then(|t| {
                ex.regex
                    .captures(t)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().trim().to_string())
            }),
            ExtractSource::Hostname => f.hostname.as_deref().and_then(|h| {
                ex.regex
                    .captures(h)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().trim().to_string())
            }),
        };

        if let Some(val) = extracted
            && !val.is_empty()
        {
            captures.insert(ex.target.clone(), val);
        }
    }
    captures
}

fn materialize_output(
    rule: &CompiledRule,
    f: &HostFindings,
    captures: &BTreeMap<String, String>,
) -> MaterializedOutput {
    let render = |opt: &Option<String>| opt.as_deref().map(|tpl| render_template(tpl, f, captures));

    MaterializedOutput {
        device_type: rule.output.device_type,
        device_name: render(&rule.output.device_name),
        vendor: render(&rule.output.vendor),
        model: render(&rule.output.model),
        notes: render(&rule.output.notes),
    }
}

fn render_template(
    template: &str,
    f: &HostFindings,
    captures: &BTreeMap<String, String>,
) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('}') {
            let expr = &after[..end];
            let (key, default_val) = match expr.split_once('|') {
                Some((k, d)) => (k.trim(), Some(d)),
                None => (expr.trim(), None),
            };
            let resolved = resolve_placeholder(key, f, captures)
                .filter(|v| !v.is_empty())
                .or_else(|| default_val.map(|d| d.to_string()))
                .unwrap_or_default();
            out.push_str(&resolved);
            rest = &after[end + 1..];
        } else {
            out.push('{');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

fn resolve_placeholder(
    key: &str,
    f: &HostFindings,
    captures: &BTreeMap<String, String>,
) -> Option<String> {
    if let Some(v) = captures.get(key) {
        return Some(v.clone());
    }
    if let Some(v) = f.attributes.get(key) {
        return Some(v.clone());
    }
    match key {
        "hostname" => f.hostname.clone(),
        "vendor" => f.vendor.clone(),
        "ip" => Some(f.ip.to_string()),
        "http.title" => f.http_title.clone(),
        "http.server" => f.http_server.clone(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn base_findings(ip_last: u8) -> HostFindings {
        HostFindings::from_device(&Device::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, ip_last)),
            "192.168.1.0/24",
        ))
    }

    fn default_engine() -> RuleEngine {
        RuleEngine::new(CompiledRuleset::from_embedded().expect("embedded TOML must compile"))
    }

    #[test]
    fn embedded_ruleset_loads_cleanly() {
        let ruleset = CompiledRuleset::from_embedded().expect("valid embedded TOML");
        assert!(!ruleset.rules.is_empty());
        assert!(
            ruleset
                .http_endpoints
                .iter()
                .any(|e| e.port == 9100 && e.path == "/metrics")
        );
    }

    #[test]
    fn short_circuits_at_stage_1_for_unambiguous_roomba() {
        let engine = default_engine();
        let mut f = base_findings(238);
        f.hostname = Some("Roomba-3174492451018780.localdomain".to_string());
        f.vendor = Some("AzureWave / iRobot".to_string());
        f.completed_scanners.insert(ScannerKind::ArpOuiRdns);

        let remaining = &ScannerKind::ordered_stages()[1..];
        let outcome = engine.evaluate(&f, remaining);
        match outcome {
            EvaluationOutcome::Conclusive { rule_id, output } => {
                assert_eq!(rule_id, "irobot_roomba_host");
                assert_eq!(output.device_type, DeviceType::Appliance);
                assert_eq!(output.device_name.as_deref(), Some("iRobot Roomba Vacuum"));
            }
            other => panic!("Expected Conclusive at Stage 1, got {:?}", other),
        }
    }

    #[test]
    fn lookahead_guard_waits_for_higher_priority_cast_rule() {
        let engine = default_engine();
        let mut f = base_findings(194);
        f.hostname = Some("Nest-Audio.localdomain".to_string());
        f.vendor = Some("Google".to_string());
        f.completed_scanners.insert(ScannerKind::ArpOuiRdns);

        // google_nest_hostname_fallback (priority 70) matches, but google_cast_speaker (100)
        // is not contradicted and awaits ApiProtocols -> must stay Pending!
        let remaining = &ScannerKind::ordered_stages()[1..];
        assert!(matches!(
            engine.evaluate(&f, remaining),
            EvaluationOutcome::Pending
        ));

        // Simulate Stage 5 returning Cast info
        f.add_port(8008);
        f.completed_scanners.insert(ScannerKind::PortsFast);
        f.completed_scanners.insert(ScannerKind::UdpDiscovery);
        f.completed_scanners.insert(ScannerKind::Http);
        f.attributes
            .insert("cast.name".to_string(), "Living Room speaker".to_string());
        f.completed_scanners.insert(ScannerKind::ApiProtocols);

        match engine.evaluate(&f, &[ScannerKind::PortsExtendedNmap]) {
            EvaluationOutcome::Conclusive { rule_id, output } => {
                assert_eq!(rule_id, "google_cast_speaker");
                assert_eq!(output.device_type, DeviceType::Entertainment);
                assert_eq!(output.device_name.as_deref(), Some("Living Room speaker"));
            }
            other => panic!("Expected Conclusive Cast match, got {:?}", other),
        }
    }

    #[test]
    fn classifies_daikin_via_udp_before_http_and_nmap() {
        let engine = default_engine();
        let mut f = base_findings(31);
        f.vendor = Some("Murata Manufacturing".to_string());
        f.completed_scanners.insert(ScannerKind::ArpOuiRdns);
        assert!(matches!(
            engine.evaluate(&f, &ScannerKind::ordered_stages()[1..]),
            EvaluationOutcome::Pending
        ));

        f.add_port(80);
        f.completed_scanners.insert(ScannerKind::PortsFast);
        f.attributes
            .insert("daikin.name".to_string(), "Living room".to_string());
        f.attributes
            .insert("daikin.unit_type".to_string(), "GPF".to_string());
        f.attributes
            .insert("daikin.cdev".to_string(), "RA".to_string());
        f.attributes
            .insert("daikin.protocol".to_string(), "DGC".to_string());
        f.attributes
            .insert("daikin.ver".to_string(), "2.6.2".to_string());
        f.attributes
            .insert("daikin.ssid".to_string(), "DaikinAP41424".to_string());
        f.completed_scanners.insert(ScannerKind::UdpDiscovery);

        match engine.evaluate(&f, &ScannerKind::ordered_stages()[3..]) {
            EvaluationOutcome::Conclusive { rule_id, output } => {
                assert_eq!(rule_id, "daikin_room_ac");
                assert_eq!(output.device_type, DeviceType::Climate);
                assert_eq!(output.vendor.as_deref(), Some("Daikin"));
                assert_eq!(
                    output.device_name.as_deref(),
                    Some("Daikin AC - Living room")
                );
                assert_eq!(
                    output.model.as_deref(),
                    Some("Daikin Room Air Conditioner (DGC Wi-Fi Adapter)")
                );
            }
            other => panic!(
                "Expected Conclusive Daikin match at UDP stage, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn extracts_unifi_and_yamaha_models_from_http() {
        let engine = default_engine();

        let mut unifi = base_findings(1);
        unifi.vendor = Some("Ubiquiti".to_string());
        unifi.is_gateway = true;
        unifi.http_bodies.push(
            r#"<script>window.UNIFI_OS_MANIFEST = {"model":{"shortName":"UDM-Pro"}};</script>"#
                .to_string(),
        );
        unifi.completed_scanners.insert(ScannerKind::ArpOuiRdns);
        unifi.completed_scanners.insert(ScannerKind::Http);
        match engine.evaluate(&unifi, &[]) {
            EvaluationOutcome::Conclusive { rule_id, output } => {
                assert_eq!(rule_id, "unifi_os_manifest");
                assert_eq!(output.device_name.as_deref(), Some("UniFi UDM-Pro"));
                assert_eq!(output.model.as_deref(), Some("Ubiquiti UDM-Pro"));
            }
            other => panic!("Expected UniFi manifest extraction, got {:?}", other),
        }

        let mut yamaha = base_findings(228);
        yamaha.http_server = Some("Network_Module/1.0 (YSP-1600)".to_string());
        yamaha.completed_scanners.insert(ScannerKind::ArpOuiRdns);
        yamaha.completed_scanners.insert(ScannerKind::Http);
        match engine.evaluate(&yamaha, &[]) {
            EvaluationOutcome::Conclusive { rule_id, output } => {
                assert_eq!(rule_id, "yamaha_musiccast_http");
                assert_eq!(output.device_type, DeviceType::Entertainment);
                assert_eq!(output.model.as_deref(), Some("Yamaha YSP-1600 (MusicCast)"));
            }
            other => panic!("Expected Yamaha extraction, got {:?}", other),
        }
    }

    #[test]
    fn handles_ambiguous_ties_best_guess_and_unidentified_hosts() {
        let custom_toml = r#"
[meta]
schema_version = 1

[[rule]]
id = "rule_a"
priority = 90
conclusive = true
[rule.match]
vendor_contains = ["acme"]
[rule.output]
device_type = "Appliance"
device_name = "Acme Device A"

[[rule]]
id = "rule_b"
priority = 90
conclusive = true
[rule.match]
ports_any = [80]
[rule.output]
device_type = "Server"
device_name = "Acme Server B"
"#;
        let engine = RuleEngine::new(CompiledRuleset::from_toml_str(custom_toml).unwrap());
        let mut tied = base_findings(50);
        tied.vendor = Some("Acme Corp".to_string());
        tied.add_port(80);
        tied.completed_scanners.insert(ScannerKind::ArpOuiRdns);
        tied.completed_scanners.insert(ScannerKind::PortsFast);

        // Should stay Pending while stages remain, then finalize as Ambiguous
        assert!(matches!(
            engine.evaluate(&tied, &[ScannerKind::Http]),
            EvaluationOutcome::Pending
        ));
        match engine.evaluate(&tied, &[]) {
            EvaluationOutcome::Finalized {
                status,
                certainty,
                matched_rules,
                ..
            } => {
                assert_eq!(status, IdentificationStatus::Ambiguous);
                assert!((30..100).contains(&certainty));
                assert_eq!(matched_rules, vec!["rule_a", "rule_b"]);
            }
            other => panic!("Expected Ambiguous finalization, got {:?}", other),
        }

        // Completely unknown host -> Unidentified 0%
        let unknown = base_findings(250);
        match engine.evaluate(&unknown, &[]) {
            EvaluationOutcome::Finalized {
                status, certainty, ..
            } => {
                assert_eq!(status, IdentificationStatus::Unidentified);
                assert_eq!(certainty, 0);
            }
            other => panic!("Expected Unidentified, got {:?}", other),
        }
    }
}
