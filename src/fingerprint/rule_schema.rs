use crate::fingerprint::findings::{HttpEndpointSpec, ScannerKind};
use crate::model::DeviceType;
use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

pub const DEFAULT_RULES_TOML: &str = include_str!("../../rules/fingerprints.toml");

const FAST_CORE_PORTS: &[u16] = &[80, 443, 22, 8008, 8080, 8443, 8883, 9100];

#[derive(Debug, Clone, Deserialize)]
pub struct RulesConfig {
    pub meta: MetaConfig,
    #[serde(default)]
    pub oui: Vec<OuiEntry>,
    #[serde(default)]
    pub rule: Vec<RuleDef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetaConfig {
    pub schema_version: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OuiEntry {
    pub prefix: String,
    pub vendor: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleDef {
    pub id: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: u16,
    #[serde(default = "default_conclusive")]
    pub conclusive: bool,
    #[serde(default)]
    pub requires_scanners: Vec<ScannerKind>,
    #[serde(rename = "match")]
    pub match_cond: MatchConditions,
    #[serde(default)]
    pub extract: Vec<ExtractorDef>,
    pub output: RuleOutput,
}

fn default_priority() -> u16 {
    50
}

fn default_conclusive() -> bool {
    true
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MatchConditions {
    pub hostname: Option<StringMatcherDef>,
    #[serde(default)]
    pub hostname_contains: Vec<String>,
    pub hostname_not_empty: Option<bool>,
    pub vendor: Option<StringMatcherDef>,
    #[serde(default)]
    pub vendor_contains: Vec<String>,
    pub is_gateway: Option<bool>,
    #[serde(default)]
    pub ports_any: Vec<u16>,
    #[serde(default)]
    pub ports_all: Vec<u16>,
    #[serde(default)]
    pub ports_none: Vec<u16>,
    pub http_title: Option<StringMatcherDef>,
    #[serde(default)]
    pub http_title_contains: Vec<String>,
    pub http_server: Option<StringMatcherDef>,
    #[serde(default)]
    pub http_server_contains: Vec<String>,
    #[serde(default)]
    pub http_body_contains: Vec<String>,
    #[serde(default)]
    pub http_body_all: Vec<String>,
    pub http_body_regex: Option<String>,
    pub http_endpoint: Option<HttpEndpointDef>,
    #[serde(default)]
    pub attributes_present: Vec<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, StringMatcherDef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StringMatcherDef {
    pub equals: Option<String>,
    pub contains: Option<String>,
    pub starts_with: Option<String>,
    pub regex: Option<String>,
    #[serde(default)]
    pub case_sensitive: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpEndpointDef {
    pub port: u16,
    pub path: String,
    #[serde(default)]
    pub contains: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtractSource {
    HttpBody,
    HttpServer,
    HttpTitle,
    Hostname,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExtractorDef {
    pub source: ExtractSource,
    pub pattern: String,
    pub target: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleOutput {
    pub device_type: DeviceType,
    pub device_name: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub notes: Option<String>,
}

/// Precompiled string matcher with eager regex validation.
#[derive(Debug, Clone)]
pub struct CompiledStringMatcher {
    pub equals: Option<String>,
    pub contains: Option<String>,
    pub starts_with: Option<String>,
    pub regex: Option<Regex>,
    pub case_sensitive: bool,
}

impl CompiledStringMatcher {
    pub fn compile(def: &StringMatcherDef, ctx: &str) -> Result<Self> {
        let regex = match &def.regex {
            Some(pat) => {
                let full_pat = if def.case_sensitive {
                    pat.clone()
                } else {
                    format!("(?i){}", pat)
                };
                Some(
                    Regex::new(&full_pat)
                        .with_context(|| format!("Invalid regex '{}' in {}", pat, ctx))?,
                )
            }
            None => None,
        };

        Ok(Self {
            equals: def.equals.clone(),
            contains: def.contains.clone(),
            starts_with: def.starts_with.clone(),
            regex,
            case_sensitive: def.case_sensitive,
        })
    }

    pub fn matches(&self, value: &str) -> bool {
        let cmp_val;
        let v = if self.case_sensitive {
            value
        } else {
            cmp_val = value.to_lowercase();
            &cmp_val
        };

        if let Some(eq) = &self.equals {
            let target = if self.case_sensitive {
                eq.clone()
            } else {
                eq.to_lowercase()
            };
            if v != target {
                return false;
            }
        }
        if let Some(sub) = &self.contains {
            let target = if self.case_sensitive {
                sub.clone()
            } else {
                sub.to_lowercase()
            };
            if !v.contains(&target) {
                return false;
            }
        }
        if let Some(prefix) = &self.starts_with {
            let target = if self.case_sensitive {
                prefix.clone()
            } else {
                prefix.to_lowercase()
            };
            if !v.starts_with(&target) {
                return false;
            }
        }
        if let Some(re) = &self.regex
            && !re.is_match(value)
        {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct CompiledExtractor {
    pub source: ExtractSource,
    pub regex: Regex,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub priority: u16,
    pub conclusive: bool,
    pub requires_scanners: Vec<ScannerKind>,
    pub hostname: Option<CompiledStringMatcher>,
    pub hostname_contains: Vec<String>,
    pub hostname_not_empty: Option<bool>,
    pub vendor: Option<CompiledStringMatcher>,
    pub vendor_contains: Vec<String>,
    pub is_gateway: Option<bool>,
    pub ports_any: Vec<u16>,
    pub ports_all: Vec<u16>,
    pub ports_none: Vec<u16>,
    pub http_title: Option<CompiledStringMatcher>,
    pub http_title_contains: Vec<String>,
    pub http_server: Option<CompiledStringMatcher>,
    pub http_server_contains: Vec<String>,
    pub http_body_contains: Vec<String>,
    pub http_body_all: Vec<String>,
    pub http_body_regex: Option<Regex>,
    pub http_endpoint: Option<HttpEndpointDef>,
    pub attributes_present: Vec<String>,
    pub attributes: BTreeMap<String, CompiledStringMatcher>,
    pub extractors: Vec<CompiledExtractor>,
    pub output: RuleOutput,
}

#[derive(Debug, Clone)]
pub struct CompiledRuleset {
    pub schema_version: u32,
    pub custom_oui: Vec<(String, String)>,
    pub rules: Vec<CompiledRule>,
    pub http_endpoints: Vec<HttpEndpointSpec>,
}

impl CompiledRuleset {
    /// Loads and compiles the embedded default TOML ruleset.
    pub fn from_embedded() -> Result<Self> {
        Self::from_toml_str(DEFAULT_RULES_TOML)
            .context("Failed to load embedded default fingerprints.toml")
    }

    /// Loads and compiles a custom TOML ruleset from disk.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read rules file {:?}", path))?;
        Self::from_toml_str(&content)
            .with_context(|| format!("Failed to parse rules file {:?}", path))
    }

    /// Parses and compiles a TOML ruleset string, validating all regexes and rule IDs.
    pub fn from_toml_str(toml_str: &str) -> Result<Self> {
        let cfg: RulesConfig =
            toml::from_str(toml_str).context("Invalid TOML syntax in ruleset")?;

        let custom_oui = cfg
            .oui
            .into_iter()
            .map(|entry| {
                let clean: String = entry
                    .prefix
                    .chars()
                    .filter(|c| c.is_ascii_hexdigit())
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                (clean, entry.vendor)
            })
            .collect();

        let mut seen_ids = HashSet::new();
        let mut rules = Vec::with_capacity(cfg.rule.len());
        let mut http_endpoints: Vec<HttpEndpointSpec> = Vec::new();

        for r in cfg.rule {
            if !seen_ids.insert(r.id.clone()) {
                anyhow::bail!("Duplicate rule id '{}' in TOML ruleset", r.id);
            }

            if let Some(ep) = &r.match_cond.http_endpoint {
                let spec = HttpEndpointSpec {
                    port: ep.port,
                    path: ep.path.clone(),
                };
                if !http_endpoints.contains(&spec) {
                    http_endpoints.push(spec);
                }
            }

            let compiled = compile_rule(r)?;
            rules.push(compiled);
        }

        // Sort rules descending by priority so evaluation inspects highest tiers first
        rules.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));

        Ok(Self {
            schema_version: cfg.meta.schema_version,
            custom_oui,
            rules,
            http_endpoints,
        })
    }
}

fn compile_rule(def: RuleDef) -> Result<CompiledRule> {
    let ctx = format!("rule '{}'", def.id);
    let m = def.match_cond;

    let hostname = m
        .hostname
        .as_ref()
        .map(|s| CompiledStringMatcher::compile(s, &ctx))
        .transpose()?;
    let vendor = m
        .vendor
        .as_ref()
        .map(|s| CompiledStringMatcher::compile(s, &ctx))
        .transpose()?;
    let http_title = m
        .http_title
        .as_ref()
        .map(|s| CompiledStringMatcher::compile(s, &ctx))
        .transpose()?;
    let http_server = m
        .http_server
        .as_ref()
        .map(|s| CompiledStringMatcher::compile(s, &ctx))
        .transpose()?;
    let http_body_regex = m
        .http_body_regex
        .as_deref()
        .map(|p| Regex::new(p).with_context(|| format!("Invalid http_body_regex in {}", ctx)))
        .transpose()?;

    let mut attributes = BTreeMap::new();
    for (k, v) in &m.attributes {
        attributes.insert(k.clone(), CompiledStringMatcher::compile(v, &ctx)?);
    }

    let mut extractors = Vec::with_capacity(def.extract.len());
    for ex in def.extract {
        let regex = Regex::new(&ex.pattern)
            .with_context(|| format!("Invalid extract regex '{}' in {}", ex.pattern, ctx))?;
        extractors.push(CompiledExtractor {
            source: ex.source,
            regex,
            target: ex.target,
        });
    }

    let requires_scanners = if def.requires_scanners.is_empty() {
        infer_required_scanners(&m, &attributes)
    } else {
        def.requires_scanners
    };

    Ok(CompiledRule {
        id: def.id,
        priority: def.priority,
        conclusive: def.conclusive,
        requires_scanners,
        hostname,
        hostname_contains: m
            .hostname_contains
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect(),
        hostname_not_empty: m.hostname_not_empty,
        vendor,
        vendor_contains: m
            .vendor_contains
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect(),
        is_gateway: m.is_gateway,
        ports_any: m.ports_any,
        ports_all: m.ports_all,
        ports_none: m.ports_none,
        http_title,
        http_title_contains: m
            .http_title_contains
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect(),
        http_server,
        http_server_contains: m
            .http_server_contains
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect(),
        http_body_contains: m
            .http_body_contains
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect(),
        http_body_all: m
            .http_body_all
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect(),
        http_body_regex,
        http_endpoint: m.http_endpoint,
        attributes_present: m.attributes_present,
        attributes,
        extractors,
        output: def.output,
    })
}

fn infer_required_scanners(
    m: &MatchConditions,
    attrs: &BTreeMap<String, CompiledStringMatcher>,
) -> Vec<ScannerKind> {
    let mut set = Vec::new();
    let mut push_unique = |kind: ScannerKind| {
        if !set.contains(&kind) {
            set.push(kind);
        }
    };

    if m.hostname.is_some()
        || !m.hostname_contains.is_empty()
        || m.hostname_not_empty.is_some()
        || m.vendor.is_some()
        || !m.vendor_contains.is_empty()
        || m.is_gateway.is_some()
    {
        push_unique(ScannerKind::ArpOuiRdns);
    }

    let all_ports = m
        .ports_any
        .iter()
        .chain(m.ports_all.iter())
        .chain(m.ports_none.iter());
    for &p in all_ports {
        if FAST_CORE_PORTS.contains(&p) {
            push_unique(ScannerKind::PortsFast);
        } else {
            push_unique(ScannerKind::PortsExtendedNmap);
        }
    }

    if m.http_title.is_some()
        || !m.http_title_contains.is_empty()
        || m.http_server.is_some()
        || !m.http_server_contains.is_empty()
        || !m.http_body_contains.is_empty()
        || !m.http_body_all.is_empty()
        || m.http_body_regex.is_some()
        || m.http_endpoint.is_some()
    {
        push_unique(ScannerKind::Http);
    }

    for key in m.attributes_present.iter().chain(attrs.keys()) {
        if key.starts_with("daikin.") {
            push_unique(ScannerKind::UdpDiscovery);
        } else {
            push_unique(ScannerKind::ApiProtocols);
        }
    }

    set
}
