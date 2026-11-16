use anyhow::{Context, Result};
use clap::Parser;
use ipnetwork::IpNetwork;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use tracing::{Level, info, warn};
use tracing_subscriber::FmtSubscriber;

mod cli;
mod fingerprint;
mod model;
mod net;
mod report;
mod scanner;
mod upstream;

use cli::{BackendChoice, Cli, Commands, ScanArgs};
use fingerprint::FingerprintPipeline;
use fingerprint::rule_schema::CompiledRuleset;
use model::NetworkTopology;
use net::InterfaceDetector;
use report::{HtmlViewerGenerator, JsonGenerator, MarkdownSummaryGenerator, MermaidGenerator};
use scanner::{HybridScanner, NativeScanner, NetworkScanner, NmapScanner};
use upstream::UpstreamTracer;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => run_scan(args).await?,
    }

    Ok(())
}

async fn run_scan(args: ScanArgs) -> Result<()> {
    // 1. Initialize Logging
    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    info!(
        "Starting netscan v{} - Automated Network Topology Mapper",
        env!("CARGO_PKG_VERSION")
    );

    // 2. Discover Local Network Interface and Default Route
    let primary_info = InterfaceDetector::detect_primary().ok();
    let primary_net = primary_info
        .as_ref()
        .map(|p| IpNetwork::new(p.network.network(), p.prefix_len).unwrap_or(p.network));
    let default_gateway = primary_info
        .as_ref()
        .and_then(|p| p.gateway.map(IpAddr::V4));

    if let (Some(net), Some(gw)) = (&primary_net, &default_gateway) {
        info!(
            "Primary network interface: {} (default gateway: {})",
            net, gw
        );
    }

    // 3. Upstream Path Trace (Between Gateway and Internet)
    // Run upstream trace before target scanning to auto-discover intermediate subnets dynamically
    let upstream_path = if !args.skip_upstream {
        let tracer = UpstreamTracer::new();
        match tracer.trace(primary_net.as_ref(), default_gateway).await {
            Ok(p) => {
                info!(
                    "Upstream path identified: Public IP {:?}, {} intermediate hop(s)",
                    p.public_ip,
                    p.hops.len()
                );
                p
            }
            Err(e) => {
                warn!("Could not trace upstream hops: {}", e);
                Default::default()
            }
        }
    } else {
        info!("Skipping upstream traceroute (--skip-upstream set)");
        Default::default()
    };

    // 4. Resolve Target Networks Dynamically
    let targets = resolve_targets(
        &args.target,
        primary_net.as_ref(),
        &upstream_path.intermediate_subnets,
    )?;
    let target_strs: Vec<String> = targets.iter().map(|t| t.to_string()).collect();
    info!("Target networks to scan: {}", target_strs.join(", "));

    // 5. Load TOML Fingerprinting Ruleset
    let ruleset = match &args.rules {
        Some(path) => {
            info!(
                "Loading custom fingerprinting rules from {}",
                path.display()
            );
            CompiledRuleset::from_file(path)?
        }
        None => CompiledRuleset::from_embedded()?,
    };
    info!(
        "Loaded {} fingerprinting rule(s) (schema v{}, full_scan={})",
        ruleset.rules.len(),
        ruleset.schema_version,
        args.full
    );

    // 6. Initialize Scanner Engine
    let scanner: Box<dyn NetworkScanner> = match args.backend {
        BackendChoice::Native => {
            info!("Scanner backend: Native Tokio Async Engine");
            Box::new(NativeScanner::new(args.concurrency, args.timeout_ms))
        }
        BackendChoice::Nmap => {
            info!("Scanner backend: Nmap Backend");
            Box::new(NmapScanner::new(args.timeout_ms))
        }
        BackendChoice::Hybrid => {
            info!("Scanner backend: Hybrid (Native Async + Nmap Enrichment)");
            Box::new(HybridScanner::new(args.concurrency, args.timeout_ms))
        }
    };

    // 7. Execute Host Enumeration
    let mut devices = scanner.enumerate_hosts(&targets).await?;
    info!("Enumerated {} active host(s)", devices.len());

    // 8. Flag Discovered Gateways
    for dev in &mut devices {
        if Some(dev.ip) == default_gateway
            || upstream_path.hops.iter().any(|h| h.ip == Some(dev.ip))
        {
            dev.is_gateway = true;
        }
    }

    // 9. Staged Discovery & Fingerprinting Pipeline
    info!("Running staged discovery and TOML rule fingerprinting...");
    let pipeline = FingerprintPipeline::new(args.concurrency, ruleset, args.full);
    let devices = pipeline.run(&devices, scanner.as_ref()).await;
    info!("Staged fingerprinting completed");

    // 9. Build Abstract In-Memory Topology Model
    let local_subnets = targets.iter().map(|t| t.to_string()).collect();
    let mut topology = NetworkTopology::new(local_subnets);
    topology.primary_gateway = default_gateway;
    topology.devices = devices;
    topology.upstream = upstream_path;

    // 10. Generate Reports Dynamically from the Abstract Topology Model
    info!("Generating network diagram, documentation, HTML viewer, and JSON export...");
    let mermaid_diagram = MermaidGenerator::generate(&topology);
    let markdown_summary = MarkdownSummaryGenerator::generate(&topology);
    let json_export = JsonGenerator::generate(&topology)?;
    let html_viewer = HtmlViewerGenerator::generate(&topology, &mermaid_diagram);

    // 11. Write Output Files
    let out_dir = Path::new(&args.output_dir);
    if !out_dir.exists() {
        fs::create_dir_all(out_dir)
            .context(format!("Failed to create output directory {:?}", out_dir))?;
    }

    let md_path = out_dir.join(&args.output_md);
    let mmd_path = out_dir.join(&args.output_mmd);
    let json_path = out_dir.join(&args.output_json);
    let html_path = out_dir.join(&args.output_html);

    fs::write(&md_path, &markdown_summary)
        .context(format!("Failed to write markdown report to {:?}", md_path))?;
    fs::write(&mmd_path, &mermaid_diagram)
        .context(format!("Failed to write mermaid diagram to {:?}", mmd_path))?;
    fs::write(&json_path, &json_export).context(format!(
        "Failed to write JSON topology data to {:?}",
        json_path
    ))?;
    fs::write(&html_path, &html_viewer).context(format!(
        "Failed to write HTML topology viewer to {:?}",
        html_path
    ))?;

    info!("Scan complete! Artifacts generated successfully:");
    info!("  - Markdown report: {}", md_path.display());
    info!("  - Mermaid diagram: {}", mmd_path.display());
    info!("  - HTML viewer:     {}", html_path.display());
    info!("  - JSON data:       {}", json_path.display());

    Ok(())
}

/// Resolves target subnets dynamically without hardcoding assumptions.
fn resolve_targets(
    cli_targets: &[String],
    primary_net: Option<&IpNetwork>,
    intermediate_subnets: &[String],
) -> Result<Vec<IpNetwork>> {
    // If CLI targets provided, respect user input
    if !cli_targets.is_empty() {
        let mut list = Vec::new();
        for s in cli_targets {
            let net: IpNetwork = s
                .parse()
                .context(format!("Invalid CIDR network string: '{}'", s))?;
            list.push(net);
        }
        return Ok(list);
    }

    // Auto-detection mode: primary LAN + any intermediate subnets discovered upstream
    let mut detected = Vec::new();

    if let Some(primary) = primary_net {
        detected.push(*primary);
    }

    for sub_str in intermediate_subnets {
        if let Ok(net) = sub_str.parse::<IpNetwork>()
            && !detected.contains(&net)
        {
            detected.push(net);
        }
    }

    if detected.is_empty() {
        // Fallback default
        let default_net: IpNetwork = "192.168.1.0/24".parse().unwrap();
        detected.push(default_net);
    }

    Ok(detected)
}
