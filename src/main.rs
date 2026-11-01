use anyhow::{Context, Result};
use clap::Parser;
use ipnetwork::IpNetwork;
use std::fs;
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
use model::NetworkTopology;
use net::InterfaceDetector;
use report::{MarkdownSummaryGenerator, MermaidGenerator};
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

    // 2. Resolve Target Networks
    let targets = resolve_targets(&args.target)?;
    let target_strs: Vec<String> = targets.iter().map(|t| t.to_string()).collect();
    info!("Target networks to scan: {}", target_strs.join(", "));

    // 3. Initialize Scanner Engine
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

    // 4. Execute Network Scan
    let mut devices = scanner.scan_network(&targets).await?;
    info!("Discovered {} active host(s)", devices.len());

    // 5. Device Fingerprinting Pipeline
    info!("Fingerprinting devices via HTTP, Google Cast, and MAC OUI...");
    let pipeline = FingerprintPipeline::new(args.concurrency);
    pipeline.enrich_all(&mut devices).await;
    info!("Device fingerprinting completed");

    // 6. Upstream Path Trace (Between Gateway and Internet)
    let upstream_path = if !args.skip_upstream {
        let tracer = UpstreamTracer::new();
        match tracer.trace().await {
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

    // 7. Build Topology Model
    let local_subnets = targets.iter().map(|t| t.to_string()).collect();
    let mut topology = NetworkTopology::new(local_subnets);
    topology.devices = devices;
    topology.upstream = upstream_path;

    // 8. Generate Reports
    info!("Generating network diagram and documentation...");
    let mermaid_diagram = MermaidGenerator::generate(&topology);
    let markdown_summary = MarkdownSummaryGenerator::generate(&topology);

    // 9. Write Output Files
    let out_dir = Path::new(&args.output_dir);
    if !out_dir.exists() {
        fs::create_dir_all(out_dir)
            .context(format!("Failed to create output directory {:?}", out_dir))?;
    }

    let md_path = out_dir.join(&args.output_md);
    let mmd_path = out_dir.join(&args.output_mmd);

    fs::write(&md_path, &markdown_summary)
        .context(format!("Failed to write markdown report to {:?}", md_path))?;
    fs::write(&mmd_path, &mermaid_diagram)
        .context(format!("Failed to write mermaid diagram to {:?}", mmd_path))?;

    info!("Scan complete! Artifacts generated successfully:");
    info!("  - Markdown report: {}", md_path.display());
    info!("  - Mermaid diagram: {}", mmd_path.display());

    Ok(())
}

/// Resolves target subnets from CLI arguments or auto-detects local LAN and intermediate gateway subnets.
fn resolve_targets(cli_targets: &[String]) -> Result<Vec<IpNetwork>> {
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

    // Auto-detection mode
    let mut detected = Vec::new();

    // 1. Auto-detect primary LAN interface (e.g. 192.168.1.0/24)
    if let Ok(primary) = InterfaceDetector::detect_primary() {
        let base_net = IpNetwork::new(primary.network.network(), primary.prefix_len)
            .unwrap_or(primary.network);
        detected.push(base_net);

        // 2. Auto-include intermediate upstream gateway network (e.g. 192.168.0.0/24)
        if primary.network.network().to_string() == "192.168.1.0" {
            if let Ok(interconnect) = "192.168.0.0/24".parse::<IpNetwork>() {
                detected.push(interconnect);
            }
        }
    }

    if detected.is_empty() {
        // Fallback default
        let default_net: IpNetwork = "192.168.1.0/24".parse().unwrap();
        detected.push(default_net);
    }

    Ok(detected)
}
