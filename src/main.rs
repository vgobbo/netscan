use anyhow::{Context, Result};
use clap::Parser;
use ipnetwork::IpNetwork;
use std::fs;
use std::path::Path;
use tracing::Level;
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

    println!("============================================================");
    println!("       netscan - Automated Network Topology Mapper          ");
    println!("============================================================");

    // 2. Resolve Target Networks
    let targets = resolve_targets(&args.target)?;
    println!("[+] Target Networks to Scan:");
    for t in &targets {
        println!("    - {}", t);
    }
    println!();

    // 3. Initialize Scanner Engine
    let scanner: Box<dyn NetworkScanner> = match args.backend {
        BackendChoice::Native => {
            println!("[+] Scanner Backend: Native Tokio Async Engine");
            Box::new(NativeScanner::new(args.concurrency, args.timeout_ms))
        }
        BackendChoice::Nmap => {
            println!("[+] Scanner Backend: Nmap Backend");
            Box::new(NmapScanner::new(args.timeout_ms))
        }
        BackendChoice::Hybrid => {
            println!("[+] Scanner Backend: Hybrid (Native Async + Nmap Enrichment)");
            Box::new(HybridScanner::new(args.concurrency, args.timeout_ms))
        }
    };

    // 4. Execute Network Scan
    println!("[*] Discovering and probing active hosts...");
    let mut devices = scanner.scan_network(&targets).await?;
    println!("[+] Discovered {} active host(s).", devices.len());
    println!();

    // 5. Device Fingerprinting Pipeline
    println!("[*] Fingerprinting devices via HTTP, Google Cast, and MAC OUI...");
    let pipeline = FingerprintPipeline::new(args.concurrency);
    pipeline.enrich_all(&mut devices).await;
    println!("[+] Fingerprinting completed.");
    println!();

    // 6. Upstream Path Trace (Between Gateway and Internet)
    let upstream_path = if !args.skip_upstream {
        println!("[*] Tracing upstream network hops between gateway and Internet...");
        let tracer = UpstreamTracer::new();
        match tracer.trace().await {
            Ok(p) => {
                println!(
                    "[+] Upstream path identified: Public IP {:?}, {} intermediate hop(s).",
                    p.public_ip,
                    p.hops.len()
                );
                p
            }
            Err(e) => {
                eprintln!("[!] Warning: Could not trace upstream hops: {}", e);
                Default::default()
            }
        }
    } else {
        println!("[*] Skipping upstream traceroute (--skip-upstream set).");
        Default::default()
    };
    println!();

    // 7. Build Topology Model
    let local_subnets = targets.iter().map(|t| t.to_string()).collect();
    let mut topology = NetworkTopology::new(local_subnets);
    topology.devices = devices;
    topology.upstream = upstream_path;

    // 8. Generate Reports
    println!("[*] Generating network diagram and documentation...");
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

    println!("============================================================");
    println!("[+] Scan Complete! Artifacts generated successfully:");
    println!("    - Markdown Report: {}", md_path.display());
    println!("    - Mermaid Diagram: {}", mmd_path.display());
    println!("============================================================");

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
