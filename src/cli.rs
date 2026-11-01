use clap::{Args, Parser, Subcommand, ValueEnum};

/// netscan: Automated Network Topology Scanner and Documentation Tool
#[derive(Parser, Debug)]
#[command(
    name = "netscan",
    author = "vgobbo",
    version = "0.1.0",
    about = "Automated Network Topology Scanner & Mapper",
    long_about = "Fast, asynchronous network topology mapper that identifies all local devices, upstream networks between gateway and Internet, and generates Mermaid diagrams and Markdown documentation."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan the network, discover devices, and generate topology documentation
    Scan(ScanArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ScanArgs {
    /// Target CIDR network(s) to scan (e.g. 192.168.1.0/24).
    /// If omitted, netscan automatically detects the local LAN and upstream gateway subnet.
    #[arg(short, long)]
    pub target: Vec<String>,

    /// Scanning engine backend to use
    #[arg(short, long, value_enum, default_value_t = BackendChoice::Hybrid)]
    pub backend: BackendChoice,

    /// Connection probe timeout in milliseconds
    #[arg(long, default_value_t = 1500)]
    pub timeout_ms: u64,

    /// Maximum concurrency for asynchronous scanning tasks
    #[arg(long, default_value_t = 128)]
    pub concurrency: usize,

    /// Output directory for generated reports and diagrams
    #[arg(short, long, default_value = ".")]
    pub output_dir: String,

    /// Markdown report file name
    #[arg(long, default_value = "network_summary.md")]
    pub output_md: String,

    /// Standalone Mermaid diagram file name
    #[arg(long, default_value = "network_diagram.mmd")]
    pub output_mmd: String,

    /// Skip tracing upstream hops to the public Internet
    #[arg(long)]
    pub skip_upstream: bool,

    /// Enable verbose / debug logging
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BackendChoice {
    /// Pure native async Rust scanner using Tokio TCP/HTTP sockets
    Native,
    /// Nmap-based scanner (invokes nmap CLI asynchronously)
    Nmap,
    /// Hybrid engine: combines fast native async sweeps with Nmap enrichment
    #[default]
    Hybrid,
}
