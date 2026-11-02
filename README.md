# netscan

**netscan** is an extensible, high-performance network topology scanner and documentation tool built in idiomatic Rust. It automatically discovers active hosts across local subnets, fingerprints devices using multi-protocol inspection (HTTP, Google Cast, HomeWizard, MAC OUI, TLS), traces upstream network paths between the default gateway and the Internet, and produces both a Markdown documentation report and a Mermaid network diagram.

---

## Features

- **Asynchronous Concurrency with Tokio:** Uses Tokio green threads and semaphores for high-throughput port sweeping and asynchronous host probing without overwhelming network buffers.
- **Pluggable Architecture (Trait & Strategy Patterns):** An extensible `NetworkScanner` trait supports:
  - `Native`: Pure Tokio async TCP socket and ICMP probing with zero external tool dependencies.
  - `Nmap`: Asynchronously orchestrates `nmap` via `tokio::process::Command` when deep inspection is desired.
  - `Hybrid` *(Default)*: Rapid native Tokio sweeps combined with ARP cache reading and Nmap enrichment.
- **Multi-Protocol Fingerprinting Pipeline:**
  - **Reqwest HTTP Client:** Queries web servers, extracts HTML `<title>` tags, `Server` headers, UniFi OS manifests (`UCG-Max`), ASUSWRT status, Zyxel CPE indicators, and Prometheus metrics.
  - **Google Cast Prober:** Queries eureka_info (`:8008`) to resolve device names (e.g. *Living Room TV*, *Living Room speaker*).
  - **HomeWizard REST API:** Queries `/api` on smart energy plugs and P1 utility meters.
  - **MAC OUI Database:** Identifies hardware manufacturers and handles randomized/locally administered MACs.
- **Upstream Path Tracing:** Maps intermediate subnets (e.g., Double-NAT `192.168.0.0/24`) and carrier hops between the primary LAN gateway and the public Internet.
- **Chrono Timestamping:** Accurately timestamps all generated documentation.
- **Clap CLI Interface:** Subcommand-based CLI (`netscan scan [OPTIONS]`).

---

## Installation & Compilation

```bash
# Debug build
cargo build

# Optimized release build
cargo build --release
```

The compiled binaries will be available at [`target/debug/netscan`](file:///home/vgobbo/topology/target/debug/netscan) and [`target/release/netscan`](file:///home/vgobbo/topology/target/release/netscan).

---

## Usage

### 1. Default Scan (Auto-Detect Local Subnets & Upstream Gateway)
```bash
cargo run -- scan
# Or using the compiled release binary:
./target/release/netscan scan
```

### 2. Scan Specific Subnets
```bash
./target/release/netscan scan -t 192.168.1.0/24 -t 192.168.0.0/24
```

### 3. Choose a Backend Engine
```bash
# Pure Native Rust Engine
./target/release/netscan scan --backend native

# Nmap Engine
./target/release/netscan scan --backend nmap

# Hybrid Engine (Default)
./target/release/netscan scan --backend hybrid
```

### 4. Custom Output Paths
```bash
./target/release/netscan scan --output-dir ./reports --output-md topology.md --output-mmd diagram.mmd --output-json topology.json
```

### 5. View Full Help Options
```bash
./target/release/netscan scan --help
```

---

## Output Artifacts

Running `netscan scan` generates:
1. [`network_summary.md`](file:///home/vgobbo/topology/network_summary.md): Markdown report containing executive summary, upstream network path, embedded Mermaid diagram, and complete device inventory table.
2. [`network_diagram.mmd`](file:///home/vgobbo/topology/network_diagram.mmd): Standalone Mermaid diagram showing network zones, device types, and device names (with IP and MAC addresses omitted).
3. [`network_topology.json`](file:///home/vgobbo/topology/network_topology.json): Complete machine-readable JSON representation of the network topology, discovered devices, open ports, fingerprinted attributes, and upstream hops.
