# AGENTS.md — Agentic Development & Contribution Guide

This document provides instructions, architectural context, and development standards for autonomous AI coding agents and human contributors working on the **`netscan`** codebase.

---

## 1. Project Overview & Mission

`netscan` is an automated, non-destructive network topology discovery and documentation tool written in idiomatic Rust. It maps connected devices across local subnets, identifies intermediate upstream networks linking the default gateway to the public Internet, and generates:
1. **Network Architecture Diagrams:** Clean Mermaid (`flowchart TD`) diagrams detailing network zones, device types, and device names (omitting IP and MAC addresses).
2. **Markdown Topology Reports:** Detailed inventory tables, hop-by-hop upstream path analysis, open port profiles, and category breakdowns.

### Cardinal Rule: Strictly Non-Destructive Operations
> **CRITICAL:** `netscan` must **only** observe and document the network.
> - Never execute network reconfiguration commands (`ip link set`, `route add/del`, DHCP changes, iptables/nftables modifications).
> - Never trigger device resets, reboot APIs, firmware flashes, or disruptive stress tests.
> - Use only passive inspection, standard TCP connect probes, safe ICMP echo, and read-only HTTP/API queries.

---

## 2. Technology Stack & Key Dependencies

| Component | Crate / Technology | Purpose |
|---|---|---|
| **Language & Edition** | Rust (Edition 2024) | High safety, performance, zero-cost abstractions |
| **Async Runtime** | `tokio` (v1.x, `features = ["full"]`) | Async I/O, green tasks, timeouts, semaphore concurrency control |
| **CLI Parser** | `clap` (v4.x, `features = ["derive"]`) | Declarative CLI interface with subcommands (`scan`) |
| **HTTP Client** | `reqwest` (v0.12.x, `rustls-tls`, `json`) | Non-destructive HTTP probing and API queries |
| **Date & Time** | `chrono` (v0.4.x, `features = ["serde"]`) | Timestamping scans and formatting report dates |
| **CIDR & Subnets** | `ipnetwork` (v0.20.x) | IP range parsing, subnet iteration, prefix handling |
| **Serialization** | `serde` / `serde_json` | JSON API parsing (Cast, HomeWizard, system routes) |
| **Error Handling** | `anyhow` & `thiserror` | Idiomatic application error handling and context |
| **Logging** | `tracing` & `tracing-subscriber` | Structured, leveled logging (`--verbose`) |

---

## 3. Architecture & Design Patterns

The codebase is structured under `src/` following clean separation of concerns and extensibility patterns:

```
src/
├── main.rs                  # CLI entry point, logging initialization, orchestration
├── cli.rs                   # Clap parser and command arguments definition
├── model.rs                 # Domain entities: Device, DeviceType, UpstreamPath, Topology
├── upstream.rs              # Gateway-to-Internet trace and intermediate subnet detection
├── net/
│   ├── mod.rs               # Network utility exports
│   ├── interface.rs         # Local interface and default route detection
│   └── arp.rs               # Kernel ARP neighbor table and local MAC reader
├── scanner/
│   ├── mod.rs               # NetworkScanner trait (Strategy Pattern)
│   ├── native.rs            # Async Tokio TCP connect & ping scanner
│   ├── nmap.rs              # Asynchronous Nmap CLI wrapper
│   └── hybrid.rs            # Hybrid scanner (Native fast sweep + Nmap enrichment)
├── fingerprint/
│   ├── mod.rs               # Fingerprinting pipeline exports
│   ├── pipeline.rs          # Parallel device enrichment orchestrator
│   ├── oui.rs               # Static and system MAC OUI vendor resolution
│   ├── http.rs              # HTTP/HTTPS header and HTML title inspection
│   ├── cast.rs              # Google Cast eureka_info API prober
│   ├── homewizard.rs        # HomeWizard local REST API prober
│   └── rules.rs             # Heuristic device classification and naming engine
└── report/
    ├── mod.rs               # Report generator exports
    ├── mermaid.rs           # Clean Mermaid flowchart generator (Visitor Pattern)
    └── markdown.rs          # Markdown inventory report generator
```

### Key Design Patterns
- **Strategy Pattern (`scanner/`):** The [`NetworkScanner`](src/scanner/mod.rs) trait defines an abstract contract (`scan_network`, `scan_ports`). New scanning engines (e.g., eBPF, raw socket SYN scan) can be added without modifying the runner.
- **Pipeline / Chain of Responsibility (`fingerprint/`):** The [`FingerprintPipeline`](src/fingerprint/pipeline.rs) runs modular probers concurrently across active hosts, feeding structured metadata into the [`RuleEngine`](src/fingerprint/rules.rs).
- **Generator Pattern (`report/`):** Report formats are decoupled from scanner data models. The [`MermaidGenerator`](src/report/mermaid.rs) formats visual topologies while [`MarkdownSummaryGenerator`](src/report/markdown.rs) compiles tabular documentation.

---

## 4. Development Commands & Workflow

Always verify your changes before submitting commits:

```bash
# 1. Format check
cargo fmt --check

# 2. Compile and check for warnings / errors (must have 0 warnings)
cargo check
cargo clippy --all-targets --all-features

# 3. Build debug and release binaries
cargo build
cargo build --release

# 4. Run automated test suite
cargo test

# 5. Run local scan test
./target/release/netscan scan
```

---

## 5. Commit & Versioning Standards

All agents and contributors must strictly adhere to **Conventional Commits 1.0** and **Semantic Versioning 2.0.0**.

### 5.1 Conventional Commits 1.0 Format
Each commit message must follow the structure:
```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

#### Allowed Types:
- `feat`: A new feature or capability (e.g., adding a new protocol prober or output format).
- `fix`: A bug fix (e.g., fixing a parsing error or classification misidentification).
- `docs`: Documentation-only changes (e.g., updating `README.md` or `AGENTS.md`).
- `refactor`: Code change that neither fixes a bug nor adds a feature.
- `perf`: A code change that improves performance or scanning throughput.
- `test`: Adding or updating test cases.
- `build`: Changes affecting the build system, Cargo dependencies, or project configuration.
- `ci`: Changes to CI/CD configuration files and scripts.
- `chore`: Maintenance tasks that do not modify `src` or test files.

#### Grouping Rule:
- **Group relevant changes** into a single cohesive commit (e.g., all files implementing a new scanner backend).
- **Split non-relevant changes** into distinct commits (e.g., do not mix documentation updates with scanner refactoring).

### 5.2 Semantic Versioning (SemVer 2.0.0)
Releases must follow `MAJOR.MINOR.PATCH` (e.g., `0.1.0` -> `0.2.0`):
- **MAJOR (`X.0.0`):** Incompatible API breaks or CLI breaking changes (e.g., removing a flag or altering the CLI contract).
- **MINOR (`0.X.0`):** Backwards-compatible new features (e.g., adding an mDNS prober or a new report format).
- **PATCH (`0.0.X`):** Backwards-compatible bug fixes and fingerprinting rule refinements.

---

## 6. Extending `netscan`: Recipes for Agents

### Recipe A: Adding a New Device Fingerprinting Rule
1. Open [`src/fingerprint/rules.rs`](src/fingerprint/rules.rs).
2. Locate the appropriate category block inside `RuleEngine::classify`.
3. Match against `hostname`, `vendor`, `device.open_ports`, or probe metadata (`http_fp`, `cast_info`, etc.).
4. Assign `device.device_type`, `device.device_name`, `device.model`, and `device.notes`.

### Recipe B: Adding a New Prober (e.g. SSDP, mDNS, SNMP)
1. Create `src/fingerprint/<protocol>.rs`.
2. Implement a prober struct with an async `probe(&Client / socket, ip)` method.
3. Export the module in [`src/fingerprint/mod.rs`](src/fingerprint/mod.rs).
4. Integrate the call into [`FingerprintPipeline::enrich_device`](src/fingerprint/pipeline.rs).
5. Feed the extracted data into [`RuleEngine::classify`](src/fingerprint/rules.rs).

### Recipe C: Modifying Mermaid Diagram Generation
1. Open [`src/report/mermaid.rs`](src/report/mermaid.rs).
2. **Never** include IP addresses or MAC addresses in the diagram labels.
3. Always escape double quotes and special characters in node labels.
4. Ensure all subgraphs have unique identifiers to avoid rendering conflicts.
