# Aegis Sentinel Suite - Phase 1: Core Scanner

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
![Status](https://img.shields.io/badge/status-production--ready-green.svg)

**Aegis** is a high-performance, production-ready network reconnaissance engine designed for massive concurrent scans, capable of handling 10,000+ hosts with advanced fingerprinting, vulnerability mapping, and forensic-grade output.

## Features

### Core Capabilities

- **🚀 High-Performance Scanning**: Worker-pool architecture with semaphore-based rate limiting
- **🔍 Multi-Method Discovery**: ICMP, TCP SYN, UDP probes, and hybrid discovery modes
- **🔌 Port Scanning**: Asynchronous non-blocking scanning with banner grabbing
- **🎯 Service Fingerprinting**: HTTP tech stacks, TLS certificate analysis, OS detection
- **🛡️ Vulnerability Mapping**: CVE database with MITRE ATT&CK technique mapping
- **📊 Real-time Metrics**: Prometheus endpoint with comprehensive telemetry
- **💾 Persistent Storage**: BadgerDB for efficient metadata storage
- **📝 Multiple Output Formats**: JSON, NDJSON, SARIF, CSV, and human-readable text

### Architecture Highlights

- **Concurrent Worker Pool**: Configurable concurrency (100-2000+ workers)
- **Rate Limiting**: Semaphore-based throttling to protect networks
- **Structured Logging**: Forensic-grade JSON logs with full audit trail
- **Graceful Shutdown**: Context-based cancellation with signal handling
- **Production Hardening**: Memory-efficient, OOM-protected, with metric observability

## Installation

### Prerequisites

- Go 1.21 or higher
- libpcap development files (for packet capture)
- Linux/Unix/macOS (Windows support available but limited)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/aegis-sentinel/aegis-suite.git
cd aegis-suite

# Install dependencies
go mod download

# Build the binary
./scripts/build.sh

# Install system-wide (optional)
sudo cp bin/aegis /usr/local/bin/
```

### Quick Start

```bash
# Basic scan
aegis scan 192.168.1.0/24

# Comprehensive scan with all features
aegis scan 192.168.1.0/24 --mode=comprehensive --output=json

# High-throughput intensive scan
aegis scan targets.txt --mode=intensive --concurrency=2000 --rate=5000

# Discovery only
aegis discover 10.0.0.0/8 --method=hybrid

# Continuous monitoring
aegis watch production-hosts.txt --interval=300 --continuous
```

## Usage

### Commands

#### `aegis scan`

Perform comprehensive network reconnaissance:

```bash
aegis scan [targets...] [flags]

Flags:
  -f, --file string           File containing targets (one per line)
  -p, --ports string          Ports to scan (e.g., 80,443 or 1-1000)
  -m, --mode string           Scan mode: quick|comprehensive|intensive|stealthy (default "quick")
  -c, --concurrency int       Concurrent workers
  -r, --rate int              Rate limit (packets per second)
  -t, --timeout int           Scan timeout in seconds (default 300)
      --dry-run               Simulate scan without execution
      --no-discovery          Skip host discovery phase
      --no-fingerprint        Skip service fingerprinting
      --no-vuln               Skip vulnerability scanning
  -o, --output string         Output format: json|ndjson|sarif|csv|text (default "json")
      --output-file string    Write output to file
      --db-path string        Database path (default "./data/aegis.db")
      --vuln-db string        Vulnerability database path (default "./data/vulndb.json")
```

**Examples:**

```bash
# Scan a CIDR range
aegis scan 192.168.1.0/24 --mode=comprehensive

# Scan specific hosts with custom ports
aegis scan 10.0.0.1 10.0.0.2 --ports=1-1000

# Intensive scan from file
aegis scan -f targets.txt --mode=intensive --concurrency=2000

# Output to SARIF format for CI/CD integration
aegis scan example.com --output=sarif --output-file=results.sarif
```

#### `aegis discover`

Fast host discovery:

```bash
aegis discover [targets...] [flags]

Flags:
  -m, --method string    Discovery method: icmp|tcp-syn|udp|hybrid (default "hybrid")
  -c, --concurrency int  Concurrent workers (default 100)
  -t, --timeout int      Timeout in seconds (default 2)
      --retries int      Number of retries (default 1)
```

**Examples:**

```bash
# Hybrid discovery
aegis discover 192.168.1.0/24

# TCP SYN discovery only
aegis discover 10.0.0.0/8 --method=tcp-syn --concurrency=500
```

#### `aegis watch`

Continuous monitoring with change detection:

```bash
aegis watch [targets...] [flags]

Flags:
  -i, --interval int        Scan interval in seconds (default 300)
      --continuous          Run continuously
      --alert-file string   File to write alerts
  -c, --concurrency int     Concurrent workers (default 100)
```

#### `aegis metrics`

Display scan metrics and statistics:

```bash
aegis metrics

# View database statistics
aegis metrics --db-path=./data/aegis.db
```

### Scan Modes

| Mode | Ports | Concurrency | Use Case |
|------|-------|-------------|----------|
| `quick` | Common (20) | 100 | Fast overview, minimal impact |
| `comprehensive` | Top 100 | 500 | Balanced depth and speed |
| `intensive` | Top 1000 | 2000 | Deep reconnaissance, max coverage |
| `stealthy` | Common (20) | 10 | Slow, low-detection scanning |

### Output Formats

- **JSON**: Pretty-printed, machine-readable
- **NDJSON**: Newline-delimited JSON for streaming
- **SARIF**: Static Analysis Results Interchange Format (CI/CD integration)
- **CSV**: Spreadsheet-compatible
- **TEXT**: Human-readable terminal output

### Metrics Endpoint

Aegis exposes Prometheus-compatible metrics on port 9090:

```bash
curl http://localhost:9090/metrics
```

**Available Metrics:**
- `aegis_scan_count` - Total scans performed
- `aegis_active_workers` - Current active workers
- `aegis_queue_depth` - Task queue depth
- `aegis_failed_tasks` - Failed task count
- `aegis_success_tasks` - Successful task count
- `aegis_avg_latency_microseconds` - Average scan latency

## Configuration

Aegis supports configuration via:
1. Configuration file (`.aegis.yaml` in home or current directory)
2. Environment variables (prefixed with `AEGIS_`)
3. Command-line flags

### Example Configuration

```yaml
scan:
  mode: quick
  concurrency: 100
  rate_limit: 1000
  timeout: 300

discovery:
  enabled: true
  method: hybrid

ports:
  preset: common
  banner_grab: true
  service_detect: true

fingerprint:
  enabled: true
  http: true
  tls: true

vulnerability:
  enabled: true
  db_path: ./data/vulndb.json

output:
  format: json
  pretty: true

storage:
  db_path: ./data/aegis.db
  retention_days: 90

metrics:
  enabled: true
  port: 9090

logging:
  level: info
  format: json
```

## Performance

### Benchmarks

Tested on:
- **CPU**: 8-core Intel Xeon
- **RAM**: 16GB
- **Network**: 1Gbps

| Target Size | Mode | Ports | Duration | Rate |
|------------|------|-------|----------|------|
| 1,000 hosts | Quick | 20 | ~30s | 33 hosts/sec |
| 10,000 hosts | Comprehensive | 100 | ~8 min | 21 hosts/sec |
| 10,000 hosts | Intensive | 1000 | ~45 min | 4 hosts/sec |

### Optimization Tips

1. **Adjust Concurrency**: Higher for fast networks, lower for stability
2. **Use Rate Limiting**: Prevent network congestion and detection
3. **Disable Unnecessary Features**: Skip fingerprinting/vuln scanning for speed
4. **Optimize Port List**: Scan only relevant ports

## Security Considerations

- **Privileged Ports**: Some features require root/admin (ICMP, raw sockets)
- **Rate Limiting**: Always use rate limiting in production networks
- **Legal**: Ensure authorization before scanning any network
- **Detection**: Intensive scans may trigger IDS/IPS systems

## Architecture

```
aegis/
├── cmd/aegis/              # CLI entry point
│   ├── main.go
│   └── commands/           # Cobra commands
├── internal/
│   ├── aegis/core/         # Core scanning engine
│   │   ├── scanner.go      # Main orchestrator
│   │   ├── discovery.go    # Host discovery
│   │   ├── portscan.go     # Port scanning
│   │   ├── fingerprint.go  # Service fingerprinting
│   │   └── vulnmap.go      # Vulnerability mapping
│   ├── common/
│   │   ├── logging/        # Structured logging
│   │   ├── store/          # BadgerDB storage
│   │   └── telemetry/      # Prometheus metrics
│   └── net/
│       └── pcap.go         # Packet capture
├── pkg/
│   └── output/             # Output formatters
├── configs/                # Configuration files
├── scripts/                # Build and benchmark scripts
└── tests/                  # Test suites
```

## Roadmap

- [x] Phase 1: Core Scanning Engine (COMPLETED)
- [ ] Phase 2: Passive Defense (Gatehound)
- [ ] Phase 3: Response Orchestration (Revenant)
- [ ] Advanced TUI with live monitoring
- [ ] Distributed scanning coordinator
- [ ] Machine learning-based anomaly detection

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Cobra](https://github.com/spf13/cobra) for CLI
- Uses [gopacket](https://github.com/google/gopacket) for packet processing
- Storage powered by [BadgerDB](https://github.com/dgraph-io/badger)

## Support

- **Issues**: [GitHub Issues](https://github.com/aegis-sentinel/aegis-suite/issues)
- **Documentation**: [Wiki](https://github.com/aegis-sentinel/aegis-suite/wiki)

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Unauthorized scanning may be illegal in your jurisdiction.
