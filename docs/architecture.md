# Aegis Sentinel Suite - Architecture

## Overview

The Aegis Sentinel Suite is a production-ready, integrated security platform consisting of three core modules that work together to provide comprehensive threat detection, monitoring, and automated response capabilities.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    AEGIS SENTINEL SUITE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────┐  ┌────────────────┐  ┌──────────────────┐  │
│  │   MODULE 1    │  │   MODULE 2     │  │    MODULE 3      │  │
│  │     AEGIS     │  │   GATEHOUND    │  │    REVENANT      │  │
│  │               │  │                │  │                  │  │
│  │ Active Recon  │  │ Passive Defense│  │ Response         │  │
│  │ & Scanning    │  │ & Monitoring   │  │ Orchestration    │  │
│  └───────┬───────┘  └────────┬───────┘  └────────┬─────────┘  │
│          │                   │                    │            │
│          └───────────────────┼────────────────────┘            │
│                              │                                 │
│                    ┌─────────▼─────────┐                       │
│                    │  Central Event    │                       │
│                    │  Bus & Storage    │                       │
│                    └───────────────────┘                       │
└─────────────────────────────────────────────────────────────────┘
```

## Module 1: Aegis - Active Reconnaissance Engine

### Purpose
High-performance parallel scanning engine for network reconnaissance, vulnerability detection, and asset discovery.

### Key Components

**Core Scanner** (`internal/aegis/core/scanner.go`)
- Worker pool management with configurable concurrency (100-2000+ workers)
- Semaphore-based rate limiting
- Queue management with backpressure handling
- Graceful shutdown and context cancellation

**Discovery Engine** (`internal/aegis/core/discovery.go`)
- ICMP ping sweeps
- TCP SYN discovery
- UDP probes
- Hybrid discovery modes
- ARP scanning for local networks

**Port Scanner** (`internal/aegis/core/portscan.go`)
- Async non-blocking TCP/UDP scanning
- Banner grabbing
- Service detection
- Protocol fingerprinting

**Fingerprinter** (`internal/aegis/core/fingerprint.go`)
- HTTP technology stack detection
- TLS certificate analysis
- OS fingerprinting via TTL/TCP options
- CMS and framework identification

**Vulnerability Mapper** (`internal/aegis/core/vulnmap.go`)
- Local CVE signature database
- Version-based vulnerability matching
- MITRE ATT&CK technique mapping
- Misconfiguration detection

### Data Flow
```
Targets → Discovery → Port Scan → Fingerprint → Vuln Mapping → Storage
```

### Performance Targets
- 10,000+ hosts with top 100 ports in controlled environments
- Sustained throughput via worker pools and rate limiting
- Memory-efficient with OOM protection
- Graceful degradation under load

---

## Module 2: Gatehound - Passive Defense System

### Purpose
Always-on passive network monitoring for unknown device detection, forensic evidence collection, and automated incident reporting.

### Key Components

**PCAP Listener** (`internal/gatehound/monitor/pcap_listener.go`)
- libpcap/gopacket integration
- SPAN/mirror and inline capture modes
- Packet rotation and encryption
- Configurable buffer sizes and worker pools

**Packet Parser** (`internal/gatehound/monitor/parser.go`)
- ARP analysis
- DHCP lease detection
- DNS/mDNS monitoring
- TLS handshake inspection
- HTTP User-Agent extraction

**Enrichment Services** (`internal/gatehound/enrich/`)
- **GeoIP**: MaxMind integration for geolocation and ASN
- **OUI Lookup**: MAC address vendor identification
- **WHOIS/RDAP**: IP ownership and registration data
- **TLS/HTTP**: Certificate and header analysis

**Correlation Engine** (`internal/gatehound/correlation/`)
- Threat intelligence feed integration (STIX/TAXII)
- Blacklist matching
- Scoring engine for risk assessment
- Historical sighting correlation

**Policy Engine** (`internal/gatehound/policy/policy.go`)
- Asset inventory comparison
- Unknown device flagging rules
- Automated action triggers
- Allowlist/blocklist management

**NAC Integration** (`internal/gatehound/nac/`)
- Cisco ISE adapter
- Aruba ClearPass adapter
- Generic API adapter
- Device quarantine and isolation

**PDF Report Generator** (`internal/gatehound/report/pdfgen.go`)
- Universal forensic template
- Chain-of-custody documentation
- Signed manifests
- Timeline visualization
- Evidence integrity verification

**Evidence Store** (`internal/gatehound/evidence/store.go`)
- Encrypted PCAP storage
- SHA-256 hashing
- ed25519 signing
- Tamper-evident manifests

### Data Flow
```
Network Traffic → PCAP Capture → Parse → Enrich → Correlate → 
Policy Check → Alert/Action → Evidence Storage → PDF Report
```

---

## Module 3: Revenant - Response Orchestrator

### Purpose
Automated verification, containment, and remediation with human approval workflows and comprehensive audit trails.

### Key Components

**Orchestration Engine** (`internal/revenant/orchestrator/engine.go`)
- Task queue management
- Worker pools for parallel execution
- Retry logic with exponential backoff
- Dead-letter queue for failed tasks
- RBAC-based approval workflows

**Sandbox Manager** (`internal/revenant/sandbox/sandboxmgr.go`)
- Ephemeral container/VM provisioning
- Read-only verification environments
- Network isolation and timeboxing
- Resource quotas (CPU/memory/time)
- Automatic teardown

**Playbook Engine** (`internal/revenant/playbooks/playbook.go`)
- YAML-based playbook definitions
- Step-by-step execution
- Rollback support
- Conditional logic
- Variable substitution
- Approval gates

**Action Modules** (`internal/revenant/actions/`)
- **Containment**: Network isolation, port disable, quarantine
- **Command**: Safe command execution with logging
- **Integration adapters** for external systems

**Integrations** (`internal/revenant/integrations/`)
- **EDR**: CrowdStrike, SentinelOne, Carbon Black
- **NAC**: Via Gatehound module
- **Cloud APIs**: AWS, Azure, GCP
- **SIEM**: Splunk, Elasticsearch
- **Ticketing**: Jira, ServiceNow

**API Server** (`internal/revenant/api/server.go`)
- REST and gRPC endpoints
- Playbook triggering
- Status monitoring
- Audit log retrieval

**RBAC** (`internal/revenant/authz/rbac.go`)
- Role-based access control
- Approval workflows
- Signed action tokens
- Audit trail

### Data Flow
```
Event → Task Creation → Queue → Worker → Sandbox Verify → 
Approval (if required) → Execute Action → Log → 
Generate Report → Re-scan (via Aegis) → Close
```

---

## Shared Infrastructure

### Common Services (`internal/common/`)

**Logging** (`logging/logger.go`)
- Structured JSON logging
- Consistent schema across modules
- Log levels: debug, info, warning, error, critical
- Session and operator tracking

**Storage** (`store/store.go`)
- BadgerDB for high-performance KV storage
- Encrypted blob storage (S3-compatible)
- Retention policies
- Automatic garbage collection

**Telemetry** (`telemetry/metrics.go`)
- Prometheus metrics endpoints
- Per-module metrics:
  - `aegis_*`: Scan metrics (scans, workers, queue depth, latency)
  - `gatehound_*`: Monitor metrics (packets, events, devices)
  - `revenant_*`: Orchestration metrics (tasks, playbooks, actions)

### Utilities (`pkg/util/`)

**Crypto** (`crypto.go`)
- AES-256-GCM encryption
- ed25519 signing
- SHA-256 hashing
- Key management interfaces
- Signed manifest creation

**Tracing** (`trace.go`)
- Distributed tracing support
- OpenTelemetry-ready
- Span management
- Contextual logging

**TUI** (`pkg/cli/tui.go`)
- Terminal-based live dashboards
- Real-time metrics visualization
- Progress bars and status displays

---

## Data Flow - End-to-End

```
1. Aegis scans network → Detects hosts, ports, services, vulns
   ↓
2. Findings published to central event bus
   ↓
3. Gatehound monitors network passively → Detects unknown device
   ↓
4. Enrichment: GeoIP, WHOIS, TI correlation
   ↓
5. Policy engine flags as suspicious
   ↓
6. Alert generated → PDF report created
   ↓
7. Event forwarded to Revenant
   ↓
8. Revenant triggers playbook (e.g., "isolate-unknown-device")
   ↓
9. Sandbox verification (optional)
   ↓
10. Approval request (if policy requires)
   ↓
11. Execute containment actions:
    - NAC: Quarantine device
    - Firewall: Block IP
    - EDR: Isolate host
    - Cloud: Snapshot volumes
   ↓
12. Generate signed remediation report
   ↓
13. Trigger re-scan via Aegis for verification
   ↓
14. Close incident, archive evidence
```

---

## Security Considerations

### Encryption & Signing
- All evidence encrypted with AES-256-GCM
- Manifests signed with ed25519
- Chain-of-custody for forensic integrity

### Access Control
- RBAC for all sensitive operations
- Signed action tokens
- Audit trails for compliance

### Safe Defaults
- Conservative concurrency limits
- Rate limiting enabled by default
- Dry-run modes for testing
- Sandboxed verification before destructive actions

### Secrets Management
- Runtime retrieval from KMS/HSM
- No hardcoded secrets
- Environment variables and config files

---

## Deployment Topologies

### Single-Node
All three modules on one host. Suitable for small/medium networks.

```
┌─────────────────────────┐
│   Aegis Sentinel Host   │
│  ┌─────────────────────┐│
│  │ Aegis (scanning)    ││
│  │ Gatehound (monitor) ││
│  │ Revenant (response) ││
│  │ BadgerDB            ││
│  │ Prometheus          ││
│  └─────────────────────┘│
└─────────────────────────┘
```

### Distributed
Modules on separate hosts for scale and isolation.

```
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│ Aegis Node   │       │ Gatehound    │       │ Revenant     │
│ (scanning)   │◄─────►│ (monitoring) │◄─────►│ (response)   │
└──────────────┘       └──────────────┘       └──────────────┘
       │                      │                       │
       └──────────────────────┼───────────────────────┘
                              │
                      ┌───────▼────────┐
                      │  Shared        │
                      │  Event Bus     │
                      │  & Storage     │
                      └────────────────┘
```

---

## Configuration

### File Structure
```
/etc/aegis-sentinel/
├── aegis.yaml         # Aegis scanner config
├── gatehound.yaml     # Gatehound monitor config
├── revenant.yaml      # Revenant orchestrator config
├── playbooks/         # Remediation playbooks
└── keys/              # Encryption and signing keys
```

### Environment Variables
All modules support env vars prefixed with module name:
- `AEGIS_*`
- `GATEHOUND_*`
- `REVENANT_*`

---

## Monitoring & Observability

### Metrics Endpoints
- Aegis: `:9090/metrics`
- Gatehound: `:9091/metrics`
- Revenant: `:9092/metrics`

### Health Checks
- `/healthz` - Liveness probe
- `/readyz` - Readiness probe

### Grafana Dashboards
Pre-built dashboards for:
- Scan performance
- Network events
- Response actions
- System resources

---

## Performance Tuning

### Aegis
- Adjust `concurrency` for scan speed
- Tune `rate_limit` to avoid network saturation
- Optimize port lists for faster scans

### Gatehound
- Set appropriate buffer sizes for packet capture
- Configure PCAP rotation intervals
- Tune enrichment caching

### Revenant
- Adjust worker pool sizes
- Configure retry policies
- Set appropriate timeouts

---

## Future Enhancements

- Horizontal scaling with coordinator nodes
- Machine learning for anomaly detection
- Advanced TUI with real-time monitoring
- Cluster mode for distributed scanning
- Enhanced MITRE ATT&CK mapping
- Additional integration adapters
