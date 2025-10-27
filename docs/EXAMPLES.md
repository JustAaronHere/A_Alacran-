# Aegis Scanner - Usage Examples

## Quick Start Examples

### Basic Host Scan

```bash
# Scan a single host with default settings (quick mode, common ports)
aegis scan 192.168.1.1

# Scan multiple hosts
aegis scan 192.168.1.1 192.168.1.2 192.168.1.3

# Scan a hostname
aegis scan example.com
```

### Network Range Scanning

```bash
# Scan a CIDR range
aegis scan 192.168.1.0/24

# Scan an IP range
aegis scan 192.168.1.1-192.168.1.254

# Large network scan
aegis scan 10.0.0.0/16 --mode=comprehensive --concurrency=2000
```

### Scan Modes

```bash
# Quick scan (fast, common ports only)
aegis scan 192.168.1.0/24 --mode=quick

# Comprehensive scan (top 100 ports, full fingerprinting)
aegis scan 192.168.1.0/24 --mode=comprehensive

# Intensive scan (top 1000 ports, max coverage)
aegis scan 192.168.1.0/24 --mode=intensive --concurrency=2000 --rate=5000

# Stealthy scan (slow, low detection)
aegis scan target.com --mode=stealthy
```

### Custom Port Scanning

```bash
# Scan specific ports
aegis scan 192.168.1.1 --ports=80,443,8080,8443

# Scan a range of ports
aegis scan 192.168.1.1 --ports=1-1000

# Scan common ports only
aegis scan 192.168.1.0/24 --ports=common

# Scan top 100 ports
aegis scan 192.168.1.0/24 --ports=top100

# Scan all ports (1-65535) - very slow!
aegis scan 192.168.1.1 --ports=1-65535 --concurrency=1000
```

### Output Formats

```bash
# JSON output (default)
aegis scan 192.168.1.1 --output=json

# Pretty-printed JSON
aegis scan 192.168.1.1 --output=json > results.json

# NDJSON (newline-delimited JSON for streaming)
aegis scan 192.168.1.0/24 --output=ndjson > results.ndjson

# SARIF format (for CI/CD integration)
aegis scan target.com --output=sarif --output-file=results.sarif

# CSV format (for spreadsheets)
aegis scan 192.168.1.0/24 --output=csv --output-file=results.csv

# Human-readable text
aegis scan 192.168.1.1 --output=text
```

### Discovery Examples

```bash
# Hybrid discovery (ICMP + TCP SYN)
aegis discover 192.168.1.0/24

# ICMP ping only
aegis discover 192.168.1.0/24 --method=icmp

# TCP SYN discovery
aegis discover 10.0.0.0/8 --method=tcp-syn --concurrency=500

# Fast discovery with high concurrency
aegis discover 192.168.0.0/16 --method=hybrid --concurrency=1000
```

### Continuous Monitoring

```bash
# Watch a network with 5-minute intervals
aegis watch 192.168.1.0/24 --interval=300 --continuous

# Monitor specific hosts
aegis watch 192.168.1.1 192.168.1.2 192.168.1.3 --interval=60 --continuous

# Watch from a file
echo "192.168.1.1" > targets.txt
echo "192.168.1.2" >> targets.txt
aegis watch -f targets.txt --interval=300 --continuous
```

### Advanced Scenarios

#### Full Enterprise Network Scan

```bash
# Comprehensive scan of enterprise network with metrics
aegis scan 10.0.0.0/8 \
  --mode=comprehensive \
  --concurrency=2000 \
  --rate=5000 \
  --output=ndjson \
  --output-file=enterprise-scan.ndjson \
  --metrics-port=9090
```

#### CI/CD Security Scanning

```bash
# Scan application servers and output SARIF for GitHub Actions
aegis scan app-server-1.example.com app-server-2.example.com \
  --mode=comprehensive \
  --output=sarif \
  --output-file=security-scan.sarif

# This SARIF file can be uploaded to GitHub Security tab
```

#### Vulnerability Assessment

```bash
# Full vulnerability scan with custom CVE database
aegis scan 192.168.1.0/24 \
  --mode=intensive \
  --vuln-db=./custom-vulndb.json \
  --output=json \
  --output-file=vuln-assessment.json
```

#### High-Throughput Scanning (10k+ hosts)

```bash
# Prepare target file with 10,000 hosts
for i in {0..255}; do
  for j in {0..39}; do
    echo "10.0.$i.$j"
  done
done > large-targets.txt

# Run high-throughput scan
aegis scan -f large-targets.txt \
  --mode=quick \
  --concurrency=2000 \
  --rate=10000 \
  --no-fingerprint \
  --output=ndjson \
  --output-file=large-scan-results.ndjson
```

#### Stealthy Reconnaissance

```bash
# Low-profile scan to avoid detection
aegis scan target.com \
  --mode=stealthy \
  --concurrency=10 \
  --rate=100 \
  --ports=top100 \
  --timeout=600
```

### Disabling Features

```bash
# Skip host discovery (scan all IPs directly)
aegis scan 192.168.1.0/24 --no-discovery

# Skip service fingerprinting (faster)
aegis scan 192.168.1.0/24 --no-fingerprint

# Skip vulnerability scanning (ports only)
aegis scan 192.168.1.0/24 --no-vuln

# Minimal scan (ports only, no extras)
aegis scan 192.168.1.0/24 --no-fingerprint --no-vuln
```

### Working with Results

```bash
# Scan and pipe to jq for filtering
aegis scan 192.168.1.0/24 --output=json | jq '.[] | select(.Ports | length > 0)'

# Find hosts with specific ports open
aegis scan 192.168.1.0/24 --output=ndjson | jq 'select(.Ports[] | .Port == 22)'

# Count total vulnerabilities
aegis scan 192.168.1.0/24 --output=json | jq '[.[].Vulnerabilities | length] | add'

# Export to CSV for analysis in Excel
aegis scan 192.168.1.0/24 --output=csv --output-file=results.csv
```

### Monitoring Metrics

```bash
# Start scan with metrics enabled
aegis scan 192.168.1.0/24 --metrics-port=9090 &

# In another terminal, monitor metrics
watch -n 1 'curl -s http://localhost:9090/metrics | grep aegis_'

# Or use Prometheus to scrape metrics
# prometheus.yml:
# scrape_configs:
#   - job_name: 'aegis'
#     static_configs:
#       - targets: ['localhost:9090']
```

### Database Operations

```bash
# View scan history
aegis metrics --db-path=./data/aegis.db

# Scan with custom database location
aegis scan 192.168.1.0/24 --db-path=/var/lib/aegis/scans.db
```

## Production Deployment Examples

### Scheduled Scanning with Cron

```bash
# Add to crontab for daily scans at 2 AM
0 2 * * * /usr/local/bin/aegis scan -f /etc/aegis/targets.txt \
  --mode=comprehensive \
  --output=ndjson \
  --output-file=/var/log/aegis/scan-$(date +\%Y\%m\%d).ndjson
```

### Docker Deployment

```bash
# Run in Docker container
docker run -v /data:/data aegis/scanner \
  scan 192.168.1.0/24 \
  --db-path=/data/aegis.db \
  --output-file=/data/results.json
```

### Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: aegis-scanner
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: aegis
            image: aegis/scanner:latest
            args:
            - scan
            - -f
            - /config/targets.txt
            - --mode=comprehensive
            - --output-file=/output/results.json
            volumeMounts:
            - name: config
              mountPath: /config
            - name: output
              mountPath: /output
          restartPolicy: OnFailure
          volumes:
          - name: config
            configMap:
              name: aegis-targets
          - name: output
            persistentVolumeClaim:
              claimName: aegis-results
```

## Troubleshooting

### Permission Issues

```bash
# Some features require elevated privileges
sudo aegis scan 192.168.1.0/24

# Or use capabilities (Linux only)
sudo setcap cap_net_raw+ep /usr/local/bin/aegis
aegis scan 192.168.1.0/24
```

### Performance Tuning

```bash
# Increase concurrency for faster scans
aegis scan 192.168.1.0/24 --concurrency=2000

# Add rate limiting to avoid overwhelming the network
aegis scan 192.168.1.0/24 --concurrency=2000 --rate=5000

# Adjust timeout for slow networks
aegis scan 192.168.1.0/24 --timeout=600
```

### Debug Mode

```bash
# Enable debug logging
aegis scan 192.168.1.1 --debug

# Verbose output
aegis scan 192.168.1.1 --verbose
```

## Best Practices

1. **Always use rate limiting** in production networks
2. **Start with quick mode** to get an overview before deep scans
3. **Monitor metrics** to track scan progress and performance
4. **Store results** in a database for historical comparison
5. **Use dry-run** to validate scan configuration before execution
6. **Adjust concurrency** based on network capacity and host count
7. **Enable logging** for audit trails and troubleshooting
