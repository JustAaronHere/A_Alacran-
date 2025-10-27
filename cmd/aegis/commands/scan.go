package commands

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/aegis/core"
	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/common/store"
	"github.com/aegis-sentinel/aegis-suite/internal/common/telemetry"
	"github.com/aegis-sentinel/aegis-suite/pkg/output"
	"github.com/spf13/cobra"
)

type scanOptions struct {
	targets      []string
	targetFile   string
	ports        string
	mode         string
	concurrency  int
	rateLimit    int
	timeout      int
	dryRun       bool
	noDiscovery  bool
	noFingerprint bool
	noVuln       bool
	outputFile   string
	dbPath       string
	vulnDBPath   string
}

func newScanCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	opts := &scanOptions{}

	cmd := &cobra.Command{
		Use:   "scan [targets...]",
		Short: "Scan network hosts for open ports, services, and vulnerabilities",
		Long: `Scan performs comprehensive network reconnaissance including:
- Host discovery (ICMP, TCP SYN, UDP)
- Port scanning with concurrent workers
- Service fingerprinting (HTTP, TLS, banner grabbing)
- Vulnerability mapping (CVE, MITRE ATT&CK)
- Forensic-grade structured output

Examples:
  aegis scan 192.168.1.0/24
  aegis scan 10.0.0.1-10.0.0.100
  aegis scan example.com --mode=comprehensive
  aegis scan -f targets.txt --concurrency=2000 --rate=5000
  aegis scan 192.168.1.1 --ports=1-1000 --output=json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(ctx, logger, opts, args)
		},
	}

	cmd.Flags().StringVarP(&opts.targetFile, "file", "f", "", "file containing targets (one per line)")
	cmd.Flags().StringVarP(&opts.ports, "ports", "p", "", "ports to scan (e.g., 80,443 or 1-1000)")
	cmd.Flags().StringVarP(&opts.mode, "mode", "m", "quick", "scan mode (quick|comprehensive|intensive|stealthy)")
	cmd.Flags().IntVarP(&opts.concurrency, "concurrency", "c", 0, "concurrent workers (default varies by mode)")
	cmd.Flags().IntVarP(&opts.rateLimit, "rate", "r", 0, "rate limit (packets per second)")
	cmd.Flags().IntVarP(&opts.timeout, "timeout", "t", 300, "scan timeout in seconds")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "simulate scan without actual execution")
	cmd.Flags().BoolVar(&opts.noDiscovery, "no-discovery", false, "skip host discovery phase")
	cmd.Flags().BoolVar(&opts.noFingerprint, "no-fingerprint", false, "skip service fingerprinting")
	cmd.Flags().BoolVar(&opts.noVuln, "no-vuln", false, "skip vulnerability scanning")
	cmd.Flags().StringVar(&opts.outputFile, "output-file", "", "output file path")
	cmd.Flags().StringVar(&opts.dbPath, "db-path", "./data/aegis.db", "database path")
	cmd.Flags().StringVar(&opts.vulnDBPath, "vuln-db", "./data/vulndb.json", "vulnerability database path")

	return cmd
}

func runScan(ctx context.Context, logger *logging.Logger, opts *scanOptions, args []string) error {
	logger.Info("Initializing Aegis Scanner", logging.WithAction("init"))

	metrics := telemetry.Global()
	go func() {
		addr := fmt.Sprintf(":%d", metricsPort)
		logger.Info(fmt.Sprintf("Starting metrics server on %s", addr))
		if err := metrics.StartMetricsServer(addr); err != nil {
			logger.Error("Metrics server failed", logging.WithError(err))
		}
	}()

	st, err := store.Open(opts.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()

	targets, err := parseTargets(opts, args)
	if err != nil {
		return fmt.Errorf("failed to parse targets: %w", err)
	}

	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	logger.Info(fmt.Sprintf("Loaded %d targets", len(targets)))

	config := buildScanConfig(opts, targets)

	scanner, err := core.NewScanner(config, logger, metrics, st)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}

	logger.Info("Starting scan", 
		logging.WithAction("scan_start"),
		logging.WithExtra("mode", opts.mode),
		logging.WithExtra("targets", len(targets)),
	)

	startTime := time.Now()
	job, err := scanner.Scan(ctx)
	duration := time.Since(startTime)

	if err != nil {
		logger.Error("Scan failed", logging.WithError(err))
		return err
	}

	logger.Info("Scan completed",
		logging.WithAction("scan_complete"),
		logging.WithExtra("duration", duration.String()),
		logging.WithExtra("hosts_scanned", len(job.Results)),
	)

	if err := writeOutput(job.Results, opts); err != nil {
		logger.Error("Failed to write output", logging.WithError(err))
		return err
	}

	printSummary(logger, job, duration)

	return nil
}

func parseTargets(opts *scanOptions, args []string) ([]string, error) {
	targets := make([]string, 0)

	for _, arg := range args {
		if strings.Contains(arg, "/") {
			ips, err := core.ParseCIDR(arg)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %s: %w", arg, err)
			}
			targets = append(targets, ips...)
		} else if strings.Contains(arg, "-") {
			parts := strings.Split(arg, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid IP range %s", arg)
			}
			ips, err := core.ParseIPRange(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid IP range %s: %w", arg, err)
			}
			targets = append(targets, ips...)
		} else {
			targets = append(targets, arg)
		}
	}

	if opts.targetFile != "" {
		fileTargets, err := readTargetsFromFile(opts.targetFile)
		if err != nil {
			return nil, err
		}
		targets = append(targets, fileTargets...)
	}

	return targets, nil
}

func readTargetsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	targets := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	return targets, scanner.Err()
}

func buildScanConfig(opts *scanOptions, targets []string) *core.ScanConfig {
	var config *core.ScanConfig

	switch strings.ToLower(opts.mode) {
	case "comprehensive":
		config = core.ComprehensiveScanConfig()
	case "intensive":
		config = core.IntensiveScanConfig()
	case "stealthy":
		config = core.DefaultScanConfig()
		config.Concurrency = 10
		config.RateLimit = 100
	default:
		config = core.DefaultScanConfig()
	}

	config.Targets = targets
	config.DryRun = opts.dryRun
	config.Output = outputFormat
	config.VulnDBPath = opts.vulnDBPath

	if opts.concurrency > 0 {
		config.Concurrency = opts.concurrency
	}
	if opts.rateLimit > 0 {
		config.RateLimit = opts.rateLimit
	}
	if opts.timeout > 0 {
		config.Timeout = time.Duration(opts.timeout) * time.Second
	}

	if opts.ports != "" {
		config.Ports = parsePorts(opts.ports)
	}

	config.DiscoveryEnabled = !opts.noDiscovery
	config.FingerprintEnabled = !opts.noFingerprint
	config.VulnScanEnabled = !opts.noVuln

	return config
}

func parsePorts(portStr string) []int {
	ports := make([]int, 0)

	if portStr == "common" {
		return core.GetCommonPorts()
	}
	if portStr == "top100" {
		return core.GetTop100Ports()
	}
	if portStr == "top1000" {
		return core.GetTop1000Ports()
	}

	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				var start, end int
				fmt.Sscanf(rangeParts[0], "%d", &start)
				fmt.Sscanf(rangeParts[1], "%d", &end)
				for i := start; i <= end; i++ {
					ports = append(ports, i)
				}
			}
		} else {
			var port int
			if _, err := fmt.Sscanf(part, "%d", &port); err == nil {
				ports = append(ports, port)
			}
		}
	}

	if len(ports) == 0 {
		return core.GetCommonPorts()
	}

	return ports
}

func writeOutput(results []*core.HostScanResult, opts *scanOptions) error {
	formatter := output.GetFormatter(output.OutputFormat(outputFormat))
	data, err := formatter.Format(results)
	if err != nil {
		return err
	}

	if opts.outputFile != "" {
		return os.WriteFile(opts.outputFile, data, 0644)
	}

	fmt.Println(string(data))
	return nil
}

func printSummary(logger *logging.Logger, job *core.ScanJob, duration time.Duration) {
	totalHosts := len(job.Results)
	totalPorts := 0
	totalVulns := 0

	for _, result := range job.Results {
		totalPorts += len(result.Ports)
		totalVulns += len(result.Vulnerabilities)
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("                      SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Job ID:              %s\n", job.ID)
	fmt.Printf("Status:              %s\n", job.Status)
	fmt.Printf("Duration:            %s\n", duration)
	fmt.Printf("Hosts Scanned:       %d\n", totalHosts)
	fmt.Printf("Open Ports Found:    %d\n", totalPorts)
	fmt.Printf("Vulnerabilities:     %d\n", totalVulns)
	fmt.Println(strings.Repeat("=", 60))

	if totalVulns > 0 {
		criticalCount := 0
		highCount := 0
		mediumCount := 0

		for _, result := range job.Results {
			for _, vulnService := range result.Vulnerabilities {
				for _, vuln := range vulnService.Vulnerabilities {
					switch strings.ToUpper(vuln.Severity) {
					case "CRITICAL":
						criticalCount++
					case "HIGH":
						highCount++
					case "MEDIUM":
						mediumCount++
					}
				}
			}
		}

		fmt.Println("\nVulnerability Breakdown:")
		fmt.Printf("  CRITICAL: %d\n", criticalCount)
		fmt.Printf("  HIGH:     %d\n", highCount)
		fmt.Printf("  MEDIUM:   %d\n", mediumCount)
		fmt.Println()
	}
}
