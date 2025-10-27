package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/aegis/core"
	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/spf13/cobra"
)

type discoverOptions struct {
	method      string
	concurrency int
	timeout     int
	retries     int
	outputFile  string
}

func newDiscoverCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	opts := &discoverOptions{}

	cmd := &cobra.Command{
		Use:   "discover [targets...]",
		Short: "Discover live hosts on the network",
		Long: `Discover performs host discovery using various methods:
- ICMP ping
- TCP SYN ping
- UDP ping
- Hybrid (combination of all methods)

Examples:
  aegis discover 192.168.1.0/24
  aegis discover 10.0.0.0/8 --method=tcp-syn
  aegis discover -f targets.txt --concurrency=500`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiscover(ctx, logger, opts, args)
		},
	}

	cmd.Flags().StringVarP(&opts.method, "method", "m", "hybrid", "discovery method (icmp|tcp-syn|udp|hybrid)")
	cmd.Flags().IntVarP(&opts.concurrency, "concurrency", "c", 100, "concurrent workers")
	cmd.Flags().IntVarP(&opts.timeout, "timeout", "t", 2, "timeout in seconds")
	cmd.Flags().IntVar(&opts.retries, "retries", 1, "number of retries")
	cmd.Flags().StringVar(&opts.outputFile, "output-file", "", "output file path")

	return cmd
}

func runDiscover(ctx context.Context, logger *logging.Logger, opts *discoverOptions, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no targets specified")
	}

	scanOpts := &scanOptions{targetFile: ""}
	targets, err := parseTargets(scanOpts, args)
	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("Starting host discovery for %d targets", len(targets)))

	method := parseDiscoveryMethod(opts.method)
	
	config := &core.DiscoveryConfig{
		Timeout:     time.Duration(opts.timeout) * time.Second,
		Retries:     opts.retries,
		Methods:     []core.DiscoveryMethod{method},
		Concurrency: opts.concurrency,
	}

	discovery := core.NewDiscovery(config)
	
	startTime := time.Now()
	results, err := discovery.DiscoverHosts(ctx, targets)
	duration := time.Since(startTime)

	if err != nil {
		return err
	}

	aliveCount := 0
	for _, result := range results {
		if result.Alive {
			aliveCount++
			fmt.Printf("[+] %s", result.IP)
			if result.Hostname != "" {
				fmt.Printf(" (%s)", result.Hostname)
			}
			if result.MAC != "" {
				fmt.Printf(" [%s]", result.MAC)
			}
			fmt.Printf(" - RTT: %s\n", result.RTT)
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("                  DISCOVERY SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Targets Scanned:   %d\n", len(targets))
	fmt.Printf("Hosts Alive:       %d\n", aliveCount)
	fmt.Printf("Duration:          %s\n", duration)
	fmt.Printf("Rate:              %.2f hosts/sec\n", float64(len(targets))/duration.Seconds())
	fmt.Println(strings.Repeat("=", 60))

	return nil
}

func parseDiscoveryMethod(method string) core.DiscoveryMethod {
	switch strings.ToLower(method) {
	case "icmp":
		return core.DiscoveryICMP
	case "tcp-syn", "tcp":
		return core.DiscoveryTCPSYN
	case "udp":
		return core.DiscoveryUDP
	case "arp":
		return core.DiscoveryARP
	default:
		return core.DiscoveryHybrid
	}
}
