package commands

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/common/store"
	"github.com/spf13/cobra"
)

type metricsOptions struct {
	dbPath string
}

func newMetricsCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	opts := &metricsOptions{}

	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Display scan metrics and statistics",
		Long:  "Display metrics and statistics from previous scans",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMetrics(ctx, logger, opts)
		},
	}

	cmd.Flags().StringVar(&opts.dbPath, "db-path", "./data/aegis.db", "database path")

	return cmd
}

func runMetrics(ctx context.Context, logger *logging.Logger, opts *metricsOptions) error {
	st, err := store.Open(opts.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()

	scans, err := st.ListScans(100)
	if err != nil {
		return fmt.Errorf("failed to list scans: %w", err)
	}

	hosts, err := st.ListHosts(1000)
	if err != nil {
		return fmt.Errorf("failed to list hosts: %w", err)
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                      AEGIS METRICS")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("\nTotal Scans:  %d\n", len(scans))
	fmt.Printf("Total Hosts:  %d\n", len(hosts))
	fmt.Println()

	if len(scans) > 0 {
		fmt.Println("Recent Scans:")
		fmt.Println("───────────────────────────────────────────────────────────────")
		
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tStatus\tTimestamp\tDuration\tFindings")
		
		count := len(scans)
		if count > 10 {
			count = 10
		}
		
		for i := 0; i < count; i++ {
			scan := scans[i]
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n",
				scan.ID[:8],
				scan.Status,
				scan.Timestamp.Format("2006-01-02 15:04:05"),
				scan.Duration,
				len(scan.Findings),
			)
		}
		w.Flush()
	}

	if len(hosts) > 0 {
		fmt.Println("\nRecent Hosts:")
		fmt.Println("───────────────────────────────────────────────────────────────")
		
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "IP\tHostname\tOS\tPorts\tLast Seen")
		
		count := len(hosts)
		if count > 20 {
			count = 20
		}
		
		for i := 0; i < count; i++ {
			host := hosts[i]
			hostname := host.Hostname
			if hostname == "" {
				hostname = "-"
			}
			os := host.OS
			if os == "" {
				os = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
				host.IP,
				hostname,
				os,
				len(host.Ports),
				host.LastSeen.Format("2006-01-02 15:04:05"),
			)
		}
		w.Flush()
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")

	return nil
}
