package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/aegis/core"
	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/common/store"
	"github.com/aegis-sentinel/aegis-suite/internal/common/telemetry"
	"github.com/spf13/cobra"
)

type watchOptions struct {
	interval    int
	continuous  bool
	alertFile   string
	concurrency int
	dbPath      string
}

func newWatchCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	opts := &watchOptions{}

	cmd := &cobra.Command{
		Use:   "watch [targets...]",
		Short: "Continuously monitor targets for changes",
		Long: `Watch continuously monitors network targets and alerts on changes:
- New open ports
- Service version changes
- New vulnerabilities
- Host state changes

Examples:
  aegis watch 192.168.1.0/24 --interval=60
  aegis watch production-servers.txt --continuous`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWatch(ctx, logger, opts, args)
		},
	}

	cmd.Flags().IntVarP(&opts.interval, "interval", "i", 300, "scan interval in seconds")
	cmd.Flags().BoolVar(&opts.continuous, "continuous", false, "run continuously")
	cmd.Flags().StringVar(&opts.alertFile, "alert-file", "", "file to write alerts")
	cmd.Flags().IntVarP(&opts.concurrency, "concurrency", "c", 100, "concurrent workers")
	cmd.Flags().StringVar(&opts.dbPath, "db-path", "./data/aegis.db", "database path")

	return cmd
}

func runWatch(ctx context.Context, logger *logging.Logger, opts *watchOptions, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no targets specified")
	}

	scanOpts := &scanOptions{targetFile: ""}
	targets, err := parseTargets(scanOpts, args)
	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("Starting continuous watch for %d targets", len(targets)))

	st, err := store.Open(opts.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()

	metrics := telemetry.Global()

	config := core.DefaultScanConfig()
	config.Targets = targets
	config.Concurrency = opts.concurrency

	scanner, err := core.NewScanner(config, logger, metrics, st)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}

	ticker := time.NewTicker(time.Duration(opts.interval) * time.Second)
	defer ticker.Stop()

	iteration := 0
	for {
		iteration++
		logger.Info(fmt.Sprintf("Starting watch iteration %d", iteration))

		job, err := scanner.Scan(ctx)
		if err != nil {
			logger.Error("Scan failed", logging.WithError(err))
		} else {
			logger.Info(fmt.Sprintf("Watch iteration %d completed: %d hosts scanned",
				iteration, len(job.Results)))
			
			if err := detectChanges(st, job.Results, logger); err != nil {
				logger.Error("Failed to detect changes", logging.WithError(err))
			}
		}

		if !opts.continuous {
			break
		}

		select {
		case <-ctx.Done():
			logger.Info("Watch terminated by signal")
			return nil
		case <-ticker.C:
		}
	}

	return nil
}

func detectChanges(st *store.Store, results []*core.HostScanResult, logger *logging.Logger) error {
	for _, result := range results {
		previousHost, err := st.GetHostInfo(result.IP)
		if err != nil {
			continue
		}

		newPorts := make(map[int]bool)
		for _, port := range result.Ports {
			newPorts[port.Port] = true
		}

		previousPorts := make(map[int]bool)
		for _, port := range previousHost.Ports {
			previousPorts[port.Port] = true
		}

		for port := range newPorts {
			if !previousPorts[port] {
				logger.Info(fmt.Sprintf("[ALERT] New open port detected on %s: %d",
					result.IP, port),
					logging.WithAction("port_change"),
					logging.WithTarget(result.IP),
				)
			}
		}

		for port := range previousPorts {
			if !newPorts[port] {
				logger.Info(fmt.Sprintf("[ALERT] Port closed on %s: %d",
					result.IP, port),
					logging.WithAction("port_change"),
					logging.WithTarget(result.IP),
				)
			}
		}
	}

	return nil
}
