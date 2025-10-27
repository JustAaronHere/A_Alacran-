package commands

import (
	"context"
	"fmt"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/common/telemetry"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/correlation"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/enrich"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/monitor"
	"github.com/spf13/cobra"
)

type probeOptions struct {
	pcapFile string
	limit    int
}

func newProbeCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	opts := &probeOptions{}

	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Analyze captured PCAP file offline",
		Long: `Probe analyzes a previously captured PCAP file to detect devices,
extract events, and generate forensic analysis without live capture.

This is useful for:
- Post-incident forensic analysis
- Testing detection rules on historical data
- Analyzing packet captures from other sources

Examples:
  gatehound probe --pcap=/tmp/capture.pcap
  gatehound probe --pcap=/tmp/capture.pcap --limit=1000`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProbe(ctx, logger, opts)
		},
	}

	cmd.Flags().StringVar(&opts.pcapFile, "pcap", "", "PCAP file to analyze (required)")
	cmd.Flags().IntVar(&opts.limit, "limit", 0, "maximum packets to process (0 = all)")
	cmd.MarkFlagRequired("pcap")

	return cmd
}

func runProbe(ctx context.Context, logger *logging.Logger, opts *probeOptions) error {
	logger.Info("Starting offline PCAP analysis",
		logging.WithAction("probe"),
		logging.WithExtra("pcap_file", opts.pcapFile),
	)

	metrics := telemetry.Global()

	ouiDB, _ := enrich.NewOUIDatabase("")
	correlationEngine := correlation.NewCorrelationEngine(logger)

	listenerConfig := &monitor.ListenerConfig{
		Mode:       monitor.CaptureModeOffline,
		PcapFile:   opts.pcapFile,
		BufferSize: 10000,
		Workers:    4,
	}

	listener, err := monitor.NewPcapListener(listenerConfig, logger, metrics)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	if err := listener.Start(ctx); err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}
	defer listener.Stop()

	logger.Info("Processing PCAP file...")

	eventCount := 0
	packetLimit := opts.limit
	if packetLimit == 0 {
		packetLimit = -1
	}

	for {
		if packetLimit > 0 && eventCount >= packetLimit {
			logger.Info("Packet limit reached")
			break
		}

		select {
		case <-ctx.Done():
			logger.Info("Analysis interrupted")
			return nil

		case event, ok := <-listener.Events():
			if !ok {
				logger.Info("PCAP processing complete")
				goto done
			}

			eventCount++

			if event.SrcMAC != nil {
				ouiInfo := ouiDB.Lookup(event.SrcMAC)
				if ouiInfo != nil {
					event.Extra["vendor"] = ouiInfo.Vendor
				}
			}

			device, err := correlationEngine.ProcessEvent(event)
			if err != nil {
				logger.Error("Failed to process event", logging.WithError(err))
				continue
			}

			if device != nil && len(device.MAC) > 0 {
				ouiInfo := ouiDB.Lookup(device.MAC)
				if ouiInfo != nil {
					device.Vendor = ouiInfo.Vendor
				}
			}

			if eventCount%1000 == 0 {
				logger.Info(fmt.Sprintf("Processed %d events", eventCount))
			}
		}
	}

done:
	stats := correlationEngine.Stats()
	devices := correlationEngine.GetAllDevices()

	logger.Info("Analysis complete",
		logging.WithExtra("total_events", eventCount),
		logging.WithExtra("total_devices", stats["total_devices"]),
		logging.WithExtra("unknown_devices", stats["unknown_devices"]),
	)

	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("                   PCAP ANALYSIS SUMMARY")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("Total Events:       %d\n", eventCount)
	fmt.Printf("Total Devices:      %d\n", stats["total_devices"])
	fmt.Printf("Unknown Devices:    %d\n", stats["unknown_devices"])
	fmt.Printf("High Threat:        %d\n", stats["high_threat_devices"])
	fmt.Println("═══════════════════════════════════════════════════════════════")

	if len(devices) > 0 {
		fmt.Println("\nDetected Devices:")
		fmt.Println("───────────────────────────────────────────────────────────────")
		for i, device := range devices {
			if i >= 10 {
				fmt.Printf("\n... and %d more devices\n", len(devices)-10)
				break
			}
			fmt.Printf("  %s - %s (Threat: %.2f)\n", device.MAC.String(), device.Vendor, device.ThreatScore)
		}
	}

	return nil
}
