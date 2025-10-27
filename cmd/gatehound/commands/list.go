package commands

import (
	"context"
	"fmt"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/pkg/output"
	"github.com/spf13/cobra"
)

func newListCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	var unknown, highThreat bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List detected devices",
		Long: `List all detected devices from the monitoring database.

Filters:
  --unknown      Show only unknown devices
  --high-threat  Show only high threat devices

Examples:
  gatehound list
  gatehound list --unknown
  gatehound list --high-threat`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(ctx, logger, unknown, highThreat)
		},
	}

	cmd.Flags().BoolVar(&unknown, "unknown", false, "show only unknown devices")
	cmd.Flags().BoolVar(&highThreat, "high-threat", false, "show only high threat devices")

	return cmd
}

func runList(ctx context.Context, logger *logging.Logger, unknown, highThreat bool) error {
	logger.Info("Listing detected devices",
		logging.WithAction("list"),
		logging.WithExtra("unknown_only", unknown),
		logging.WithExtra("high_threat_only", highThreat),
	)

	fmt.Println(output.Header("DETECTED DEVICES"))
	fmt.Println()

	table := output.NewTable("MAC Address", "IP Address", "Hostname", "Vendor", "Threat Score", "Status")
	
	if unknown {
		fmt.Println(output.Section("Unknown Devices"))
		fmt.Println()
		table.AddRow(
			"00:1A:2B:3C:4D:5E",
			output.Colorize(output.BrightCyan, "192.168.1.105"),
			output.Colorize(output.Gray, "Unknown"),
			output.Colorize(output.BrightWhite, "Apple Inc."),
			output.Colorize(output.Red, "65"),
			output.StatusBadge("QUARANTINED"),
		)
		table.AddRow(
			"AA:BB:CC:DD:EE:FF",
			output.Colorize(output.BrightCyan, "192.168.1.142"),
			output.Colorize(output.Gray, "Unknown"),
			output.Colorize(output.BrightWhite, "Samsung"),
			output.Colorize(output.Yellow, "45"),
			output.StatusBadge("PENDING"),
		)
	} else if highThreat {
		fmt.Println(output.Section("High Threat Devices"))
		fmt.Println()
		table.AddRow(
			"11:22:33:44:55:66",
			output.Colorize(output.BrightCyan, "192.168.1.200"),
			output.Colorize(output.BrightWhite, "suspicious-device"),
			output.Colorize(output.BrightWhite, "Unknown"),
			output.Colorize(output.BrightRed, "95"),
			output.StatusBadge("QUARANTINED"),
		)
	} else {
		fmt.Println(output.Section("All Devices"))
		fmt.Println()
		table.AddRow(
			"00:11:22:33:44:55",
			output.Colorize(output.BrightCyan, "192.168.1.10"),
			output.Colorize(output.BrightWhite, "workstation-01"),
			output.Colorize(output.BrightWhite, "Dell Inc."),
			output.Colorize(output.Green, "10"),
			output.StatusBadge("ACTIVE"),
		)
		table.AddRow(
			"66:77:88:99:AA:BB",
			output.Colorize(output.BrightCyan, "192.168.1.20"),
			output.Colorize(output.BrightWhite, "laptop-hr-05"),
			output.Colorize(output.BrightWhite, "HP Inc."),
			output.Colorize(output.Green, "15"),
			output.StatusBadge("ACTIVE"),
		)
		table.AddRow(
			"00:1A:2B:3C:4D:5E",
			output.Colorize(output.BrightCyan, "192.168.1.105"),
			output.Colorize(output.Gray, "Unknown"),
			output.Colorize(output.BrightWhite, "Apple Inc."),
			output.Colorize(output.Red, "65"),
			output.StatusBadge("QUARANTINED"),
		)
	}

	fmt.Println(table.Render())
	fmt.Println(output.SectionEnd())
	fmt.Println()
	fmt.Println(output.Info("Device listing requires active monitoring session or database query"))
	fmt.Println(output.Warning("Sample data shown for demonstration"))
	fmt.Println()

	return nil
}
