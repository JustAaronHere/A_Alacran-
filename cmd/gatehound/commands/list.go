package commands

import (
	"context"
	"fmt"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
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

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                    DETECTED DEVICES")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	if unknown {
		fmt.Println("\nUnknown Devices:")
		fmt.Println("  (query database for unknown devices)")
	} else if highThreat {
		fmt.Println("\nHigh Threat Devices:")
		fmt.Println("  (query database for high threat devices)")
	} else {
		fmt.Println("\nAll Devices:")
		fmt.Println("  (query database for all devices)")
	}

	fmt.Println("\n(Note: Device listing requires active monitoring session or database query)")

	return nil
}
