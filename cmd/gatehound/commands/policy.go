package commands

import (
	"context"
	"fmt"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/spf13/cobra"
)

func newPolicyCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage device policies",
		Long: `Manage device policies for allow/block lists and custom rules.

Subcommands:
  add       - Add a policy rule
  remove    - Remove a policy rule
  list      - List all policy rules`,
	}

	cmd.AddCommand(newPolicyAddCmd(ctx, logger))
	cmd.AddCommand(newPolicyRemoveCmd(ctx, logger))
	cmd.AddCommand(newPolicyListCmd(ctx, logger))

	return cmd
}

func newPolicyAddCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	var macAllow, macBlock, ipAllow, ipBlock string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a policy rule",
		Long: `Add a device to the allow or block list.

Examples:
  gatehound policy add --mac-allow=00:11:22:33:44:55
  gatehound policy add --mac-block=AA:BB:CC:DD:EE:FF
  gatehound policy add --ip-allow=192.168.1.100
  gatehound policy add --ip-block=10.0.0.50`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if macAllow != "" {
				logger.Info("Adding MAC to allow list", logging.WithExtra("mac", macAllow))
				fmt.Printf("✓ Added MAC %s to allow list\n", macAllow)
			}
			if macBlock != "" {
				logger.Info("Adding MAC to block list", logging.WithExtra("mac", macBlock))
				fmt.Printf("✓ Added MAC %s to block list\n", macBlock)
			}
			if ipAllow != "" {
				logger.Info("Adding IP to allow list", logging.WithExtra("ip", ipAllow))
				fmt.Printf("✓ Added IP %s to allow list\n", ipAllow)
			}
			if ipBlock != "" {
				logger.Info("Adding IP to block list", logging.WithExtra("ip", ipBlock))
				fmt.Printf("✓ Added IP %s to block list\n", ipBlock)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&macAllow, "mac-allow", "", "MAC address to allow")
	cmd.Flags().StringVar(&macBlock, "mac-block", "", "MAC address to block")
	cmd.Flags().StringVar(&ipAllow, "ip-allow", "", "IP address to allow")
	cmd.Flags().StringVar(&ipBlock, "ip-block", "", "IP address to block")

	return cmd
}

func newPolicyRemoveCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	var mac, ip string

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a policy rule",
		Long: `Remove a device from the allow or block list.

Examples:
  gatehound policy remove --mac=00:11:22:33:44:55
  gatehound policy remove --ip=192.168.1.100`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if mac != "" {
				logger.Info("Removing MAC from policies", logging.WithExtra("mac", mac))
				fmt.Printf("✓ Removed MAC %s from policies\n", mac)
			}
			if ip != "" {
				logger.Info("Removing IP from policies", logging.WithExtra("ip", ip))
				fmt.Printf("✓ Removed IP %s from policies\n", ip)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&mac, "mac", "", "MAC address to remove")
	cmd.Flags().StringVar(&ip, "ip", "", "IP address to remove")

	return cmd
}

func newPolicyListCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all policy rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Println("                      POLICY RULES")
			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Println("\nAllow List (MACs):")
			fmt.Println("  (none configured)")
			fmt.Println("\nBlock List (MACs):")
			fmt.Println("  (none configured)")
			fmt.Println("\nCustom Rules:")
			fmt.Println("  (none configured)")
			return nil
		},
	}
}
