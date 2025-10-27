package commands

import (
	"context"
	"fmt"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/playbooks"
	"github.com/spf13/cobra"
)

func newPlaybookCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "playbook",
		Short: "Manage remediation playbooks",
		Long: `Validate, list, and manage remediation playbooks.

Subcommands:
  validate  - Validate playbook syntax and structure
  list      - List available playbooks
  show      - Display playbook details`,
	}

	cmd.AddCommand(newPlaybookValidateCmd(ctx, logger))
	cmd.AddCommand(newPlaybookListCmd(ctx, logger))

	return cmd
}

func newPlaybookValidateCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	var playbookPath string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a playbook file",
		Long: `Validate playbook syntax and structure without executing it.

Examples:
  revenant playbook validate --file=./playbooks/isolate.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Validating playbook",
				logging.WithExtra("path", playbookPath),
			)

			playbook, err := playbooks.LoadPlaybook(playbookPath)
			if err != nil {
				return fmt.Errorf("failed to load playbook: %w", err)
			}

			if err := playbooks.ValidatePlaybook(playbook); err != nil {
				fmt.Printf("✗ Playbook validation failed:\n")
				fmt.Printf("  %s\n", err.Error())
				return err
			}

			fmt.Println("✓ Playbook validation successful")
			fmt.Printf("\nPlaybook: %s\n", playbook.Name)
			fmt.Printf("ID:       %s\n", playbook.ID)
			fmt.Printf("Steps:    %d\n", len(playbook.Steps))
			if playbook.RequiresApproval {
				fmt.Println("Approval: Required")
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&playbookPath, "file", "f", "", "playbook file path (required)")
	cmd.MarkFlagRequired("file")

	return cmd
}

func newPlaybookListCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	var directory string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available playbooks",
		Long: `List all playbooks in the specified directory.

Examples:
  revenant playbook list
  revenant playbook list --dir=./playbooks`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Listing playbooks",
				logging.WithExtra("directory", directory),
			)

			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Println("                  AVAILABLE PLAYBOOKS")
			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Printf("\nDirectory: %s\n", directory)
			fmt.Println("\n(Scan directory for .yaml files)")

			return nil
		},
	}

	cmd.Flags().StringVar(&directory, "dir", "./playbooks", "playbooks directory")

	return cmd
}
