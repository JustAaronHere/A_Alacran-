package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/sandbox"
	"github.com/spf13/cobra"
)

type sandboxOptions struct {
	evidenceID string
	image      string
	timeout    int
	scriptPath string
}

func newSandboxVerifyCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	opts := &sandboxOptions{}

	cmd := &cobra.Command{
		Use:   "sandbox-verify",
		Short: "Verify exploits or suspicious behavior in sandbox",
		Long: `Run verification tests in isolated sandbox environment.

The sandbox provides:
- Network isolation
- Resource limits (CPU, memory)
- Timeboxed execution
- Read-only filesystem
- Automatic cleanup

Examples:
  revenant sandbox-verify --evidence=evt-123456
  revenant sandbox-verify --script=./verify.sh --image=alpine:latest
  revenant sandbox-verify --evidence=evt-789 --timeout=300`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSandboxVerify(ctx, logger, opts)
		},
	}

	cmd.Flags().StringVar(&opts.evidenceID, "evidence", "", "evidence ID to verify")
	cmd.Flags().StringVar(&opts.image, "image", "alpine:latest", "container image to use")
	cmd.Flags().IntVar(&opts.timeout, "timeout", 300, "sandbox timeout in seconds")
	cmd.Flags().StringVar(&opts.scriptPath, "script", "", "verification script path")

	return cmd
}

func runSandboxVerify(ctx context.Context, logger *logging.Logger, opts *sandboxOptions) error {
	logger.Info("Starting sandbox verification",
		logging.WithAction("sandbox_verify"),
		logging.WithExtra("evidence_id", opts.evidenceID),
	)

	manager := sandbox.NewSandboxManager(logger, 50)

	config := &sandbox.SandboxConfig{
		Type:            sandbox.SandboxTypeContainer,
		Image:           opts.image,
		Timeout:         time.Duration(opts.timeout) * time.Second,
		NetworkIsolated: true,
		ReadOnly:        true,
		CPULimit:        1,
		MemoryLimit:     512 * 1024 * 1024,
	}

	sb, err := manager.Create(config)
	if err != nil {
		return fmt.Errorf("failed to create sandbox: %w", err)
	}

	logger.Info("Sandbox created",
		logging.WithExtra("sandbox_id", sb.ID),
	)

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                 SANDBOX VERIFICATION")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("Sandbox ID:     %s\n", sb.ID)
	fmt.Printf("Type:           %s\n", sb.Type)
	fmt.Printf("Image:          %s\n", config.Image)
	fmt.Printf("Timeout:        %d seconds\n", opts.timeout)
	fmt.Printf("Isolated:       %v\n", config.NetworkIsolated)
	fmt.Println("═══════════════════════════════════════════════════════════════")

	fmt.Println("\nStarting sandbox execution...")

	if err := manager.Start(ctx, sb.ID); err != nil {
		return fmt.Errorf("sandbox execution failed: %w", err)
	}

	sb, err = manager.Get(sb.ID)
	if err != nil {
		return fmt.Errorf("failed to get sandbox status: %w", err)
	}

	fmt.Println("\n✓ Sandbox execution completed")
	fmt.Printf("\nStatus:         %s\n", sb.Status)
	fmt.Printf("Exit Code:      %d\n", sb.ExitCode)
	if sb.Output != "" {
		fmt.Printf("Output:         %s\n", sb.Output)
	}

	if sb.StartedAt != nil && sb.StoppedAt != nil {
		duration := sb.StoppedAt.Sub(*sb.StartedAt)
		fmt.Printf("Duration:       %s\n", duration)
	}

	return nil
}
