package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/common/store"
	"github.com/aegis-sentinel/aegis-suite/internal/common/telemetry"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/actions"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/orchestrator"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/playbooks"
	"github.com/spf13/cobra"
)

type runPlaybookOptions struct {
	playbookPath string
	target       string
	autoApprove  bool
	dryRun       bool
	vars         map[string]string
	dbPath       string
}

func newRunPlaybookCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	opts := &runPlaybookOptions{
		vars: make(map[string]string),
	}

	cmd := &cobra.Command{
		Use:   "run-playbook",
		Short: "Run a remediation playbook",
		Long: `Execute a remediation playbook against a target host or device.

Playbooks define a sequence of actions such as:
- Containment (isolate, quarantine, block)
- Verification (sandbox testing, exploit validation)
- Remediation (patch, restart, reconfigure)
- Rollback procedures

Examples:
  revenant run-playbook --playbook=./playbooks/isolate.yaml --target=192.168.1.100
  revenant run-playbook --playbook=./playbooks/patch.yaml --target=host-123 --auto-approve
  revenant run-playbook --playbook=./playbooks/remediate.yaml --target=10.0.0.50 --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlaybook(ctx, logger, opts)
		},
	}

	cmd.Flags().StringVar(&opts.playbookPath, "playbook", "", "path to playbook YAML file (required)")
	cmd.Flags().StringVar(&opts.target, "target", "", "target host or device (required)")
	cmd.Flags().BoolVar(&opts.autoApprove, "auto-approve", false, "automatically approve execution")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "simulate execution without making changes")
	cmd.Flags().StringVar(&opts.dbPath, "db-path", "./data/revenant.db", "database path")
	cmd.MarkFlagRequired("playbook")
	cmd.MarkFlagRequired("target")

	return cmd
}

func runPlaybook(ctx context.Context, logger *logging.Logger, opts *runPlaybookOptions) error {
	logger.Info("Initializing Revenant orchestrator",
		logging.WithAction("init"),
	)

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

	playbook, err := playbooks.LoadPlaybook(opts.playbookPath)
	if err != nil {
		return fmt.Errorf("failed to load playbook: %w", err)
	}

	logger.Info("Loaded playbook",
		logging.WithExtra("playbook_id", playbook.ID),
		logging.WithExtra("name", playbook.Name),
		logging.WithExtra("steps", len(playbook.Steps)),
	)

	if err := playbooks.ValidatePlaybook(playbook); err != nil {
		return fmt.Errorf("playbook validation failed: %w", err)
	}

	playbookExecutor := playbooks.NewPlaybookExecutor(logger)
	playbookExecutor.RegisterAction("containment", actions.NewContainmentAction(logger))
	playbookExecutor.RegisterAction("command", actions.NewCommandAction(logger, opts.dryRun))

	engineConfig := &orchestrator.EngineConfig{
		Workers:    5,
		MaxRetries: 3,
		RetryDelay: 5 * time.Second,
		QueueSize:  100,
	}

	engine := orchestrator.NewEngine(engineConfig, logger, metrics, playbookExecutor)
	engine.Start()
	defer engine.Stop()

	task := &orchestrator.Task{
		Type:             orchestrator.TaskTypePlaybook,
		TargetHost:       opts.target,
		PlaybookID:       playbook.ID,
		CreatedBy:        "cli-operator",
		AutoApprove:      opts.autoApprove,
		RequiresApproval: playbook.RequiresApproval && !opts.autoApprove,
		Metadata: map[string]interface{}{
			"playbook_path": opts.playbookPath,
			"dry_run":       opts.dryRun,
		},
	}

	if err := engine.SubmitTask(task); err != nil {
		return fmt.Errorf("failed to submit task: %w", err)
	}

	logger.Info("Task submitted",
		logging.WithExtra("task_id", task.ID),
		logging.WithExtra("target", opts.target),
	)

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                   PLAYBOOK EXECUTION")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("Task ID:        %s\n", task.ID)
	fmt.Printf("Playbook:       %s\n", playbook.Name)
	fmt.Printf("Target:         %s\n", opts.target)
	fmt.Printf("Status:         %s\n", task.Status)
	if opts.dryRun {
		fmt.Println("Mode:           DRY RUN (no changes will be made)")
	}
	fmt.Println("═══════════════════════════════════════════════════════════════")

	if task.RequiresApproval {
		fmt.Println("\n⚠ This task requires manual approval")
		fmt.Printf("Use 'revenant tasks approve --id=%s' to approve\n", task.ID)
		return nil
	}

	fmt.Println("\nWaiting for task to complete...")
	
	for i := 0; i < 60; i++ {
		time.Sleep(1 * time.Second)
		
		updatedTask, err := engine.GetTask(task.ID)
		if err != nil {
			return fmt.Errorf("failed to get task status: %w", err)
		}

		if updatedTask.Status == orchestrator.TaskStatusCompleted {
			fmt.Println("\n✓ Task completed successfully")
			
			if updatedTask.Result != nil {
				fmt.Printf("\nDuration:       %s\n", updatedTask.Result.Duration)
				fmt.Printf("Actions Run:    %d\n", updatedTask.Result.ActionsRun)
				fmt.Printf("Actions Failed: %d\n", updatedTask.Result.ActionsFailed)
				fmt.Printf("Changes Made:   %d\n", len(updatedTask.Result.Changes))
			}
			
			return nil
		}

		if updatedTask.Status == orchestrator.TaskStatusFailed {
			fmt.Println("\n✗ Task failed")
			if updatedTask.Error != "" {
				fmt.Printf("Error: %s\n", updatedTask.Error)
			}
			return fmt.Errorf("task execution failed")
		}

		if i%5 == 0 {
			fmt.Printf(".")
		}
	}

	fmt.Println("\n⚠ Task still running after timeout")
	fmt.Printf("Check status with: revenant tasks get --id=%s\n", task.ID)

	return nil
}
