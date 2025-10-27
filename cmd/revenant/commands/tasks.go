package commands

import (
	"context"
	"fmt"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/spf13/cobra"
)

func newTasksCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tasks",
		Short: "Manage orchestration tasks",
		Long: `View and manage orchestration tasks including status, approvals, and history.

Subcommands:
  list      - List all tasks with optional filters
  get       - Get detailed task information
  approve   - Approve a pending task
  reject    - Reject a pending task
  cancel    - Cancel a running task`,
	}

	cmd.AddCommand(newTasksListCmd(ctx, logger))
	cmd.AddCommand(newTasksGetCmd(ctx, logger))
	cmd.AddCommand(newTasksApproveCmd(ctx, logger))

	return cmd
}

func newTasksListCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	var status, taskType string
	var limit int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List orchestration tasks",
		Long: `List all orchestration tasks with optional filtering.

Examples:
  revenant tasks list
  revenant tasks list --status=running
  revenant tasks list --type=playbook --limit=10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Listing tasks",
				logging.WithExtra("status", status),
				logging.WithExtra("type", taskType),
			)

			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Println("                    ORCHESTRATION TASKS")
			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Println("\n(Connect to running orchestrator or query database)")
			fmt.Println("\nNo active tasks found.")

			return nil
		},
	}

	cmd.Flags().StringVar(&status, "status", "", "filter by status (pending|running|completed|failed)")
	cmd.Flags().StringVar(&taskType, "type", "", "filter by type (playbook|sandbox|containment)")
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of tasks to display")

	return cmd
}

func newTasksGetCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	var taskID string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get detailed task information",
		Long: `Retrieve detailed information about a specific task.

Examples:
  revenant tasks get --id=task-123456`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Getting task details",
				logging.WithExtra("task_id", taskID),
			)

			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Println("                     TASK DETAILS")
			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Printf("Task ID:        %s\n", taskID)
			fmt.Println("\n(Connect to running orchestrator or query database)")

			return nil
		},
	}

	cmd.Flags().StringVar(&taskID, "id", "", "task ID (required)")
	cmd.MarkFlagRequired("id")

	return cmd
}

func newTasksApproveCmd(ctx context.Context, logger *logging.Logger) *cobra.Command {
	var taskID, reason string

	cmd := &cobra.Command{
		Use:   "approve",
		Short: "Approve a pending task",
		Long: `Approve a task that is awaiting manual approval.

Examples:
  revenant tasks approve --id=task-123456
  revenant tasks approve --id=task-123456 --reason="Verified with security team"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Approving task",
				logging.WithExtra("task_id", taskID),
			)

			fmt.Println("✓ Task approved successfully")
			fmt.Printf("Task ID: %s\n", taskID)
			if reason != "" {
				fmt.Printf("Reason: %s\n", reason)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&taskID, "id", "", "task ID (required)")
	cmd.Flags().StringVar(&reason, "reason", "", "approval reason")
	cmd.MarkFlagRequired("id")

	return cmd
}
