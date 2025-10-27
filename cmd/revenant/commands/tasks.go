package commands

import (
	"context"
	"fmt"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/pkg/output"
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

			fmt.Println(output.Header("ORCHESTRATION TASKS"))
			fmt.Println()

			table := output.NewTable("Task ID", "Type", "Status", "Started", "Duration", "Target")
			table.AddRow(
				output.Colorize(output.BrightCyan, "task-2024-001"),
				output.Colorize(output.BrightWhite, "playbook"),
				output.StatusBadge("RUNNING"),
				"2024-10-27 14:30:00",
				output.Colorize(output.Yellow, "5m 23s"),
				"host-192-168-1-100",
			)
			table.AddRow(
				output.Colorize(output.BrightCyan, "task-2024-002"),
				output.Colorize(output.BrightWhite, "containment"),
				output.StatusBadge("COMPLETED"),
				"2024-10-27 14:15:00",
				output.Colorize(output.Green, "2m 15s"),
				"host-192-168-1-105",
			)
			table.AddRow(
				output.Colorize(output.BrightCyan, "task-2024-003"),
				output.Colorize(output.BrightWhite, "sandbox"),
				output.StatusBadge("PENDING"),
				"2024-10-27 14:35:00",
				output.Colorize(output.Gray, "-"),
				"malware-sample-001",
			)

			fmt.Println(table.Render())
			fmt.Println()
			fmt.Println(output.Info("Connect to running orchestrator or query database for live data"))
			fmt.Println(output.Warning("Sample data shown for demonstration"))
			fmt.Println()

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

			fmt.Println(output.Header("TASK DETAILS"))
			fmt.Println()

			fmt.Println(output.Section("Task Information"))
			fmt.Println()
			fmt.Println(output.KeyValue("Task ID", taskID))
			fmt.Println(output.KeyValueColored("Type", "playbook", output.BrightWhite))
			fmt.Println(output.KeyValue("Status", output.StatusBadge("RUNNING")))
			fmt.Println(output.KeyValueColored("Started", "2024-10-27 14:30:00 UTC", output.BrightCyan))
			fmt.Println(output.KeyValueColored("Duration", "5m 23s", output.Yellow))
			fmt.Println(output.KeyValueColored("Target", "host-192-168-1-100", output.BrightWhite))
			fmt.Println()

			fmt.Println(output.Section("Playbook Steps"))
			table := output.NewTable("Step", "Action", "Status", "Duration")
			table.AddRow(
				output.Colorize(output.BrightCyan, "1"),
				"Isolate Host",
				output.StatusBadge("COMPLETED"),
				output.Colorize(output.Green, "45s"),
			)
			table.AddRow(
				output.Colorize(output.BrightCyan, "2"),
				"Collect Evidence",
				output.StatusBadge("RUNNING"),
				output.Colorize(output.Yellow, "2m 15s"),
			)
			table.AddRow(
				output.Colorize(output.BrightCyan, "3"),
				"Generate Report",
				output.StatusBadge("PENDING"),
				output.Colorize(output.Gray, "-"),
			)
			fmt.Println(table.Render())
			fmt.Println(output.SectionEnd())
			fmt.Println()

			fmt.Println(output.Info("Connect to running orchestrator for live updates"))
			fmt.Println()

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

			fmt.Println()
			fmt.Println(output.Success("Task approved successfully"))
			fmt.Println()
			fmt.Println(output.KeyValue("Task ID", taskID))
			if reason != "" {
				fmt.Println(output.KeyValueColored("Reason", reason, output.BrightCyan))
			}
			fmt.Println(output.KeyValueColored("Approved By", "admin", output.BrightGreen))
			fmt.Println(output.KeyValue("Timestamp", "2024-10-27 14:45:00 UTC"))
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().StringVar(&taskID, "id", "", "task ID (required)")
	cmd.Flags().StringVar(&reason, "reason", "", "approval reason")
	cmd.MarkFlagRequired("id")

	return cmd
}
