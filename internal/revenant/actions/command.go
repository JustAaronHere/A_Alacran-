package actions

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/orchestrator"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/playbooks"
)

type CommandAction struct {
	logger    *logging.Logger
	dryRun    bool
	allowList map[string]bool
}

func NewCommandAction(logger *logging.Logger, dryRun bool) *CommandAction {
	return &CommandAction{
		logger:    logger,
		dryRun:    dryRun,
		allowList: make(map[string]bool),
	}
}

func (ca *CommandAction) Execute(ctx context.Context, step playbooks.Step, vars map[string]interface{}) (*orchestrator.ActionRecord, error) {
	start := time.Now()
	record := &orchestrator.ActionRecord{
		ID:        fmt.Sprintf("action-%d", time.Now().UnixNano()),
		Name:      step.Name,
		Type:      step.Type,
		Status:    "running",
		StartedAt: start,
		Success:   false,
		Metadata:  make(map[string]interface{}),
	}

	command := step.Action
	if cmd, ok := step.Params["command"].(string); ok {
		command = cmd
	}

	command = ca.interpolateVars(command, vars)

	ca.logger.Info("Executing command",
		logging.WithAction("command"),
		logging.WithExtra("command", command),
		logging.WithExtra("dry_run", ca.dryRun),
	)

	var output string
	var err error

	if ca.dryRun {
		output = fmt.Sprintf("[DRY RUN] Would execute: %s", command)
		ca.logger.Info(output)
	} else {
		output, err = ca.executeCommand(ctx, command)
	}

	completed := time.Now()
	record.CompletedAt = &completed
	record.Duration = completed.Sub(start)

	if err != nil {
		record.Status = "failed"
		record.Error = err.Error()
		record.Output = output
		return record, err
	}

	record.Status = "completed"
	record.Success = true
	record.Output = output

	return record, nil
}

func (ca *CommandAction) executeCommand(ctx context.Context, command string) (string, error) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty command")
	}

	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command failed: %w", err)
	}

	return string(output), nil
}

func (ca *CommandAction) interpolateVars(command string, vars map[string]interface{}) string {
	result := command
	for key, value := range vars {
		placeholder := fmt.Sprintf("{{%s}}", key)
		result = strings.ReplaceAll(result, placeholder, fmt.Sprintf("%v", value))
	}
	return result
}

func (ca *CommandAction) Rollback(ctx context.Context, step playbooks.Step, vars map[string]interface{}) error {
	ca.logger.Info("Rolling back command action",
		logging.WithExtra("step", step.Name),
	)
	return nil
}
