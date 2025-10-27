package playbooks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/orchestrator"
	"gopkg.in/yaml.v3"
)

type Playbook struct {
	ID          string                 `yaml:"id" json:"id"`
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description" json:"description"`
	Version     string                 `yaml:"version" json:"version"`
	Author      string                 `yaml:"author" json:"author"`
	Tags        []string               `yaml:"tags" json:"tags"`
	RequiresApproval bool              `yaml:"requires_approval" json:"requires_approval"`
	Idempotent  bool                   `yaml:"idempotent" json:"idempotent"`
	Timeout     time.Duration          `yaml:"timeout" json:"timeout"`
	Variables   map[string]interface{} `yaml:"variables,omitempty" json:"variables,omitempty"`
	Steps       []Step                 `yaml:"steps" json:"steps"`
	Rollback    []Step                 `yaml:"rollback,omitempty" json:"rollback,omitempty"`
	Metadata    map[string]interface{} `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

type Step struct {
	Name        string                 `yaml:"name" json:"name"`
	Type        string                 `yaml:"type" json:"type"`
	Action      string                 `yaml:"action" json:"action"`
	Target      string                 `yaml:"target,omitempty" json:"target,omitempty"`
	Params      map[string]interface{} `yaml:"params,omitempty" json:"params,omitempty"`
	Condition   string                 `yaml:"condition,omitempty" json:"condition,omitempty"`
	ContinueOnError bool               `yaml:"continue_on_error" json:"continue_on_error"`
	Timeout     time.Duration          `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Retry       *RetryConfig           `yaml:"retry,omitempty" json:"retry,omitempty"`
}

type RetryConfig struct {
	MaxAttempts int           `yaml:"max_attempts" json:"max_attempts"`
	Delay       time.Duration `yaml:"delay" json:"delay"`
	BackoffMultiplier float64 `yaml:"backoff_multiplier,omitempty" json:"backoff_multiplier,omitempty"`
}

type PlaybookExecutor struct {
	logger    *logging.Logger
	actions   map[string]ActionHandler
}

type ActionHandler interface {
	Execute(ctx context.Context, step Step, vars map[string]interface{}) (*orchestrator.ActionRecord, error)
	Rollback(ctx context.Context, step Step, vars map[string]interface{}) error
}

func NewPlaybookExecutor(logger *logging.Logger) *PlaybookExecutor {
	return &PlaybookExecutor{
		logger:  logger,
		actions: make(map[string]ActionHandler),
	}
}

func (pe *PlaybookExecutor) RegisterAction(actionType string, handler ActionHandler) {
	pe.actions[actionType] = handler
}

func (pe *PlaybookExecutor) Execute(ctx context.Context, task *orchestrator.Task) (*orchestrator.TaskResult, error) {
	playbookPath := task.Metadata["playbook_path"].(string)
	
	playbook, err := LoadPlaybook(playbookPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load playbook: %w", err)
	}

	pe.logger.Info("Executing playbook",
		logging.WithExtra("playbook_id", playbook.ID),
		logging.WithExtra("steps", len(playbook.Steps)),
	)

	start := time.Now()
	result := &orchestrator.TaskResult{
		Success:    true,
		ActionsRun: 0,
		Changes:    make([]orchestrator.Change, 0),
		Evidence:   make([]string, 0),
		Metadata:   make(map[string]interface{}),
	}

	vars := make(map[string]interface{})
	for k, v := range playbook.Variables {
		vars[k] = v
	}
	if task.Metadata != nil {
		for k, v := range task.Metadata {
			vars[k] = v
		}
	}
	vars["target"] = task.TargetHost
	vars["task_id"] = task.ID

	executedActions := make([]*orchestrator.ActionRecord, 0)

	for i, step := range playbook.Steps {
		pe.logger.Debug(fmt.Sprintf("Executing step %d: %s", i+1, step.Name))

		if step.Condition != "" && !pe.evaluateCondition(step.Condition, vars) {
			pe.logger.Debug(fmt.Sprintf("Skipping step %d: condition not met", i+1))
			continue
		}

		handler, exists := pe.actions[step.Type]
		if !exists {
			return nil, fmt.Errorf("unknown action type: %s", step.Type)
		}

		stepCtx := ctx
		if step.Timeout > 0 {
			var cancel context.CancelFunc
			stepCtx, cancel = context.WithTimeout(ctx, step.Timeout)
			defer cancel()
		}

		actionRecord, err := pe.executeStepWithRetry(stepCtx, step, handler, vars)

		if err != nil {
			pe.logger.Error(fmt.Sprintf("Step %d failed", i+1),
				logging.WithError(err),
				logging.WithExtra("step_name", step.Name),
			)

			result.ActionsFailed++

			if !step.ContinueOnError {
				result.Success = false
				result.Message = fmt.Sprintf("Step '%s' failed: %v", step.Name, err)
				
				pe.logger.Warning("Rolling back playbook execution")
				if err := pe.rollback(ctx, playbook, executedActions); err != nil {
					pe.logger.Error("Rollback failed", logging.WithError(err))
				}

				return result, err
			}
		} else {
			result.ActionsRun++
			executedActions = append(executedActions, actionRecord)
			
			if actionRecord != nil && len(actionRecord.Changes) > 0 {
				result.Changes = append(result.Changes, actionRecord.Changes...)
			}
		}
	}

	result.Duration = time.Since(start)
	result.Message = fmt.Sprintf("Playbook executed successfully: %d actions run, %d failed", result.ActionsRun, result.ActionsFailed)

	pe.logger.Info("Playbook execution completed",
		logging.WithExtra("playbook_id", playbook.ID),
		logging.WithExtra("duration", result.Duration.String()),
		logging.WithExtra("actions_run", result.ActionsRun),
	)

	return result, nil
}

func (pe *PlaybookExecutor) executeStepWithRetry(ctx context.Context, step Step, handler ActionHandler, vars map[string]interface{}) (*orchestrator.ActionRecord, error) {
	maxAttempts := 1
	delay := time.Second
	backoff := 1.5

	if step.Retry != nil {
		maxAttempts = step.Retry.MaxAttempts
		if step.Retry.Delay > 0 {
			delay = step.Retry.Delay
		}
		if step.Retry.BackoffMultiplier > 0 {
			backoff = step.Retry.BackoffMultiplier
		}
	}

	var lastErr error
	currentDelay := delay

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		actionRecord, err := handler.Execute(ctx, step, vars)
		if err == nil {
			return actionRecord, nil
		}

		lastErr = err
		pe.logger.Warning(fmt.Sprintf("Step attempt %d/%d failed", attempt, maxAttempts),
			logging.WithError(err),
		)

		if attempt < maxAttempts {
			time.Sleep(currentDelay)
			currentDelay = time.Duration(float64(currentDelay) * backoff)
		}
	}

	return nil, fmt.Errorf("step failed after %d attempts: %w", maxAttempts, lastErr)
}

func (pe *PlaybookExecutor) rollback(ctx context.Context, playbook *Playbook, executedActions []*orchestrator.ActionRecord) error {
	pe.logger.Info("Starting rollback",
		logging.WithExtra("actions_to_rollback", len(executedActions)),
	)

	for i := len(executedActions) - 1; i >= 0; i-- {
		action := executedActions[i]
		pe.logger.Debug(fmt.Sprintf("Rolling back action: %s", action.Name))
	}

	if len(playbook.Rollback) > 0 {
		for _, step := range playbook.Rollback {
			handler, exists := pe.actions[step.Type]
			if !exists {
				pe.logger.Warning(fmt.Sprintf("No handler for rollback step: %s", step.Type))
				continue
			}

			if err := handler.Rollback(ctx, step, make(map[string]interface{})); err != nil {
				pe.logger.Error("Rollback step failed",
					logging.WithError(err),
					logging.WithExtra("step_name", step.Name),
				)
			}
		}
	}

	return nil
}

func (pe *PlaybookExecutor) evaluateCondition(condition string, vars map[string]interface{}) bool {
	return true
}

func (pe *PlaybookExecutor) Rollback(ctx context.Context, task *orchestrator.Task) error {
	return nil
}

func LoadPlaybook(path string) (*Playbook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read playbook file: %w", err)
	}

	var playbook Playbook
	if err := yaml.Unmarshal(data, &playbook); err != nil {
		return nil, fmt.Errorf("failed to parse playbook: %w", err)
	}

	if playbook.Timeout == 0 {
		playbook.Timeout = 10 * time.Minute
	}

	return &playbook, nil
}

func LoadPlaybooksFromDir(dirPath string) ([]*Playbook, error) {
	playbooks := make([]*Playbook, 0)

	files, err := filepath.Glob(filepath.Join(dirPath, "*.yaml"))
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		playbook, err := LoadPlaybook(file)
		if err != nil {
			continue
		}
		playbooks = append(playbooks, playbook)
	}

	return playbooks, nil
}

func ValidatePlaybook(playbook *Playbook) error {
	if playbook.ID == "" {
		return fmt.Errorf("playbook ID is required")
	}
	if playbook.Name == "" {
		return fmt.Errorf("playbook name is required")
	}
	if len(playbook.Steps) == 0 {
		return fmt.Errorf("playbook must have at least one step")
	}

	for i, step := range playbook.Steps {
		if step.Name == "" {
			return fmt.Errorf("step %d: name is required", i)
		}
		if step.Type == "" {
			return fmt.Errorf("step %d: type is required", i)
		}
	}

	return nil
}
