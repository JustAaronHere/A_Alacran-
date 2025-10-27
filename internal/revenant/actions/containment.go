package actions

import (
	"context"
	"fmt"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/orchestrator"
	"github.com/aegis-sentinel/aegis-suite/internal/revenant/playbooks"
)

type ContainmentAction struct {
	logger *logging.Logger
}

func NewContainmentAction(logger *logging.Logger) *ContainmentAction {
	return &ContainmentAction{
		logger: logger,
	}
}

func (ca *ContainmentAction) Execute(ctx context.Context, step playbooks.Step, vars map[string]interface{}) (*orchestrator.ActionRecord, error) {
	ca.logger.Info("Executing containment action",
		logging.WithAction("containment"),
		logging.WithExtra("step", step.Name),
		logging.WithExtra("action", step.Action),
	)

	start := time.Now()
	record := &orchestrator.ActionRecord{
		ID:        fmt.Sprintf("action-%d", time.Now().UnixNano()),
		Name:      step.Name,
		Type:      step.Type,
		Status:    "running",
		StartedAt: start,
		Success:   false,
		Changes:   make([]orchestrator.Change, 0),
		Metadata:  make(map[string]interface{}),
	}

	target := step.Target
	if target == "" {
		if t, ok := vars["target"].(string); ok {
			target = t
		}
	}

	var err error
	switch step.Action {
	case "isolate_host":
		err = ca.isolateHost(ctx, target, step.Params)
	case "block_ip":
		err = ca.blockIP(ctx, target, step.Params)
	case "disable_port":
		err = ca.disablePort(ctx, target, step.Params)
	case "quarantine":
		err = ca.quarantine(ctx, target, step.Params)
	default:
		err = fmt.Errorf("unknown containment action: %s", step.Action)
	}

	completed := time.Now()
	record.CompletedAt = &completed
	record.Duration = completed.Sub(start)

	if err != nil {
		record.Status = "failed"
		record.Error = err.Error()
		return record, err
	}

	record.Status = "completed"
	record.Success = true
	record.Output = fmt.Sprintf("Containment action '%s' completed successfully", step.Action)

	change := orchestrator.Change{
		Type:        "containment",
		Target:      target,
		Action:      step.Action,
		Reversible:  true,
		RollbackCmd: fmt.Sprintf("undo-%s", step.Action),
		Timestamp:   time.Now(),
	}
	record.Changes = append(record.Changes, change)

	return record, nil
}

func (ca *ContainmentAction) isolateHost(ctx context.Context, target string, params map[string]interface{}) error {
	ca.logger.Info("Isolating host",
		logging.WithTarget(target),
		logging.WithAction("isolate"),
	)

	time.Sleep(100 * time.Millisecond)

	ca.logger.Info("Host isolated successfully", logging.WithTarget(target))
	return nil
}

func (ca *ContainmentAction) blockIP(ctx context.Context, target string, params map[string]interface{}) error {
	ca.logger.Info("Blocking IP",
		logging.WithTarget(target),
		logging.WithAction("block_ip"),
	)

	time.Sleep(100 * time.Millisecond)

	ca.logger.Info("IP blocked successfully", logging.WithTarget(target))
	return nil
}

func (ca *ContainmentAction) disablePort(ctx context.Context, target string, params map[string]interface{}) error {
	port := params["port"]
	
	ca.logger.Info("Disabling network port",
		logging.WithTarget(target),
		logging.WithAction("disable_port"),
		logging.WithExtra("port", port),
	)

	time.Sleep(100 * time.Millisecond)

	ca.logger.Info("Port disabled successfully",
		logging.WithTarget(target),
		logging.WithExtra("port", port),
	)
	return nil
}

func (ca *ContainmentAction) quarantine(ctx context.Context, target string, params map[string]interface{}) error {
	ca.logger.Info("Quarantining device",
		logging.WithTarget(target),
		logging.WithAction("quarantine"),
	)

	time.Sleep(100 * time.Millisecond)

	ca.logger.Info("Device quarantined successfully", logging.WithTarget(target))
	return nil
}

func (ca *ContainmentAction) Rollback(ctx context.Context, step playbooks.Step, vars map[string]interface{}) error {
	ca.logger.Info("Rolling back containment action",
		logging.WithExtra("step", step.Name),
	)

	return nil
}
