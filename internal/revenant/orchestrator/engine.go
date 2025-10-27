package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/common/telemetry"
	"github.com/google/uuid"
)

type Engine struct {
	logger        *logging.Logger
	metrics       *telemetry.Metrics
	
	tasks         map[string]*Task
	taskQueue     chan *Task
	deadLetterQ   chan *Task
	mu            sync.RWMutex
	
	workers       int
	maxRetries    int
	retryDelay    time.Duration
	
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	
	approvalQueue map[string]*ApprovalRequest
	approvalMu    sync.RWMutex
	
	executor      TaskExecutor
}

type TaskExecutor interface {
	Execute(ctx context.Context, task *Task) (*TaskResult, error)
	Rollback(ctx context.Context, task *Task) error
}

type EngineConfig struct {
	Workers       int
	MaxRetries    int
	RetryDelay    time.Duration
	QueueSize     int
	DeadLetterSize int
}

func NewEngine(config *EngineConfig, logger *logging.Logger, metrics *telemetry.Metrics, executor TaskExecutor) *Engine {
	if config.Workers == 0 {
		config.Workers = 10
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 5 * time.Second
	}
	if config.QueueSize == 0 {
		config.QueueSize = 1000
	}
	if config.DeadLetterSize == 0 {
		config.DeadLetterSize = 100
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Engine{
		logger:        logger,
		metrics:       metrics,
		tasks:         make(map[string]*Task),
		taskQueue:     make(chan *Task, config.QueueSize),
		deadLetterQ:   make(chan *Task, config.DeadLetterSize),
		workers:       config.Workers,
		maxRetries:    config.MaxRetries,
		retryDelay:    config.RetryDelay,
		ctx:           ctx,
		cancel:        cancel,
		approvalQueue: make(map[string]*ApprovalRequest),
		executor:      executor,
	}
}

func (e *Engine) Start() {
	e.logger.Info("Starting orchestration engine",
		logging.WithExtra("workers", e.workers),
		logging.WithExtra("max_retries", e.maxRetries),
	)

	for i := 0; i < e.workers; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}

	e.wg.Add(1)
	go e.deadLetterWorker()

	e.metrics.SetCustomGauge("revenant_workers", int64(e.workers))
}

func (e *Engine) Stop() {
	e.logger.Info("Stopping orchestration engine")
	e.cancel()
	e.wg.Wait()
	close(e.taskQueue)
	close(e.deadLetterQ)
}

func (e *Engine) SubmitTask(task *Task) error {
	if task.ID == "" {
		task.ID = uuid.New().String()
	}

	if task.CreatedAt.IsZero() {
		task.CreatedAt = time.Now()
	}

	if task.MaxRetries == 0 {
		task.MaxRetries = e.maxRetries
	}

	task.Status = TaskStatusPending

	e.mu.Lock()
	e.tasks[task.ID] = task
	e.mu.Unlock()

	if task.RequiresApproval && !task.AutoApprove {
		task.Status = TaskStatusApproving
		e.requestApproval(task)
		e.logger.Info("Task submitted for approval",
			logging.WithExtra("task_id", task.ID),
			logging.WithExtra("type", task.Type),
		)
		return nil
	}

	select {
	case e.taskQueue <- task:
		e.metrics.IncrementCustomCounter("revenant_tasks_submitted")
		e.logger.Info("Task submitted",
			logging.WithExtra("task_id", task.ID),
			logging.WithExtra("type", task.Type),
		)
		return nil
	default:
		return fmt.Errorf("task queue full")
	}
}

func (e *Engine) worker(id int) {
	defer e.wg.Done()

	e.logger.Debug(fmt.Sprintf("Worker %d started", id))

	for {
		select {
		case <-e.ctx.Done():
			return
		case task := <-e.taskQueue:
			e.metrics.IncrementActiveWorkers()
			e.processTask(task)
			e.metrics.DecrementActiveWorkers()
		}
	}
}

func (e *Engine) processTask(task *Task) {
	e.logger.Info("Processing task",
		logging.WithAction("task_execute"),
		logging.WithExtra("task_id", task.ID),
		logging.WithExtra("type", task.Type),
	)

	task.Status = TaskStatusRunning
	now := time.Now()
	task.StartedAt = &now

	e.metrics.IncrementCustomCounter("revenant_tasks_started")

	ctx, cancel := context.WithTimeout(e.ctx, 5*time.Minute)
	defer cancel()

	result, err := e.executor.Execute(ctx, task)

	if err != nil {
		e.handleTaskError(task, err)
		return
	}

	task.Result = result
	completed := time.Now()
	task.CompletedAt = &completed
	task.Status = TaskStatusCompleted

	e.metrics.IncrementCustomCounter("revenant_tasks_completed")
	e.metrics.IncrementSuccessTasks()

	e.logger.Info("Task completed successfully",
		logging.WithExtra("task_id", task.ID),
		logging.WithExtra("duration", result.Duration.String()),
	)
}

func (e *Engine) handleTaskError(task *Task, err error) {
	task.Error = err.Error()
	task.RetryCount++

	e.logger.Warning("Task execution failed",
		logging.WithExtra("task_id", task.ID),
		logging.WithExtra("error", err.Error()),
		logging.WithExtra("retry_count", task.RetryCount),
	)

	if task.RetryCount < task.MaxRetries {
		task.Status = TaskStatusPending
		go func() {
			time.Sleep(e.retryDelay * time.Duration(task.RetryCount))
			select {
			case e.taskQueue <- task:
				e.logger.Info("Task requeued for retry",
					logging.WithExtra("task_id", task.ID),
					logging.WithExtra("retry_count", task.RetryCount),
				)
			case <-e.ctx.Done():
			}
		}()
	} else {
		task.Status = TaskStatusFailed
		completed := time.Now()
		task.CompletedAt = &completed

		select {
		case e.deadLetterQ <- task:
			e.logger.Error("Task moved to dead letter queue",
				logging.WithExtra("task_id", task.ID),
			)
		default:
			e.logger.Error("Dead letter queue full, task dropped",
				logging.WithExtra("task_id", task.ID),
			)
		}

		e.metrics.IncrementFailedTasks()
	}
}

func (e *Engine) deadLetterWorker() {
	defer e.wg.Done()

	for {
		select {
		case <-e.ctx.Done():
			return
		case task := <-e.deadLetterQ:
			e.logger.Error("Task in dead letter queue",
				logging.WithExtra("task_id", task.ID),
				logging.WithExtra("error", task.Error),
				logging.WithExtra("retries", task.RetryCount),
			)
		}
	}
}

func (e *Engine) requestApproval(task *Task) {
	request := &ApprovalRequest{
		TaskID:      task.ID,
		RequestedAt: time.Now(),
		RequestedBy: task.CreatedBy,
		Reason:      "Manual approval required",
		TaskDetails: task,
	}

	e.approvalMu.Lock()
	e.approvalQueue[task.ID] = request
	e.approvalMu.Unlock()

	e.logger.Info("Approval requested",
		logging.WithExtra("task_id", task.ID),
	)
}

func (e *Engine) ApproveTask(taskID, approver, reason string) error {
	e.approvalMu.Lock()
	request, exists := e.approvalQueue[taskID]
	if !exists {
		e.approvalMu.Unlock()
		return fmt.Errorf("approval request not found: %s", taskID)
	}
	delete(e.approvalQueue, taskID)
	e.approvalMu.Unlock()

	task := request.TaskDetails
	task.Status = TaskStatusPending
	task.ApprovedBy = approver

	e.logger.Info("Task approved",
		logging.WithExtra("task_id", taskID),
		logging.WithExtra("approved_by", approver),
	)

	return e.SubmitTask(task)
}

func (e *Engine) RejectTask(taskID, rejecter, reason string) error {
	e.approvalMu.Lock()
	request, exists := e.approvalQueue[taskID]
	if !exists {
		e.approvalMu.Unlock()
		return fmt.Errorf("approval request not found: %s", taskID)
	}
	delete(e.approvalQueue, taskID)
	e.approvalMu.Unlock()

	task := request.TaskDetails
	task.Status = TaskStatusCancelled
	completed := time.Now()
	task.CompletedAt = &completed
	task.Error = fmt.Sprintf("Rejected by %s: %s", rejecter, reason)

	e.logger.Info("Task rejected",
		logging.WithExtra("task_id", taskID),
		logging.WithExtra("rejected_by", rejecter),
	)

	return nil
}

func (e *Engine) GetTask(taskID string) (*Task, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	task, exists := e.tasks[taskID]
	if !exists {
		return nil, fmt.Errorf("task not found: %s", taskID)
	}

	return task, nil
}

func (e *Engine) ListTasks(filter *TaskFilter) []*Task {
	e.mu.RLock()
	defer e.mu.RUnlock()

	tasks := make([]*Task, 0)

	for _, task := range e.tasks {
		if e.matchesFilter(task, filter) {
			tasks = append(tasks, task)
		}

		if filter != nil && filter.Limit > 0 && len(tasks) >= filter.Limit {
			break
		}
	}

	return tasks
}

func (e *Engine) matchesFilter(task *Task, filter *TaskFilter) bool {
	if filter == nil {
		return true
	}

	if len(filter.Status) > 0 {
		match := false
		for _, status := range filter.Status {
			if task.Status == status {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}

	if len(filter.Type) > 0 {
		match := false
		for _, taskType := range filter.Type {
			if task.Type == taskType {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}

	if filter.CreatedAfter != nil && task.CreatedAt.Before(*filter.CreatedAfter) {
		return false
	}

	if filter.TargetHost != "" && task.TargetHost != filter.TargetHost {
		return false
	}

	if filter.CreatedBy != "" && task.CreatedBy != filter.CreatedBy {
		return false
	}

	return true
}

func (e *Engine) GetPendingApprovals() []*ApprovalRequest {
	e.approvalMu.RLock()
	defer e.approvalMu.RUnlock()

	requests := make([]*ApprovalRequest, 0, len(e.approvalQueue))
	for _, request := range e.approvalQueue {
		requests = append(requests, request)
	}

	return requests
}

func (e *Engine) Stats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	pending := 0
	running := 0
	completed := 0
	failed := 0

	for _, task := range e.tasks {
		switch task.Status {
		case TaskStatusPending:
			pending++
		case TaskStatusRunning:
			running++
		case TaskStatusCompleted:
			completed++
		case TaskStatusFailed:
			failed++
		}
	}

	return map[string]interface{}{
		"total_tasks":       len(e.tasks),
		"pending":           pending,
		"running":           running,
		"completed":         completed,
		"failed":            failed,
		"queue_depth":       len(e.taskQueue),
		"dead_letter_depth": len(e.deadLetterQ),
		"pending_approvals": len(e.approvalQueue),
	}
}
