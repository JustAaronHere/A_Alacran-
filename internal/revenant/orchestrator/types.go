package orchestrator

import (
	"time"
)

type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusRolledBack TaskStatus = "rolled_back"
	TaskStatusApproving TaskStatus = "awaiting_approval"
	TaskStatusCancelled TaskStatus = "cancelled"
)

type TaskType string

const (
	TaskTypePlaybook       TaskType = "playbook"
	TaskTypeSandbox        TaskType = "sandbox"
	TaskTypeContainment    TaskType = "containment"
	TaskTypeRemediation    TaskType = "remediation"
	TaskTypeVerification   TaskType = "verification"
	TaskTypeRollback       TaskType = "rollback"
)

type Task struct {
	ID             string                 `json:"id"`
	Type           TaskType               `json:"type"`
	Status         TaskStatus             `json:"status"`
	Priority       int                    `json:"priority"`
	TargetHost     string                 `json:"target_host,omitempty"`
	TargetDevice   string                 `json:"target_device,omitempty"`
	PlaybookID     string                 `json:"playbook_id,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	StartedAt      *time.Time             `json:"started_at,omitempty"`
	CompletedAt    *time.Time             `json:"completed_at,omitempty"`
	CreatedBy      string                 `json:"created_by"`
	ApprovedBy     string                 `json:"approved_by,omitempty"`
	AutoApprove    bool                   `json:"auto_approve"`
	RequiresApproval bool                 `json:"requires_approval"`
	RetryCount     int                    `json:"retry_count"`
	MaxRetries     int                    `json:"max_retries"`
	Result         *TaskResult            `json:"result,omitempty"`
	Error          string                 `json:"error,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	Actions        []ActionRecord         `json:"actions,omitempty"`
}

type TaskResult struct {
	Success       bool                   `json:"success"`
	Message       string                 `json:"message"`
	Output        string                 `json:"output,omitempty"`
	ActionsRun    int                    `json:"actions_run"`
	ActionsFailed int                    `json:"actions_failed"`
	Duration      time.Duration          `json:"duration"`
	Changes       []Change               `json:"changes,omitempty"`
	Evidence      []string               `json:"evidence,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type Change struct {
	Type        string                 `json:"type"`
	Target      string                 `json:"target"`
	Action      string                 `json:"action"`
	Before      string                 `json:"before,omitempty"`
	After       string                 `json:"after,omitempty"`
	Reversible  bool                   `json:"reversible"`
	RollbackCmd string                 `json:"rollback_cmd,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type ActionRecord struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Status      string                 `json:"status"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Success     bool                   `json:"success"`
	Output      string                 `json:"output,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Changes     []Change               `json:"changes,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type ApprovalRequest struct {
	TaskID      string                 `json:"task_id"`
	RequestedAt time.Time              `json:"requested_at"`
	RequestedBy string                 `json:"requested_by"`
	Reason      string                 `json:"reason"`
	TaskDetails *Task                  `json:"task_details"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type ApprovalResponse struct {
	TaskID     string    `json:"task_id"`
	Approved   bool      `json:"approved"`
	ApprovedBy string    `json:"approved_by"`
	ApprovedAt time.Time `json:"approved_at"`
	Reason     string    `json:"reason,omitempty"`
}

type TaskFilter struct {
	Status       []TaskStatus
	Type         []TaskType
	CreatedAfter *time.Time
	TargetHost   string
	CreatedBy    string
	Limit        int
}
