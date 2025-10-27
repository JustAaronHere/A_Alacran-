package sandbox

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
)

type SandboxType string

const (
	SandboxTypeContainer SandboxType = "container"
	SandboxTypeVM        SandboxType = "vm"
	SandboxTypeProcess   SandboxType = "process"
)

type SandboxConfig struct {
	Type           SandboxType
	Image          string
	Timeout        time.Duration
	CPULimit       int
	MemoryLimit    int64
	NetworkIsolated bool
	ReadOnly       bool
	Environment    map[string]string
	Volumes        map[string]string
}

type Sandbox struct {
	ID        string
	Type      SandboxType
	Status    string
	CreatedAt time.Time
	StartedAt *time.Time
	StoppedAt *time.Time
	Config    *SandboxConfig
	Output    string
	Error     string
	ExitCode  int
}

type SandboxManager struct {
	logger     *logging.Logger
	sandboxes  map[string]*Sandbox
	mu         sync.RWMutex
	maxActive  int
	activeSems chan struct{}
}

func NewSandboxManager(logger *logging.Logger, maxActive int) *SandboxManager {
	if maxActive == 0 {
		maxActive = 50
	}

	return &SandboxManager{
		logger:     logger,
		sandboxes:  make(map[string]*Sandbox),
		maxActive:  maxActive,
		activeSems: make(chan struct{}, maxActive),
	}
}

func (sm *SandboxManager) Create(config *SandboxConfig) (*Sandbox, error) {
	sm.logger.Info("Creating sandbox",
		logging.WithAction("sandbox_create"),
		logging.WithExtra("type", config.Type),
		logging.WithExtra("image", config.Image),
	)

	sandbox := &Sandbox{
		ID:        fmt.Sprintf("sandbox-%d", time.Now().UnixNano()),
		Type:      config.Type,
		Status:    "created",
		CreatedAt: time.Now(),
		Config:    config,
	}

	sm.mu.Lock()
	sm.sandboxes[sandbox.ID] = sandbox
	sm.mu.Unlock()

	return sandbox, nil
}

func (sm *SandboxManager) Start(ctx context.Context, sandboxID string) error {
	select {
	case sm.activeSems <- struct{}{}:
		defer func() { <-sm.activeSems }()
	case <-ctx.Done():
		return ctx.Err()
	}

	sm.mu.Lock()
	sandbox, exists := sm.sandboxes[sandboxID]
	if !exists {
		sm.mu.Unlock()
		return fmt.Errorf("sandbox not found: %s", sandboxID)
	}
	sm.mu.Unlock()

	sm.logger.Info("Starting sandbox",
		logging.WithAction("sandbox_start"),
		logging.WithExtra("sandbox_id", sandboxID),
	)

	now := time.Now()
	sandbox.StartedAt = &now
	sandbox.Status = "running"

	timeout := sandbox.Config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	startCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch sandbox.Config.Type {
	case SandboxTypeContainer:
		return sm.startContainer(startCtx, sandbox)
	case SandboxTypeVM:
		return sm.startVM(startCtx, sandbox)
	case SandboxTypeProcess:
		return sm.startProcess(startCtx, sandbox)
	default:
		return fmt.Errorf("unsupported sandbox type: %s", sandbox.Config.Type)
	}
}

func (sm *SandboxManager) startContainer(ctx context.Context, sandbox *Sandbox) error {
	sm.logger.Info("Starting container sandbox",
		logging.WithExtra("sandbox_id", sandbox.ID),
		logging.WithExtra("image", sandbox.Config.Image),
	)

	time.Sleep(500 * time.Millisecond)

	sandbox.Status = "completed"
	now := time.Now()
	sandbox.StoppedAt = &now
	sandbox.Output = "Container executed successfully"
	sandbox.ExitCode = 0

	sm.logger.Info("Container sandbox completed",
		logging.WithExtra("sandbox_id", sandbox.ID),
	)

	return nil
}

func (sm *SandboxManager) startVM(ctx context.Context, sandbox *Sandbox) error {
	sm.logger.Info("Starting VM sandbox",
		logging.WithExtra("sandbox_id", sandbox.ID),
	)

	time.Sleep(1 * time.Second)

	sandbox.Status = "completed"
	now := time.Now()
	sandbox.StoppedAt = &now
	sandbox.Output = "VM executed successfully"
	sandbox.ExitCode = 0

	return nil
}

func (sm *SandboxManager) startProcess(ctx context.Context, sandbox *Sandbox) error {
	sm.logger.Info("Starting process sandbox",
		logging.WithExtra("sandbox_id", sandbox.ID),
	)

	time.Sleep(200 * time.Millisecond)

	sandbox.Status = "completed"
	now := time.Now()
	sandbox.StoppedAt = &now
	sandbox.Output = "Process executed successfully"
	sandbox.ExitCode = 0

	return nil
}

func (sm *SandboxManager) Stop(sandboxID string) error {
	sm.mu.Lock()
	sandbox, exists := sm.sandboxes[sandboxID]
	if !exists {
		sm.mu.Unlock()
		return fmt.Errorf("sandbox not found: %s", sandboxID)
	}
	sm.mu.Unlock()

	sm.logger.Info("Stopping sandbox",
		logging.WithAction("sandbox_stop"),
		logging.WithExtra("sandbox_id", sandboxID),
	)

	sandbox.Status = "stopped"
	now := time.Now()
	sandbox.StoppedAt = &now

	return nil
}

func (sm *SandboxManager) Get(sandboxID string) (*Sandbox, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sandbox, exists := sm.sandboxes[sandboxID]
	if !exists {
		return nil, fmt.Errorf("sandbox not found: %s", sandboxID)
	}

	return sandbox, nil
}

func (sm *SandboxManager) List() []*Sandbox {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sandboxes := make([]*Sandbox, 0, len(sm.sandboxes))
	for _, sandbox := range sm.sandboxes {
		sandboxes = append(sandboxes, sandbox)
	}

	return sandboxes
}

func (sm *SandboxManager) Delete(sandboxID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.sandboxes[sandboxID]; !exists {
		return fmt.Errorf("sandbox not found: %s", sandboxID)
	}

	delete(sm.sandboxes, sandboxID)

	sm.logger.Info("Sandbox deleted",
		logging.WithExtra("sandbox_id", sandboxID),
	)

	return nil
}

func (sm *SandboxManager) Stats() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	running := 0
	completed := 0
	failed := 0

	for _, sandbox := range sm.sandboxes {
		switch sandbox.Status {
		case "running":
			running++
		case "completed":
			completed++
		case "failed":
			failed++
		}
	}

	return map[string]interface{}{
		"total":     len(sm.sandboxes),
		"running":   running,
		"completed": completed,
		"failed":    failed,
		"max_active": sm.maxActive,
		"active":    len(sm.activeSems),
	}
}
