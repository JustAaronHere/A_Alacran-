package integrations

import (
	"context"
	"fmt"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
)

type EDRProvider string

const (
	EDRCrowdStrike   EDRProvider = "crowdstrike"
	EDRSentinelOne   EDRProvider = "sentinelone"
	EDRCarbonBlack   EDRProvider = "carbonblack"
	EDRMicrosoftDEP  EDRProvider = "microsoft_defender"
)

type EDRConfig struct {
	Provider  EDRProvider
	APIKey    string
	APISecret string
	BaseURL   string
	TenantID  string
	Timeout   time.Duration
}

type EDRAction string

const (
	EDRActionQuarantine       EDRAction = "quarantine"
	EDRActionUnquarantine     EDRAction = "unquarantine"
	EDRActionKillProcess      EDRAction = "kill_process"
	EDRActionIsolateHost      EDRAction = "isolate_host"
	EDRActionUnisolateHost    EDRAction = "unisolate_host"
	EDRActionCollectForensics EDRAction = "collect_forensics"
)

type EDRRequest struct {
	Action     EDRAction
	HostID     string
	Hostname   string
	ProcessID  int
	ProcessName string
	FilePath   string
	FileHash   string
	Reason     string
	Metadata   map[string]interface{}
}

type EDRResponse struct {
	Success   bool
	Message   string
	ActionID  string
	Timestamp time.Time
	Details   map[string]interface{}
}

type EDRClient interface {
	Connect(ctx context.Context) error
	Disconnect() error
	ExecuteAction(ctx context.Context, req *EDRRequest) (*EDRResponse, error)
	GetHostStatus(ctx context.Context, hostID string) (*HostStatus, error)
	GetProcessInfo(ctx context.Context, hostID string, processID int) (*ProcessInfo, error)
	CollectForensics(ctx context.Context, hostID string) (*ForensicsPackage, error)
}

type HostStatus struct {
	HostID         string
	Hostname       string
	IPAddress      string
	IsIsolated     bool
	IsQuarantined  bool
	AgentVersion   string
	LastSeen       time.Time
	ThreatLevel    string
	ActiveThreats  int
}

type ProcessInfo struct {
	ProcessID   int
	ProcessName string
	FilePath    string
	FileHash    string
	CommandLine string
	ParentPID   int
	User        string
	StartTime   time.Time
	IsRunning   bool
	ThreatScore int
}

type ForensicsPackage struct {
	HostID       string
	CollectionID string
	Artifacts    []string
	PackageURL   string
	Size         int64
	Status       string
	CreatedAt    time.Time
}

type BaseEDRClient struct {
	config *EDRConfig
	logger *logging.Logger
}

func NewEDRClient(config *EDRConfig, logger *logging.Logger) (EDRClient, error) {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	switch config.Provider {
	case EDRCrowdStrike:
		return NewCrowdStrikeClient(config, logger)
	case EDRSentinelOne:
		return NewSentinelOneClient(config, logger)
	case EDRCarbonBlack:
		return NewCarbonBlackClient(config, logger)
	case EDRMicrosoftDEP:
		return NewMicrosoftDefenderClient(config, logger)
	default:
		return nil, fmt.Errorf("unsupported EDR provider: %s", config.Provider)
	}
}
