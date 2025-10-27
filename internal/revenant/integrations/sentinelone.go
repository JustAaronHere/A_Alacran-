package integrations

import (
	"context"
	"fmt"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
)

type SentinelOneClient struct {
	*BaseEDRClient
}

func NewSentinelOneClient(config *EDRConfig, logger *logging.Logger) (*SentinelOneClient, error) {
	if config.BaseURL == "" {
		config.BaseURL = "https://usea1-partners.sentinelone.net"
	}

	base := &BaseEDRClient{
		config: config,
		logger: logger,
	}

	return &SentinelOneClient{BaseEDRClient: base}, nil
}

func (s1 *SentinelOneClient) Connect(ctx context.Context) error {
	s1.logger.Info("Connecting to SentinelOne API")
	return nil
}

func (s1 *SentinelOneClient) Disconnect() error {
	s1.logger.Info("Disconnected from SentinelOne")
	return nil
}

func (s1 *SentinelOneClient) ExecuteAction(ctx context.Context, req *EDRRequest) (*EDRResponse, error) {
	s1.logger.Info("Executing EDR action on SentinelOne",
		logging.WithAction(string(req.Action)),
		logging.WithExtra("host", req.Hostname))

	return &EDRResponse{
		Success:   true,
		Message:   fmt.Sprintf("SentinelOne action %s executed", req.Action),
		ActionID:  "s1-action-" + time.Now().Format("20060102150405"),
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"provider": "sentinelone"},
	}, nil
}

func (s1 *SentinelOneClient) GetHostStatus(ctx context.Context, hostID string) (*HostStatus, error) {
	return &HostStatus{
		HostID:       hostID,
		AgentVersion: "21.x",
		LastSeen:     time.Now(),
	}, nil
}

func (s1 *SentinelOneClient) GetProcessInfo(ctx context.Context, hostID string, processID int) (*ProcessInfo, error) {
	return &ProcessInfo{
		ProcessID: processID,
	}, nil
}

func (s1 *SentinelOneClient) CollectForensics(ctx context.Context, hostID string) (*ForensicsPackage, error) {
	return &ForensicsPackage{
		HostID:       hostID,
		CollectionID: "forensics-" + time.Now().Format("20060102150405"),
		Status:       "collecting",
		CreatedAt:    time.Now(),
	}, nil
}
