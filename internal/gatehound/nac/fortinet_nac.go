package nac

import (
	"context"
	"fmt"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
)

type FortinetNACClient struct {
	*BaseNACClient
}

func NewFortinetNACClient(config *NACConfig, logger *logging.Logger) (*FortinetNACClient, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("endpoint is required for Fortinet NAC")
	}

	base := &BaseNACClient{
		config:     config,
		logger:     logger,
		httpClient: createHTTPClient(config),
		connected:  false,
	}

	return &FortinetNACClient{
		BaseNACClient: base,
	}, nil
}

func (f *FortinetNACClient) Connect(ctx context.Context) error {
	f.logger.Info("Connecting to Fortinet NAC",
		logging.WithExtra("endpoint", f.config.Endpoint),
	)

	f.connected = true
	f.logger.Info("Successfully connected to Fortinet NAC")
	return nil
}

func (f *FortinetNACClient) Disconnect() error {
	f.connected = false
	f.logger.Info("Disconnected from Fortinet NAC")
	return nil
}

func (f *FortinetNACClient) ExecuteAction(ctx context.Context, req *NACRequest) (*NACResponse, error) {
	if !f.connected {
		return nil, fmt.Errorf("not connected to Fortinet NAC")
	}

	f.logger.Info("Executing NAC action on Fortinet NAC",
		logging.WithAction(string(req.Action)),
	)

	return &NACResponse{
		Success:   false,
		Message:   "Fortinet NAC implementation pending - use Generic API adapter",
		Timestamp: time.Now(),
	}, fmt.Errorf("not fully implemented - use generic API adapter")
}

func (f *FortinetNACClient) GetDeviceStatus(ctx context.Context, macAddress string) (*DeviceStatus, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *FortinetNACClient) GetSessionInfo(ctx context.Context, sessionID string) (*SessionInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *FortinetNACClient) HealthCheck(ctx context.Context) error {
	return nil
}
