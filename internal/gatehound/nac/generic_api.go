package nac

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
)

type GenericAPIClient struct {
	*BaseNACClient
}

func NewGenericAPIClient(config *NACConfig, logger *logging.Logger) (*GenericAPIClient, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("endpoint is required for Generic API")
	}

	base := &BaseNACClient{
		config:     config,
		logger:     logger,
		httpClient: createHTTPClient(config),
		connected:  false,
	}

	return &GenericAPIClient{BaseNACClient: base}, nil
}

func (g *GenericAPIClient) Connect(ctx context.Context) error {
	g.logger.Info("Connecting to Generic NAC API", logging.WithExtra("endpoint", g.config.Endpoint))
	if err := g.HealthCheck(ctx); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	g.connected = true
	g.logger.Info("Successfully connected to Generic NAC API")
	return nil
}

func (g *GenericAPIClient) Disconnect() error {
	g.connected = false
	g.logger.Info("Disconnected from Generic NAC API")
	return nil
}

func (g *GenericAPIClient) ExecuteAction(ctx context.Context, req *NACRequest) (*NACResponse, error) {
	if !g.connected {
		return nil, fmt.Errorf("not connected to NAC API")
	}

	g.logger.Info("Executing NAC action via Generic API",
		logging.WithAction(string(req.Action)),
		logging.WithExtra("target", req.Target))

	endpoint := fmt.Sprintf("%s/api/nac/action", g.config.Endpoint)
	payload := map[string]interface{}{
		"action":      string(req.Action),
		"target":      req.Target,
		"mac_address": req.MACAddress,
		"ip_address":  req.IPAddress,
		"reason":      req.Reason,
		"metadata":    req.Metadata,
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if g.config.APIKey != "" {
		httpReq.Header.Set("X-API-Key", g.config.APIKey)
	} else if g.config.Username != "" {
		httpReq.SetBasicAuth(g.config.Username, g.config.Password)
	}

	resp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Success bool                   `json:"success"`
		Message string                 `json:"message"`
		Details map[string]interface{} `json:"details,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &NACResponse{
		Success:   result.Success,
		Message:   result.Message,
		Timestamp: time.Now(),
		Details:   result.Details,
	}, nil
}

func (g *GenericAPIClient) GetDeviceStatus(ctx context.Context, macAddress string) (*DeviceStatus, error) {
	url := fmt.Sprintf("%s/api/nac/device/%s", g.config.Endpoint, macAddress)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	if g.config.APIKey != "" {
		httpReq.Header.Set("X-API-Key", g.config.APIKey)
	} else if g.config.Username != "" {
		httpReq.SetBasicAuth(g.config.Username, g.config.Password)
	}

	resp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var status DeviceStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}

	return &status, nil
}

func (g *GenericAPIClient) HealthCheck(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/health", g.config.Endpoint)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	if g.config.APIKey != "" {
		httpReq.Header.Set("X-API-Key", g.config.APIKey)
	}

	resp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status: %d", resp.StatusCode)
	}

	return nil
}
