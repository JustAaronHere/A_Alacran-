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

type CiscoISEClient struct {
	*BaseNACClient
}

func NewCiscoISEClient(config *NACConfig, logger *logging.Logger) (*CiscoISEClient, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("endpoint is required for Cisco ISE")
	}

	base := &BaseNACClient{
		config:     config,
		logger:     logger,
		httpClient: createHTTPClient(config),
		connected:  false,
	}

	return &CiscoISEClient{BaseNACClient: base}, nil
}

func (c *CiscoISEClient) Connect(ctx context.Context) error {
	c.logger.Info("Connecting to Cisco ISE", logging.WithExtra("endpoint", c.config.Endpoint))
	if err := c.HealthCheck(ctx); err != nil {
		return fmt.Errorf("failed to connect to Cisco ISE: %w", err)
	}
	c.connected = true
	c.logger.Info("Successfully connected to Cisco ISE")
	return nil
}

func (c *CiscoISEClient) Disconnect() error {
	c.connected = false
	c.logger.Info("Disconnected from Cisco ISE")
	return nil
}

func (c *CiscoISEClient) ExecuteAction(ctx context.Context, req *NACRequest) (*NACResponse, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected to Cisco ISE")
	}

	c.logger.Info("Executing NAC action on Cisco ISE",
		logging.WithAction(string(req.Action)),
		logging.WithExtra("mac", req.MACAddress))

	switch req.Action {
	case ActionQuarantine:
		return c.quarantineDevice(ctx, req)
	case ActionUnquarantine:
		return c.unquarantineDevice(ctx, req)
	case ActionSessionTerminate:
		return c.terminateSession(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported action for Cisco ISE: %s", req.Action)
	}
}

func (c *CiscoISEClient) quarantineDevice(ctx context.Context, req *NACRequest) (*NACResponse, error) {
	url := fmt.Sprintf("%s/api/v1/policy/quarantine", c.config.Endpoint)
	payload := map[string]interface{}{
		"macAddress": req.MACAddress,
		"reason":     req.Reason,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(c.config.Username, c.config.Password)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &NACResponse{
		Success:   resp.StatusCode == http.StatusOK,
		Message:   fmt.Sprintf("Device %s quarantined", req.MACAddress),
		Timestamp: time.Now(),
	}, nil
}

func (c *CiscoISEClient) unquarantineDevice(ctx context.Context, req *NACRequest) (*NACResponse, error) {
	url := fmt.Sprintf("%s/api/v1/policy/quarantine/%s", c.config.Endpoint, req.MACAddress)

	httpReq, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return nil, err
	}

	httpReq.SetBasicAuth(c.config.Username, c.config.Password)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &NACResponse{
		Success:   resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent,
		Message:   fmt.Sprintf("Device %s unquarantined", req.MACAddress),
		Timestamp: time.Now(),
	}, nil
}

func (c *CiscoISEClient) terminateSession(ctx context.Context, req *NACRequest) (*NACResponse, error) {
	url := fmt.Sprintf("%s/api/v1/session/terminate", c.config.Endpoint)
	payload := map[string]interface{}{
		"macAddress": req.MACAddress,
		"reason":     req.Reason,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(c.config.Username, c.config.Password)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &NACResponse{
		Success:   resp.StatusCode == http.StatusOK,
		Message:   "Session terminated",
		Timestamp: time.Now(),
	}, nil
}

func (c *CiscoISEClient) GetDeviceStatus(ctx context.Context, macAddress string) (*DeviceStatus, error) {
	url := fmt.Sprintf("%s/api/v1/session/mac/%s", c.config.Endpoint, macAddress)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	httpReq.SetBasicAuth(c.config.Username, c.config.Password)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Device DeviceStatus `json:"device"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result.Device, nil
}

func (c *CiscoISEClient) HealthCheck(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v1/health", c.config.Endpoint)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	httpReq.SetBasicAuth(c.config.Username, c.config.Password)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status: %d", resp.StatusCode)
	}

	return nil
}
