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

type ArubaClearPassClient struct {
	*BaseNACClient
	accessToken string
}

func NewArubaClearPassClient(config *NACConfig, logger *logging.Logger) (*ArubaClearPassClient, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("endpoint is required for Aruba ClearPass")
	}

	base := &BaseNACClient{
		config:     config,
		logger:     logger,
		httpClient: createHTTPClient(config),
		connected:  false,
	}

	return &ArubaClearPassClient{BaseNACClient: base}, nil
}

func (a *ArubaClearPassClient) Connect(ctx context.Context) error {
	a.logger.Info("Connecting to Aruba ClearPass", logging.WithExtra("endpoint", a.config.Endpoint))
	if err := a.authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	a.connected = true
	a.logger.Info("Successfully connected to Aruba ClearPass")
	return nil
}

func (a *ArubaClearPassClient) authenticate(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/oauth", a.config.Endpoint)
	payload := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     a.config.Username,
		"client_secret": a.config.Password,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var authResp struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return err
	}

	a.accessToken = authResp.AccessToken
	return nil
}

func (a *ArubaClearPassClient) Disconnect() error {
	a.connected = false
	a.accessToken = ""
	a.logger.Info("Disconnected from Aruba ClearPass")
	return nil
}

func (a *ArubaClearPassClient) ExecuteAction(ctx context.Context, req *NACRequest) (*NACResponse, error) {
	if !a.connected {
		return nil, fmt.Errorf("not connected to Aruba ClearPass")
	}

	a.logger.Info("Executing NAC action on Aruba ClearPass",
		logging.WithAction(string(req.Action)),
		logging.WithExtra("mac", req.MACAddress))

	switch req.Action {
	case ActionQuarantine:
		return a.quarantineDevice(ctx, req)
	case ActionUnquarantine:
		return a.unquarantineDevice(ctx, req)
	case ActionSessionTerminate:
		return a.terminateSession(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported action for Aruba ClearPass: %s", req.Action)
	}
}

func (a *ArubaClearPassClient) quarantineDevice(ctx context.Context, req *NACRequest) (*NACResponse, error) {
	url := fmt.Sprintf("%s/api/endpoint/mac-address/%s", a.config.Endpoint, req.MACAddress)
	update := map[string]interface{}{
		"status": "quarantined",
		"attributes": map[string]string{
			"quarantine_reason": req.Reason,
			"quarantine_time":   time.Now().Format(time.RFC3339),
		},
	}

	body, err := json.Marshal(update)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.accessToken))

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &NACResponse{
		Success:   resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent,
		Message:   fmt.Sprintf("Device %s quarantined", req.MACAddress),
		Timestamp: time.Now(),
	}, nil
}

func (a *ArubaClearPassClient) unquarantineDevice(ctx context.Context, req *NACRequest) (*NACResponse, error) {
	url := fmt.Sprintf("%s/api/endpoint/mac-address/%s", a.config.Endpoint, req.MACAddress)
	update := map[string]interface{}{
		"status": "known",
		"attributes": map[string]string{
			"unquarantine_time": time.Now().Format(time.RFC3339),
		},
	}

	body, err := json.Marshal(update)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.accessToken))

	resp, err := a.httpClient.Do(httpReq)
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

func (a *ArubaClearPassClient) terminateSession(ctx context.Context, req *NACRequest) (*NACResponse, error) {
	url := fmt.Sprintf("%s/api/session/%s/disconnect", a.config.Endpoint, req.MACAddress)
	payload := map[string]string{"reason": req.Reason}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.accessToken))

	resp, err := a.httpClient.Do(httpReq)
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

func (a *ArubaClearPassClient) GetDeviceStatus(ctx context.Context, macAddress string) (*DeviceStatus, error) {
	url := fmt.Sprintf("%s/api/endpoint/mac-address/%s", a.config.Endpoint, macAddress)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.accessToken))

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		MACAddress string `json:"mac_address"`
		IPAddress  string `json:"ip_address"`
		Status     string `json:"status"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &DeviceStatus{
		MACAddress:    result.MACAddress,
		IPAddress:     result.IPAddress,
		IsQuarantined: result.Status == "quarantined",
		AuthStatus:    result.Status,
	}, nil
}

func (a *ArubaClearPassClient) HealthCheck(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/server/version", a.config.Endpoint)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.accessToken))

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status: %d", resp.StatusCode)
	}

	return nil
}
