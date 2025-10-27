package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/monitor"
)

type AlertType string

const (
	AlertTypeUnknownDevice AlertType = "unknown_device"
	AlertTypeHighThreat    AlertType = "high_threat"
	AlertTypeAnomaly       AlertType = "anomaly"
	AlertTypePolicyViolation AlertType = "policy_violation"
)

type Alert struct {
	ID          string                 `json:"id"`
	Type        AlertType              `json:"type"`
	Severity    string                 `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Device      *monitor.DeviceInfo    `json:"device,omitempty"`
	Event       *monitor.NetworkEvent  `json:"event,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type AlertBridge struct {
	logger      *logging.Logger
	webhooks    []string
	mu          sync.RWMutex
	alertQueue  chan *Alert
	workers     int
}

func NewAlertBridge(logger *logging.Logger, workers int) *AlertBridge {
	if workers == 0 {
		workers = 2
	}

	return &AlertBridge{
		logger:     logger,
		webhooks:   make([]string, 0),
		alertQueue: make(chan *Alert, 1000),
		workers:    workers,
	}
}

func (ab *AlertBridge) Start() {
	for i := 0; i < ab.workers; i++ {
		go ab.alertWorker(i)
	}
}

func (ab *AlertBridge) alertWorker(id int) {
	ab.logger.Debug(fmt.Sprintf("Alert worker %d started", id))

	for alert := range ab.alertQueue {
		ab.processAlert(alert)
	}
}

func (ab *AlertBridge) SendAlert(alert *Alert) {
	select {
	case ab.alertQueue <- alert:
		ab.logger.Info("Alert queued",
			logging.WithExtra("alert_id", alert.ID),
			logging.WithExtra("type", alert.Type),
			logging.WithExtra("severity", alert.Severity),
		)
	default:
		ab.logger.Warning("Alert queue full, dropping alert",
			logging.WithExtra("alert_id", alert.ID),
		)
	}
}

func (ab *AlertBridge) processAlert(alert *Alert) {
	ab.logger.Info("Processing alert",
		logging.WithAction("alert"),
		logging.WithExtra("alert_id", alert.ID),
		logging.WithExtra("type", alert.Type),
	)

	ab.mu.RLock()
	webhooks := make([]string, len(ab.webhooks))
	copy(webhooks, ab.webhooks)
	ab.mu.RUnlock()

	for _, webhook := range webhooks {
		if err := ab.sendWebhook(webhook, alert); err != nil {
			ab.logger.Error("Failed to send webhook",
				logging.WithError(err),
				logging.WithExtra("webhook", webhook),
			)
		}
	}
}

func (ab *AlertBridge) sendWebhook(url string, alert *Alert) error {
	data, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Gatehound/1.0")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	ab.logger.Debug("Webhook sent successfully",
		logging.WithExtra("webhook", url),
		logging.WithExtra("status", resp.StatusCode),
	)

	return nil
}

func (ab *AlertBridge) AddWebhook(url string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	ab.webhooks = append(ab.webhooks, url)
}

func (ab *AlertBridge) RemoveWebhook(url string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	for i, webhook := range ab.webhooks {
		if webhook == url {
			ab.webhooks = append(ab.webhooks[:i], ab.webhooks[i+1:]...)
			break
		}
	}
}

func (ab *AlertBridge) ListWebhooks() []string {
	ab.mu.RLock()
	defer ab.mu.RUnlock()

	webhooks := make([]string, len(ab.webhooks))
	copy(webhooks, ab.webhooks)
	return webhooks
}

func (ab *AlertBridge) Close() {
	close(ab.alertQueue)
}
