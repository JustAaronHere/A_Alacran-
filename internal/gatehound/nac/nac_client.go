package nac

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
)

type NACProvider string

const (
	ProviderCiscoISE     NACProvider = "cisco_ise"
	ProviderArubaClear   NACProvider = "aruba_clearpass"
	ProviderFortinet     NACProvider = "fortinet_nac"
	ProviderGenericAPI   NACProvider = "generic_api"
)

type NACConfig struct {
	Provider      NACProvider
	Endpoint      string
	Username      string
	Password      string
	APIKey        string
	TLSSkipVerify bool
	Timeout       time.Duration
	RetryAttempts int
}

type NACAction string

const (
	ActionQuarantine       NACAction = "quarantine"
	ActionUnquarantine     NACAction = "unquarantine"
	ActionPortDisable      NACAction = "port_disable"
	ActionPortEnable       NACAction = "port_enable"
	ActionSessionTerminate NACAction = "session_terminate"
	ActionVLANReassign     NACAction = "vlan_reassign"
	ActionACLApply         NACAction = "acl_apply"
	ActionACLRemove        NACAction = "acl_remove"
)

type NACRequest struct {
	Action     NACAction
	Target     string
	MACAddress string
	IPAddress  string
	SwitchPort string
	SwitchIP   string
	VLANID     int
	ACLName    string
	Reason     string
	Metadata   map[string]interface{}
}

type NACResponse struct {
	Success   bool
	Message   string
	SessionID string
	Timestamp time.Time
	Details   map[string]interface{}
}

type NACClient interface {
	Connect(ctx context.Context) error
	Disconnect() error
	ExecuteAction(ctx context.Context, req *NACRequest) (*NACResponse, error)
	GetDeviceStatus(ctx context.Context, macAddress string) (*DeviceStatus, error)
	GetSessionInfo(ctx context.Context, sessionID string) (*SessionInfo, error)
	HealthCheck(ctx context.Context) error
}

type DeviceStatus struct {
	MACAddress    string
	IPAddress     string
	Hostname      string
	IsQuarantined bool
	VLANID        int
	ACLs          []string
	SessionID     string
	AuthStatus    string
	LastSeen      time.Time
}

type SessionInfo struct {
	SessionID     string
	MACAddress    string
	IPAddress     string
	Username      string
	SwitchIP      string
	SwitchPort    string
	VLANID        int
	ACLs          []string
	StartTime     time.Time
	LastActivity  time.Time
	Status        string
}

type BaseNACClient struct {
	config     *NACConfig
	logger     *logging.Logger
	httpClient *http.Client
	connected  bool
}

func NewNACClient(config *NACConfig, logger *logging.Logger) (NACClient, error) {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.RetryAttempts == 0 {
		config.RetryAttempts = 3
	}

	switch config.Provider {
	case ProviderCiscoISE:
		return NewCiscoISEClient(config, logger)
	case ProviderArubaClear:
		return NewArubaClearPassClient(config, logger)
	case ProviderFortinet:
		return NewFortinetNACClient(config, logger)
	case ProviderGenericAPI:
		return NewGenericAPIClient(config, logger)
	default:
		return nil, fmt.Errorf("unsupported NAC provider: %s", config.Provider)
	}
}

func createHTTPClient(config *NACConfig) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.TLSSkipVerify,
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}
}
