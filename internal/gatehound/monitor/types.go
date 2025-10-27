package monitor

import (
	"net"
	"time"
)

type EventType string

const (
	EventTypeARP       EventType = "arp"
	EventTypeDHCP      EventType = "dhcp"
	EventTypeMDNS      EventType = "mdns"
	EventTypeDNS       EventType = "dns"
	EventTypeTLS       EventType = "tls"
	EventTypeHTTP      EventType = "http"
	EventTypeTCPSYN    EventType = "tcp_syn"
	EventTypeUnknown   EventType = "unknown_device"
	EventTypeAnomaly   EventType = "anomaly"
)

type NetworkEvent struct {
	ID           string                 `json:"id"`
	Type         EventType              `json:"type"`
	Timestamp    time.Time              `json:"timestamp"`
	SrcIP        net.IP                 `json:"src_ip,omitempty"`
	DstIP        net.IP                 `json:"dst_ip,omitempty"`
	SrcMAC       net.HardwareAddr       `json:"src_mac,omitempty"`
	DstMAC       net.HardwareAddr       `json:"dst_mac,omitempty"`
	SrcPort      uint16                 `json:"src_port,omitempty"`
	DstPort      uint16                 `json:"dst_port,omitempty"`
	Protocol     string                 `json:"protocol,omitempty"`
	Hostname     string                 `json:"hostname,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	TTL          uint8                  `json:"ttl,omitempty"`
	Confidence   float64                `json:"confidence"`
	IsUnknown    bool                   `json:"is_unknown"`
	IsAnomaly    bool                   `json:"is_anomaly"`
	AnomalyScore float64                `json:"anomaly_score,omitempty"`
	Extra        map[string]interface{} `json:"extra,omitempty"`
}

type DeviceInfo struct {
	MAC          net.HardwareAddr       `json:"mac"`
	IP           []net.IP               `json:"ip"`
	Hostname     string                 `json:"hostname,omitempty"`
	Vendor       string                 `json:"vendor,omitempty"`
	FirstSeen    time.Time              `json:"first_seen"`
	LastSeen     time.Time              `json:"last_seen"`
	DHCPInfo     *DHCPFingerprint       `json:"dhcp_info,omitempty"`
	HTTPInfo     *HTTPFingerprint       `json:"http_info,omitempty"`
	TLSInfo      *TLSFingerprint        `json:"tls_info,omitempty"`
	OSGuess      string                 `json:"os_guess,omitempty"`
	TTLProfile   []uint8                `json:"ttl_profile,omitempty"`
	IsKnown      bool                   `json:"is_known"`
	ThreatScore  float64                `json:"threat_score"`
	GatewayIP    net.IP                 `json:"gateway_ip,omitempty"`
	EventCount   int                    `json:"event_count"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type DHCPFingerprint struct {
	Hostname         string   `json:"hostname,omitempty"`
	RequestedIP      net.IP   `json:"requested_ip,omitempty"`
	VendorClass      string   `json:"vendor_class,omitempty"`
	ParameterRequest []byte   `json:"parameter_request,omitempty"`
	Options          []uint8  `json:"options,omitempty"`
	Signature        string   `json:"signature"`
}

type HTTPFingerprint struct {
	UserAgent   string            `json:"user_agent,omitempty"`
	Server      string            `json:"server,omitempty"`
	Host        string            `json:"host,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Method      string            `json:"method,omitempty"`
	StatusCode  int               `json:"status_code,omitempty"`
}

type TLSFingerprint struct {
	Version        string   `json:"version,omitempty"`
	SNI            string   `json:"sni,omitempty"`
	CipherSuites   []uint16 `json:"cipher_suites,omitempty"`
	Extensions     []uint16 `json:"extensions,omitempty"`
	ALPN           []string `json:"alpn,omitempty"`
	JA3            string   `json:"ja3,omitempty"`
	CertCommonName string   `json:"cert_common_name,omitempty"`
	CertIssuer     string   `json:"cert_issuer,omitempty"`
	CertSANs       []string `json:"cert_sans,omitempty"`
}

type GatewayInfo struct {
	IP           net.IP                 `json:"ip"`
	MAC          net.HardwareAddr       `json:"mac"`
	Vendor       string                 `json:"vendor,omitempty"`
	Hostname     string                 `json:"hostname,omitempty"`
	Model        string                 `json:"model,omitempty"`
	Firmware     string                 `json:"firmware,omitempty"`
	OpenPorts    []int                  `json:"open_ports,omitempty"`
	Services     map[int]string         `json:"services,omitempty"`
	DetectedAt   time.Time              `json:"detected_at"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type ARPEvent struct {
	SourceMAC  net.HardwareAddr `json:"source_mac"`
	SourceIP   net.IP           `json:"source_ip"`
	TargetMAC  net.HardwareAddr `json:"target_mac"`
	TargetIP   net.IP           `json:"target_ip"`
	Operation  uint16           `json:"operation"`
	Timestamp  time.Time        `json:"timestamp"`
	IsGratuitous bool           `json:"is_gratuitous"`
}

type DNSEvent struct {
	QueryName     string    `json:"query_name"`
	QueryType     string    `json:"query_type"`
	ResponseIPs   []net.IP  `json:"response_ips,omitempty"`
	ResponseCode  string    `json:"response_code"`
	SourceIP      net.IP    `json:"source_ip"`
	Timestamp     time.Time `json:"timestamp"`
}
