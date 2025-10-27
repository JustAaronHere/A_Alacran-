package enrich

import (
	"fmt"
	"net"
	"sync"
)

type GeoIPProvider interface {
	Lookup(ip net.IP) (*GeoIPInfo, error)
	Close() error
}

type GeoIPInfo struct {
	IP            net.IP  `json:"ip"`
	Country       string  `json:"country,omitempty"`
	CountryCode   string  `json:"country_code,omitempty"`
	Region        string  `json:"region,omitempty"`
	City          string  `json:"city,omitempty"`
	Latitude      float64 `json:"latitude,omitempty"`
	Longitude     float64 `json:"longitude,omitempty"`
	PostalCode    string  `json:"postal_code,omitempty"`
	Timezone      string  `json:"timezone,omitempty"`
	ASN           uint    `json:"asn,omitempty"`
	ASNOrg        string  `json:"asn_org,omitempty"`
	ISP           string  `json:"isp,omitempty"`
	Organization  string  `json:"organization,omitempty"`
	IsAnonymous   bool    `json:"is_anonymous"`
	IsProxy       bool    `json:"is_proxy"`
	IsTor         bool    `json:"is_tor"`
}

type GeoIPEnricher struct {
	provider GeoIPProvider
	cache    map[string]*GeoIPInfo
	mu       sync.RWMutex
}

func NewGeoIPEnricher(provider GeoIPProvider) *GeoIPEnricher {
	return &GeoIPEnricher{
		provider: provider,
		cache:    make(map[string]*GeoIPInfo),
	}
}

func (ge *GeoIPEnricher) Enrich(ip net.IP) (*GeoIPInfo, error) {
	if ip == nil {
		return nil, fmt.Errorf("nil IP address")
	}

	if isPrivateIP(ip) {
		return &GeoIPInfo{
			IP:      ip,
			Country: "Private Network",
		}, nil
	}

	cacheKey := ip.String()

	ge.mu.RLock()
	if cached, ok := ge.cache[cacheKey]; ok {
		ge.mu.RUnlock()
		return cached, nil
	}
	ge.mu.RUnlock()

	info, err := ge.provider.Lookup(ip)
	if err != nil {
		return nil, err
	}

	ge.mu.Lock()
	ge.cache[cacheKey] = info
	ge.mu.Unlock()

	return info, nil
}

func (ge *GeoIPEnricher) Close() error {
	if ge.provider != nil {
		return ge.provider.Close()
	}
	return nil
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}

	for _, block := range privateBlocks {
		_, subnet, _ := net.ParseCIDR(block)
		if subnet.Contains(ip) {
			return true
		}
	}

	return false
}

type MockGeoIPProvider struct {
	mockData map[string]*GeoIPInfo
	mu       sync.RWMutex
}

func NewMockGeoIPProvider() *MockGeoIPProvider {
	return &MockGeoIPProvider{
		mockData: make(map[string]*GeoIPInfo),
	}
}

func (m *MockGeoIPProvider) Lookup(ip net.IP) (*GeoIPInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if info, ok := m.mockData[ip.String()]; ok {
		return info, nil
	}

	return &GeoIPInfo{
		IP:          ip,
		Country:     "Unknown",
		CountryCode: "XX",
		City:        "Unknown",
		Latitude:    0.0,
		Longitude:   0.0,
		ASN:         0,
		ASNOrg:      "Unknown",
	}, nil
}

func (m *MockGeoIPProvider) AddMockData(ip string, info *GeoIPInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mockData[ip] = info
}

func (m *MockGeoIPProvider) Close() error {
	return nil
}
