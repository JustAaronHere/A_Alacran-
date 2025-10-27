package correlation

import (
	"net"
	"sync"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/monitor"
)

type CorrelationEngine struct {
	logger          *logging.Logger
	devices         map[string]*monitor.DeviceInfo
	events          []*monitor.NetworkEvent
	mu              sync.RWMutex
	maxEventHistory int
	threatScorer    *ThreatScorer
}

func NewCorrelationEngine(logger *logging.Logger) *CorrelationEngine {
	return &CorrelationEngine{
		logger:          logger,
		devices:         make(map[string]*monitor.DeviceInfo),
		events:          make([]*monitor.NetworkEvent, 0),
		maxEventHistory: 10000,
		threatScorer:    NewThreatScorer(),
	}
}

func (ce *CorrelationEngine) ProcessEvent(event *monitor.NetworkEvent) (*monitor.DeviceInfo, error) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	ce.events = append(ce.events, event)
	if len(ce.events) > ce.maxEventHistory {
		ce.events = ce.events[len(ce.events)-ce.maxEventHistory:]
	}

	var device *monitor.DeviceInfo

	if len(event.SrcMAC) > 0 {
		device = ce.getOrCreateDevice(event.SrcMAC)
		ce.updateDeviceFromEvent(device, event)
	}

	if device != nil {
		device.ThreatScore = ce.threatScorer.CalculateScore(device, ce.events)
		device.EventCount++
		device.LastSeen = event.Timestamp
	}

	return device, nil
}

func (ce *CorrelationEngine) getOrCreateDevice(mac net.HardwareAddr) *monitor.DeviceInfo {
	key := mac.String()
	
	device, exists := ce.devices[key]
	if !exists {
		device = &monitor.DeviceInfo{
			MAC:        mac,
			IP:         make([]net.IP, 0),
			FirstSeen:  time.Now(),
			LastSeen:   time.Now(),
			IsKnown:    false,
			EventCount: 0,
			Metadata:   make(map[string]interface{}),
		}
		ce.devices[key] = device
	}

	return device
}

func (ce *CorrelationEngine) updateDeviceFromEvent(device *monitor.DeviceInfo, event *monitor.NetworkEvent) {
	if event.SrcIP != nil && !ce.containsIP(device.IP, event.SrcIP) {
		device.IP = append(device.IP, event.SrcIP)
	}

	if event.Hostname != "" && device.Hostname == "" {
		device.Hostname = event.Hostname
	}

	switch event.Type {
	case monitor.EventTypeDHCP:
		if device.DHCPInfo == nil {
			device.DHCPInfo = &monitor.DHCPFingerprint{}
		}
		if hostname, ok := event.Extra["hostname"].(string); ok {
			device.DHCPInfo.Hostname = hostname
		}
		if vendorClass, ok := event.Extra["vendor_class"].(string); ok {
			device.DHCPInfo.VendorClass = vendorClass
		}

	case monitor.EventTypeHTTP:
		if device.HTTPInfo == nil {
			device.HTTPInfo = &monitor.HTTPFingerprint{}
		}
		if event.UserAgent != "" {
			device.HTTPInfo.UserAgent = event.UserAgent
		}
		if host, ok := event.Extra["host"].(string); ok {
			device.HTTPInfo.Host = host
		}

	case monitor.EventTypeTLS:
		if device.TLSInfo == nil {
			device.TLSInfo = &monitor.TLSFingerprint{}
		}
		if sni, ok := event.Extra["sni"].(string); ok {
			device.TLSInfo.SNI = sni
		}
		if version, ok := event.Extra["tls_version"].(string); ok {
			device.TLSInfo.Version = version
		}
	}

	if event.TTL > 0 {
		if device.TTLProfile == nil {
			device.TTLProfile = make([]uint8, 0)
		}
		device.TTLProfile = append(device.TTLProfile, event.TTL)
		if len(device.TTLProfile) > 10 {
			device.TTLProfile = device.TTLProfile[len(device.TTLProfile)-10:]
		}

		device.OSGuess = ce.guessOSFromTTL(event.TTL)
	}
}

func (ce *CorrelationEngine) containsIP(ips []net.IP, ip net.IP) bool {
	for _, existingIP := range ips {
		if existingIP.Equal(ip) {
			return true
		}
	}
	return false
}

func (ce *CorrelationEngine) guessOSFromTTL(ttl uint8) string {
	switch {
	case ttl <= 64:
		return "Linux/Unix"
	case ttl <= 128:
		return "Windows"
	case ttl <= 255:
		return "Cisco/Network Device"
	default:
		return "Unknown"
	}
}

func (ce *CorrelationEngine) GetDevice(mac net.HardwareAddr) (*monitor.DeviceInfo, bool) {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	device, exists := ce.devices[mac.String()]
	return device, exists
}

func (ce *CorrelationEngine) GetAllDevices() []*monitor.DeviceInfo {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	devices := make([]*monitor.DeviceInfo, 0, len(ce.devices))
	for _, device := range ce.devices {
		devices = append(devices, device)
	}

	return devices
}

func (ce *CorrelationEngine) GetUnknownDevices() []*monitor.DeviceInfo {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	unknown := make([]*monitor.DeviceInfo, 0)
	for _, device := range ce.devices {
		if !device.IsKnown {
			unknown = append(unknown, device)
		}
	}

	return unknown
}

func (ce *CorrelationEngine) GetHighThreatDevices(threshold float64) []*monitor.DeviceInfo {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	threats := make([]*monitor.DeviceInfo, 0)
	for _, device := range ce.devices {
		if device.ThreatScore >= threshold {
			threats = append(threats, device)
		}
	}

	return threats
}

func (ce *CorrelationEngine) MarkDeviceKnown(mac net.HardwareAddr) error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	device, exists := ce.devices[mac.String()]
	if !exists {
		return nil
	}

	device.IsKnown = true
	return nil
}

func (ce *CorrelationEngine) GetRecentEvents(since time.Time) []*monitor.NetworkEvent {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	recent := make([]*monitor.NetworkEvent, 0)
	for _, event := range ce.events {
		if event.Timestamp.After(since) {
			recent = append(recent, event)
		}
	}

	return recent
}

func (ce *CorrelationEngine) Stats() map[string]interface{} {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	unknownCount := 0
	highThreatCount := 0

	for _, device := range ce.devices {
		if !device.IsKnown {
			unknownCount++
		}
		if device.ThreatScore >= 50.0 {
			highThreatCount++
		}
	}

	return map[string]interface{}{
		"total_devices":       len(ce.devices),
		"unknown_devices":     unknownCount,
		"high_threat_devices": highThreatCount,
		"total_events":        len(ce.events),
	}
}
