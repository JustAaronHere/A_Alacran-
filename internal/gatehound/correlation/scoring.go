package correlation

import (
	"strings"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/monitor"
)

type ThreatScorer struct {
	blacklist map[string]bool
	tiFeeds   []ThreatIntelFeed
}

type ThreatIntelFeed interface {
	IsBlacklisted(ip string) bool
	GetThreatInfo(ip string) *ThreatInfo
}

type ThreatInfo struct {
	Malicious    bool
	Confidence   float64
	Categories   []string
	Description  string
	LastSeen     time.Time
}

func NewThreatScorer() *ThreatScorer {
	return &ThreatScorer{
		blacklist: make(map[string]bool),
		tiFeeds:   make([]ThreatIntelFeed, 0),
	}
}

func (ts *ThreatScorer) CalculateScore(device *monitor.DeviceInfo, events []*monitor.NetworkEvent) float64 {
	score := 0.0

	if !device.IsKnown {
		score += 20.0
	}

	if device.Vendor == "Unknown" || device.Vendor == "" {
		score += 10.0
	}

	for _, ip := range device.IP {
		if ts.isBlacklisted(ip.String()) {
			score += 50.0
			break
		}
	}

	if ts.hasAnomalousActivity(device, events) {
		score += 15.0
	}

	if ts.hasPortScanningBehavior(device, events) {
		score += 25.0
	}

	if ts.hasSuspiciousUserAgent(device) {
		score += 10.0
	}

	if ts.hasUnusualTTL(device) {
		score += 5.0
	}

	if device.EventCount > 1000 {
		score += 5.0
	}

	if score > 100.0 {
		score = 100.0
	}

	return score
}

func (ts *ThreatScorer) isBlacklisted(ip string) bool {
	if ts.blacklist[ip] {
		return true
	}

	for _, feed := range ts.tiFeeds {
		if feed.IsBlacklisted(ip) {
			return true
		}
	}

	return false
}

func (ts *ThreatScorer) hasAnomalousActivity(device *monitor.DeviceInfo, events []*monitor.NetworkEvent) bool {
	recentEvents := 0
	now := time.Now()

	for _, event := range events {
		if event.SrcMAC != nil && event.SrcMAC.String() == device.MAC.String() {
			if now.Sub(event.Timestamp) < 5*time.Minute {
				recentEvents++
			}
		}
	}

	return recentEvents > 100
}

func (ts *ThreatScorer) hasPortScanningBehavior(device *monitor.DeviceInfo, events []*monitor.NetworkEvent) bool {
	uniquePorts := make(map[uint16]bool)
	now := time.Now()

	for _, event := range events {
		if event.Type == monitor.EventTypeTCPSYN && 
		   event.SrcMAC != nil && 
		   event.SrcMAC.String() == device.MAC.String() {
			if now.Sub(event.Timestamp) < 10*time.Minute {
				uniquePorts[event.DstPort] = true
			}
		}
	}

	return len(uniquePorts) > 20
}

func (ts *ThreatScorer) hasSuspiciousUserAgent(device *monitor.DeviceInfo) bool {
	if device.HTTPInfo == nil {
		return false
	}

	ua := strings.ToLower(device.HTTPInfo.UserAgent)
	
	suspiciousPatterns := []string{
		"curl",
		"wget",
		"python",
		"nikto",
		"nmap",
		"masscan",
		"sqlmap",
		"metasploit",
		"burp",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(ua, pattern) {
			return true
		}
	}

	return false
}

func (ts *ThreatScorer) hasUnusualTTL(device *monitor.DeviceInfo) bool {
	if len(device.TTLProfile) == 0 {
		return false
	}

	variance := 0
	for i := 1; i < len(device.TTLProfile); i++ {
		diff := int(device.TTLProfile[i]) - int(device.TTLProfile[i-1])
		if diff < 0 {
			diff = -diff
		}
		variance += diff
	}

	avgVariance := variance / len(device.TTLProfile)
	return avgVariance > 10
}

func (ts *ThreatScorer) AddBlacklist(ip string) {
	ts.blacklist[ip] = true
}

func (ts *ThreatScorer) RemoveBlacklist(ip string) {
	delete(ts.blacklist, ip)
}

func (ts *ThreatScorer) AddTIFeed(feed ThreatIntelFeed) {
	ts.tiFeeds = append(ts.tiFeeds, feed)
}
