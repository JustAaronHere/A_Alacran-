package policy

import (
	"fmt"
	"net"
	"sync"

	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/monitor"
)

type PolicyEngine struct {
	mu              sync.RWMutex
	allowedMACs     map[string]bool
	allowedIPs      map[string]bool
	allowedVendors  map[string]bool
	blockedMACs     map[string]bool
	blockedIPs      map[string]bool
	rules           []*Rule
	defaultAction   Action
}

type Action string

const (
	ActionAllow  Action = "allow"
	ActionBlock  Action = "block"
	ActionAlert  Action = "alert"
	ActionLog    Action = "log"
)

type RuleType string

const (
	RuleTypeMAC    RuleType = "mac"
	RuleTypeIP     RuleType = "ip"
	RuleTypeVendor RuleType = "vendor"
	RuleTypeDHCP   RuleType = "dhcp"
	RuleTypeCustom RuleType = "custom"
)

type Rule struct {
	ID          string
	Name        string
	Type        RuleType
	Pattern     string
	Action      Action
	Priority    int
	Enabled     bool
	Description string
}

func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		allowedMACs:    make(map[string]bool),
		allowedIPs:     make(map[string]bool),
		allowedVendors: make(map[string]bool),
		blockedMACs:    make(map[string]bool),
		blockedIPs:     make(map[string]bool),
		rules:          make([]*Rule, 0),
		defaultAction:  ActionAlert,
	}
}

func (pe *PolicyEngine) EvaluateDevice(device *monitor.DeviceInfo) Action {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	macStr := device.MAC.String()
	if pe.blockedMACs[macStr] {
		return ActionBlock
	}

	if pe.allowedMACs[macStr] {
		return ActionAllow
	}

	for _, ip := range device.IP {
		ipStr := ip.String()
		if pe.blockedIPs[ipStr] {
			return ActionBlock
		}
		if pe.allowedIPs[ipStr] {
			return ActionAllow
		}
	}

	if device.Vendor != "" && pe.allowedVendors[device.Vendor] {
		return ActionAllow
	}

	for _, rule := range pe.rules {
		if !rule.Enabled {
			continue
		}

		if pe.matchRule(rule, device) {
			return rule.Action
		}
	}

	if device.IsKnown {
		return ActionAllow
	}

	return pe.defaultAction
}

func (pe *PolicyEngine) matchRule(rule *Rule, device *monitor.DeviceInfo) bool {
	switch rule.Type {
	case RuleTypeMAC:
		return device.MAC.String() == rule.Pattern

	case RuleTypeIP:
		for _, ip := range device.IP {
			if ip.String() == rule.Pattern {
				return true
			}
		}

	case RuleTypeVendor:
		return device.Vendor == rule.Pattern

	case RuleTypeDHCP:
		if device.DHCPInfo != nil {
			return device.DHCPInfo.VendorClass == rule.Pattern
		}
	}

	return false
}

func (pe *PolicyEngine) AddAllowedMAC(mac string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if _, err := net.ParseMAC(mac); err != nil {
		return fmt.Errorf("invalid MAC address: %w", err)
	}

	pe.allowedMACs[mac] = true
	delete(pe.blockedMACs, mac)

	return nil
}

func (pe *PolicyEngine) RemoveAllowedMAC(mac string) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	delete(pe.allowedMACs, mac)
}

func (pe *PolicyEngine) AddBlockedMAC(mac string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if _, err := net.ParseMAC(mac); err != nil {
		return fmt.Errorf("invalid MAC address: %w", err)
	}

	pe.blockedMACs[mac] = true
	delete(pe.allowedMACs, mac)

	return nil
}

func (pe *PolicyEngine) RemoveBlockedMAC(mac string) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	delete(pe.blockedMACs, mac)
}

func (pe *PolicyEngine) AddAllowedIP(ip string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address")
	}

	pe.allowedIPs[ip] = true
	delete(pe.blockedIPs, ip)

	return nil
}

func (pe *PolicyEngine) AddBlockedIP(ip string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address")
	}

	pe.blockedIPs[ip] = true
	delete(pe.allowedIPs, ip)

	return nil
}

func (pe *PolicyEngine) AddAllowedVendor(vendor string) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.allowedVendors[vendor] = true
}

func (pe *PolicyEngine) AddRule(rule *Rule) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.rules = append(pe.rules, rule)
}

func (pe *PolicyEngine) RemoveRule(ruleID string) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	for i, rule := range pe.rules {
		if rule.ID == ruleID {
			pe.rules = append(pe.rules[:i], pe.rules[i+1:]...)
			break
		}
	}
}

func (pe *PolicyEngine) GetRule(ruleID string) *Rule {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	for _, rule := range pe.rules {
		if rule.ID == ruleID {
			return rule
		}
	}

	return nil
}

func (pe *PolicyEngine) ListRules() []*Rule {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	rules := make([]*Rule, len(pe.rules))
	copy(rules, pe.rules)

	return rules
}

func (pe *PolicyEngine) SetDefaultAction(action Action) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.defaultAction = action
}

func (pe *PolicyEngine) GetDefaultAction() Action {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.defaultAction
}

func (pe *PolicyEngine) Stats() map[string]interface{} {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	return map[string]interface{}{
		"allowed_macs":    len(pe.allowedMACs),
		"allowed_ips":     len(pe.allowedIPs),
		"allowed_vendors": len(pe.allowedVendors),
		"blocked_macs":    len(pe.blockedMACs),
		"blocked_ips":     len(pe.blockedIPs),
		"total_rules":     len(pe.rules),
		"default_action":  pe.defaultAction,
	}
}
