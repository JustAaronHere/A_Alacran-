package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/enrich"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/evidence"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/monitor"
)

type ReportTemplate string

const (
	TemplateUniversal ReportTemplate = "universal"
	TemplateExecutive ReportTemplate = "executive"
	TemplateForensic  ReportTemplate = "forensic"
)

type IncidentReport struct {
	ID              string
	Title           string
	Timestamp       time.Time
	Severity        string
	Device          *monitor.DeviceInfo
	Gateway         *monitor.GatewayInfo
	GeoInfo         *enrich.GeoIPInfo
	WhoisInfo       *enrich.WhoisInfo
	Events          []*monitor.NetworkEvent
	ThreatScore     float64
	Evidence        []*evidence.Evidence
	Remediation     []string
	Analyst         string
	Metadata        map[string]interface{}
}

type PDFGenerator struct {
	outputDir string
	template  ReportTemplate
}

func NewPDFGenerator(outputDir string, template ReportTemplate) (*PDFGenerator, error) {
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	return &PDFGenerator{
		outputDir: outputDir,
		template:  template,
	}, nil
}

func (pg *PDFGenerator) GenerateReport(report *IncidentReport) (string, error) {
	filename := filepath.Join(pg.outputDir, fmt.Sprintf("incident-%s-%d.txt", report.ID, time.Now().Unix()))

	content := pg.generateTextReport(report)

	if err := os.WriteFile(filename, []byte(content), 0640); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	return filename, nil
}

func (pg *PDFGenerator) generateTextReport(report *IncidentReport) string {
	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString("                          SECURITY INCIDENT REPORT\n")
	sb.WriteString("                              GATEHOUND SYSTEM\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════════════════\n\n")

	sb.WriteString("EXECUTIVE SUMMARY\n")
	sb.WriteString("───────────────────────────────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("Incident ID:       %s\n", report.ID))
	sb.WriteString(fmt.Sprintf("Title:             %s\n", report.Title))
	sb.WriteString(fmt.Sprintf("Date/Time:         %s\n", report.Timestamp.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Severity:          %s\n", report.Severity))
	sb.WriteString(fmt.Sprintf("Threat Score:      %.2f/100\n", report.ThreatScore))
	sb.WriteString(fmt.Sprintf("Analyst:           %s\n", report.Analyst))
	sb.WriteString("\n")

	if report.Device != nil {
		sb.WriteString("DEVICE PROFILE\n")
		sb.WriteString("───────────────────────────────────────────────────────────────────────────\n")
		sb.WriteString(fmt.Sprintf("MAC Address:       %s\n", report.Device.MAC.String()))
		sb.WriteString(fmt.Sprintf("Vendor:            %s\n", report.Device.Vendor))
		
		if len(report.Device.IP) > 0 {
			sb.WriteString("IP Addresses:      ")
			for i, ip := range report.Device.IP {
				if i > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(ip.String())
			}
			sb.WriteString("\n")
		}

		if report.Device.Hostname != "" {
			sb.WriteString(fmt.Sprintf("Hostname:          %s\n", report.Device.Hostname))
		}

		sb.WriteString(fmt.Sprintf("OS Guess:          %s\n", report.Device.OSGuess))
		sb.WriteString(fmt.Sprintf("Known Device:      %v\n", report.Device.IsKnown))
		sb.WriteString(fmt.Sprintf("First Seen:        %s\n", report.Device.FirstSeen.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Last Seen:         %s\n", report.Device.LastSeen.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Event Count:       %d\n", report.Device.EventCount))

		if report.Device.DHCPInfo != nil {
			sb.WriteString("\nDHCP Information:\n")
			if report.Device.DHCPInfo.Hostname != "" {
				sb.WriteString(fmt.Sprintf("  Hostname:        %s\n", report.Device.DHCPInfo.Hostname))
			}
			if report.Device.DHCPInfo.VendorClass != "" {
				sb.WriteString(fmt.Sprintf("  Vendor Class:    %s\n", report.Device.DHCPInfo.VendorClass))
			}
		}

		if report.Device.HTTPInfo != nil && report.Device.HTTPInfo.UserAgent != "" {
			sb.WriteString("\nHTTP Information:\n")
			sb.WriteString(fmt.Sprintf("  User-Agent:      %s\n", report.Device.HTTPInfo.UserAgent))
		}

		if report.Device.TLSInfo != nil && report.Device.TLSInfo.SNI != "" {
			sb.WriteString("\nTLS Information:\n")
			sb.WriteString(fmt.Sprintf("  SNI:             %s\n", report.Device.TLSInfo.SNI))
			sb.WriteString(fmt.Sprintf("  Version:         %s\n", report.Device.TLSInfo.Version))
		}

		sb.WriteString("\n")
	}

	if report.GeoInfo != nil && report.GeoInfo.Country != "" {
		sb.WriteString("GEOLOCATION & NETWORK INFORMATION\n")
		sb.WriteString("───────────────────────────────────────────────────────────────────────────\n")
		sb.WriteString(fmt.Sprintf("Country:           %s (%s)\n", report.GeoInfo.Country, report.GeoInfo.CountryCode))
		if report.GeoInfo.City != "" {
			sb.WriteString(fmt.Sprintf("City:              %s\n", report.GeoInfo.City))
		}
		if report.GeoInfo.Region != "" {
			sb.WriteString(fmt.Sprintf("Region:            %s\n", report.GeoInfo.Region))
		}
		if report.GeoInfo.Latitude != 0 || report.GeoInfo.Longitude != 0 {
			sb.WriteString(fmt.Sprintf("Coordinates:       %.6f, %.6f\n", report.GeoInfo.Latitude, report.GeoInfo.Longitude))
		}
		if report.GeoInfo.ASN > 0 {
			sb.WriteString(fmt.Sprintf("ASN:               AS%d\n", report.GeoInfo.ASN))
			sb.WriteString(fmt.Sprintf("ASN Org:           %s\n", report.GeoInfo.ASNOrg))
		}
		if report.GeoInfo.IsProxy || report.GeoInfo.IsTor {
			sb.WriteString("\n⚠ WARNING: Proxy/Anonymization Detected\n")
			if report.GeoInfo.IsProxy {
				sb.WriteString("  - Proxy detected\n")
			}
			if report.GeoInfo.IsTor {
				sb.WriteString("  - Tor exit node\n")
			}
		}
		sb.WriteString("\n")
	}

	if report.Gateway != nil {
		sb.WriteString("GATEWAY/ROUTER INFORMATION\n")
		sb.WriteString("───────────────────────────────────────────────────────────────────────────\n")
		sb.WriteString(fmt.Sprintf("IP Address:        %s\n", report.Gateway.IP.String()))
		sb.WriteString(fmt.Sprintf("MAC Address:       %s\n", report.Gateway.MAC.String()))
		if report.Gateway.Vendor != "" {
			sb.WriteString(fmt.Sprintf("Vendor:            %s\n", report.Gateway.Vendor))
		}
		if report.Gateway.Hostname != "" {
			sb.WriteString(fmt.Sprintf("Hostname:          %s\n", report.Gateway.Hostname))
		}
		if report.Gateway.Model != "" {
			sb.WriteString(fmt.Sprintf("Model:             %s\n", report.Gateway.Model))
		}
		sb.WriteString("\n")
	}

	if len(report.Events) > 0 {
		sb.WriteString("TIMELINE OF EVENTS\n")
		sb.WriteString("───────────────────────────────────────────────────────────────────────────\n")
		
		count := len(report.Events)
		if count > 10 {
			count = 10
		}

		for i := 0; i < count; i++ {
			event := report.Events[i]
			sb.WriteString(fmt.Sprintf("[%s] %s\n", 
				event.Timestamp.Format("15:04:05"), 
				string(event.Type)))
			
			if event.SrcIP != nil {
				sb.WriteString(fmt.Sprintf("  Source: %s", event.SrcIP.String()))
				if event.SrcPort > 0 {
					sb.WriteString(fmt.Sprintf(":%d", event.SrcPort))
				}
				sb.WriteString("\n")
			}
			
			if event.DstIP != nil {
				sb.WriteString(fmt.Sprintf("  Dest:   %s", event.DstIP.String()))
				if event.DstPort > 0 {
					sb.WriteString(fmt.Sprintf(":%d", event.DstPort))
				}
				sb.WriteString("\n")
			}
			sb.WriteString("\n")
		}

		if len(report.Events) > 10 {
			sb.WriteString(fmt.Sprintf("... and %d more events\n\n", len(report.Events)-10))
		}
	}

	if len(report.Evidence) > 0 {
		sb.WriteString("EVIDENCE COLLECTED\n")
		sb.WriteString("───────────────────────────────────────────────────────────────────────────\n")
		for _, ev := range report.Evidence {
			sb.WriteString(fmt.Sprintf("- %s (%s)\n", ev.ID, ev.Type))
			sb.WriteString(fmt.Sprintf("  Collected: %s\n", ev.Timestamp.Format(time.RFC3339)))
			if ev.FileHash != "" {
				sb.WriteString(fmt.Sprintf("  Hash: %s\n", ev.FileHash[:16]))
			}
			if ev.Signature != "" {
				sb.WriteString("  Status: Signed ✓\n")
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("THREAT ASSESSMENT\n")
	sb.WriteString("───────────────────────────────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("Threat Score: %.2f/100\n\n", report.ThreatScore))

	severity := "LOW"
	if report.ThreatScore >= 75 {
		severity = "CRITICAL"
	} else if report.ThreatScore >= 50 {
		severity = "HIGH"
	} else if report.ThreatScore >= 25 {
		severity = "MEDIUM"
	}
	sb.WriteString(fmt.Sprintf("Severity Level: %s\n\n", severity))

	if len(report.Remediation) > 0 {
		sb.WriteString("RECOMMENDED ACTIONS\n")
		sb.WriteString("───────────────────────────────────────────────────────────────────────────\n")
		for i, action := range report.Remediation {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, action))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("═══════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString("                           END OF REPORT\n")
	sb.WriteString(fmt.Sprintf("            Generated: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString("             Gatehound Passive Defense System v1.0\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════════════════\n")

	return sb.String()
}

func (pg *PDFGenerator) GenerateDeviceSummary(devices []*monitor.DeviceInfo) (string, error) {
	filename := filepath.Join(pg.outputDir, fmt.Sprintf("device-summary-%d.txt", time.Now().Unix()))

	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString("                        DEVICE INVENTORY SUMMARY\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════════════════\n\n")

	sb.WriteString(fmt.Sprintf("Total Devices: %d\n", len(devices)))
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))

	for i, device := range devices {
		sb.WriteString(fmt.Sprintf("Device %d:\n", i+1))
		sb.WriteString(fmt.Sprintf("  MAC: %s\n", device.MAC.String()))
		sb.WriteString(fmt.Sprintf("  Vendor: %s\n", device.Vendor))
		if len(device.IP) > 0 {
			sb.WriteString(fmt.Sprintf("  IP: %s\n", device.IP[0].String()))
		}
		sb.WriteString(fmt.Sprintf("  Known: %v\n", device.IsKnown))
		sb.WriteString(fmt.Sprintf("  Threat Score: %.2f\n", device.ThreatScore))
		sb.WriteString("\n")
	}

	if err := os.WriteFile(filename, []byte(sb.String()), 0640); err != nil {
		return "", fmt.Errorf("failed to write summary: %w", err)
	}

	return filename, nil
}
