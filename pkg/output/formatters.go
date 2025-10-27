package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/aegis/core"
)

type OutputFormat string

const (
	FormatJSON   OutputFormat = "json"
	FormatNDJSON OutputFormat = "ndjson"
	FormatSARIF  OutputFormat = "sarif"
	FormatCSV    OutputFormat = "csv"
	FormatText   OutputFormat = "text"
)

type Formatter interface {
	Format(results []*core.HostScanResult) ([]byte, error)
	FormatStream(w io.Writer, result *core.HostScanResult) error
}

type JSONFormatter struct {
	Pretty bool
}

func (f *JSONFormatter) Format(results []*core.HostScanResult) ([]byte, error) {
	if f.Pretty {
		return json.MarshalIndent(results, "", "  ")
	}
	return json.Marshal(results)
}

func (f *JSONFormatter) FormatStream(w io.Writer, result *core.HostScanResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

type NDJSONFormatter struct{}

func (f *NDJSONFormatter) Format(results []*core.HostScanResult) ([]byte, error) {
	var sb strings.Builder
	for _, result := range results {
		data, err := json.Marshal(result)
		if err != nil {
			return nil, err
		}
		sb.Write(data)
		sb.WriteByte('\n')
	}
	return []byte(sb.String()), nil
}

func (f *NDJSONFormatter) FormatStream(w io.Writer, result *core.HostScanResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

type SARIFFormatter struct{}

type SARIFReport struct {
	Version string      `json:"version"`
	Schema  string      `json:"$schema"`
	Runs    []SARIFRun  `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool    `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	InformationURI  string `json:"informationUri"`
}

type SARIFResult struct {
	RuleID  string            `json:"ruleId"`
	Level   string            `json:"level"`
	Message SARIFMessage      `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

func (f *SARIFFormatter) Format(results []*core.HostScanResult) ([]byte, error) {
	sarifResults := make([]SARIFResult, 0)

	for _, hostResult := range results {
		for _, vulnService := range hostResult.Vulnerabilities {
			for _, vuln := range vulnService.Vulnerabilities {
				level := "warning"
				switch strings.ToUpper(vuln.Severity) {
				case "CRITICAL", "HIGH":
					level = "error"
				case "MEDIUM":
					level = "warning"
				case "LOW":
					level = "note"
				}

				sarifResults = append(sarifResults, SARIFResult{
					RuleID: vuln.CVE,
					Level:  level,
					Message: SARIFMessage{
						Text: fmt.Sprintf("%s - %s (Service: %s %s)",
							vuln.CVE, vuln.Description, vulnService.Service, vulnService.Version),
					},
					Locations: []SARIFLocation{
						{
							PhysicalLocation: SARIFPhysicalLocation{
								ArtifactLocation: SARIFArtifactLocation{
									URI: fmt.Sprintf("host://%s", hostResult.IP),
								},
							},
						},
					},
				})
			}
		}
	}

	report := SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "Aegis Scanner",
						Version:        "1.0.0",
						InformationURI: "https://github.com/aegis-sentinel/aegis-suite",
					},
				},
				Results: sarifResults,
			},
		},
	}

	return json.MarshalIndent(report, "", "  ")
}

func (f *SARIFFormatter) FormatStream(w io.Writer, result *core.HostScanResult) error {
	return fmt.Errorf("SARIF format does not support streaming")
}

type CSVFormatter struct{}

func (f *CSVFormatter) Format(results []*core.HostScanResult) ([]byte, error) {
	var sb strings.Builder
	writer := csv.NewWriter(&sb)

	headers := []string{"IP", "Hostname", "Port", "Protocol", "State", "Service", "Version", "CVE", "Severity", "Description"}
	if err := writer.Write(headers); err != nil {
		return nil, err
	}

	for _, hostResult := range results {
		for _, port := range hostResult.Ports {
			row := []string{
				hostResult.IP,
				hostResult.Hostname,
				fmt.Sprintf("%d", port.Port),
				port.Protocol,
				string(port.State),
				port.Service,
				port.Version,
				"",
				"",
				"",
			}
			writer.Write(row)
		}

		for _, vulnService := range hostResult.Vulnerabilities {
			for _, vuln := range vulnService.Vulnerabilities {
				row := []string{
					hostResult.IP,
					hostResult.Hostname,
					"",
					"",
					"",
					vulnService.Service,
					vulnService.Version,
					vuln.CVE,
					vuln.Severity,
					vuln.Description,
				}
				writer.Write(row)
			}
		}
	}

	writer.Flush()
	return []byte(sb.String()), writer.Error()
}

func (f *CSVFormatter) FormatStream(w io.Writer, result *core.HostScanResult) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	for _, port := range result.Ports {
		row := []string{
			result.IP,
			result.Hostname,
			fmt.Sprintf("%d", port.Port),
			port.Protocol,
			string(port.State),
			port.Service,
			port.Version,
			"",
			"",
			"",
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return writer.Error()
}

type TextFormatter struct{}

func (f *TextFormatter) Format(results []*core.HostScanResult) ([]byte, error) {
	var sb strings.Builder

	sb.WriteString(Header("AEGIS SCAN RESULTS"))
	sb.WriteString("\n\n")

	for idx, result := range results {
		if idx > 0 {
			sb.WriteString("\n" + Divider() + "\n\n")
		}

		sb.WriteString(Section(fmt.Sprintf("Host: %s", result.IP)))
		sb.WriteString("\n")

		if result.Hostname != "" {
			sb.WriteString(KeyValue("Hostname", result.Hostname) + "\n")
		}
		sb.WriteString(KeyValue("IP Address", result.IP) + "\n")
		sb.WriteString(KeyValue("Scan Time", result.Timestamp.Format(time.RFC3339)) + "\n")
		sb.WriteString(KeyValue("Duration", result.ScanTime.String()) + "\n")

		if result.Fingerprint != nil && result.Fingerprint.OS != nil {
			confidence := fmt.Sprintf("%d%%", result.Fingerprint.OS.Confidence)
			var confColor Color
			if result.Fingerprint.OS.Confidence >= 90 {
				confColor = Green
			} else if result.Fingerprint.OS.Confidence >= 70 {
				confColor = Yellow
			} else {
				confColor = Red
			}
			sb.WriteString(Colorize(Gray, "Operating System: ") + 
				Colorize(Bold, result.Fingerprint.OS.Name) + 
				" " + Colorize(confColor, "("+confidence+")") + "\n")
		}

		type portInfo struct {
			Port     int
			Protocol string
			Service  string
			Version  string
		}
		
		openPorts := make([]portInfo, 0)
		for _, port := range result.Ports {
			if port.State == core.PortOpen {
				openPorts = append(openPorts, portInfo{
					Port:     port.Port,
					Protocol: port.Protocol,
					Service:  port.Service,
					Version:  port.Version,
				})
			}
		}

		if len(openPorts) > 0 {
			sb.WriteString("\n" + Section("Open Ports") + "\n")
			table := NewTable("Port", "Protocol", "Service", "Version")
			for _, port := range openPorts {
				portStr := Colorize(BrightCyan, fmt.Sprintf("%d", port.Port))
				protocol := Colorize(Gray, strings.ToUpper(port.Protocol))
				service := port.Service
				if service == "" {
					service = Colorize(Gray, "unknown")
				} else {
					service = Colorize(Green, service)
				}
				version := port.Version
				if version == "" {
					version = Colorize(Gray, "-")
				}
				table.AddRow(portStr, protocol, service, version)
			}
			sb.WriteString(table.Render() + "\n")
		}

		if len(result.Vulnerabilities) > 0 {
			sb.WriteString("\n" + Section("Vulnerabilities") + "\n")
			
			table := NewTable("CVE", "Severity", "Service", "Description")
			for _, vulnService := range result.Vulnerabilities {
				for _, vuln := range vulnService.Vulnerabilities {
					cveStr := Colorize(BrightWhite, vuln.CVE)
					sevBadge := SeverityBadge(vuln.Severity)
					serviceStr := fmt.Sprintf("%s %s", vulnService.Service, vulnService.Version)
					desc := vuln.Description
					if len(desc) > 50 {
						desc = desc[:47] + "..."
					}
					table.AddRow(cveStr, sevBadge, serviceStr, desc)
				}
			}
			sb.WriteString(table.Render() + "\n")

			criticalCount := 0
			highCount := 0
			mediumCount := 0
			lowCount := 0

			for _, vulnService := range result.Vulnerabilities {
				for _, vuln := range vulnService.Vulnerabilities {
					switch strings.ToUpper(vuln.Severity) {
					case "CRITICAL":
						criticalCount++
					case "HIGH":
						highCount++
					case "MEDIUM":
						mediumCount++
					case "LOW":
						lowCount++
					}
				}
			}

			sb.WriteString("\n" + Colorize(Gray, "Vulnerability Summary: "))
			if criticalCount > 0 {
				sb.WriteString(Critical(fmt.Sprintf("%d Critical", criticalCount)) + " ")
			}
			if highCount > 0 {
				sb.WriteString(High(fmt.Sprintf("%d High", highCount)) + " ")
			}
			if mediumCount > 0 {
				sb.WriteString(Medium(fmt.Sprintf("%d Medium", mediumCount)) + " ")
			}
			if lowCount > 0 {
				sb.WriteString(Low(fmt.Sprintf("%d Low", lowCount)))
			}
			sb.WriteString("\n")
		}

		if result.Fingerprint != nil && result.Fingerprint.HTTP != nil {
			sb.WriteString("\n" + Section("HTTP Information") + "\n")
			if result.Fingerprint.HTTP.Server != "" {
				sb.WriteString(KeyValue("Server", result.Fingerprint.HTTP.Server) + "\n")
			}
			if result.Fingerprint.HTTP.Title != "" {
				sb.WriteString(KeyValue("Title", result.Fingerprint.HTTP.Title) + "\n")
			}
			if result.Fingerprint.HTTP.CMS != "" {
				sb.WriteString(KeyValueColored("CMS", result.Fingerprint.HTTP.CMS, BrightGreen) + "\n")
			}
			if result.Fingerprint.HTTP.Framework != "" {
				sb.WriteString(KeyValueColored("Framework", result.Fingerprint.HTTP.Framework, BrightCyan) + "\n")
			}
		}

		sb.WriteString(SectionEnd() + "\n")
	}

	return []byte(sb.String()), nil
}

func (f *TextFormatter) FormatStream(w io.Writer, result *core.HostScanResult) error {
	data, err := f.Format([]*core.HostScanResult{result})
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func GetFormatter(format OutputFormat) Formatter {
	switch format {
	case FormatJSON:
		return &JSONFormatter{Pretty: true}
	case FormatNDJSON:
		return &NDJSONFormatter{}
	case FormatSARIF:
		return &SARIFFormatter{}
	case FormatCSV:
		return &CSVFormatter{}
	case FormatText:
		return &TextFormatter{}
	default:
		return &JSONFormatter{Pretty: true}
	}
}
