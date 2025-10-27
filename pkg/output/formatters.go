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

	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	sb.WriteString("                    AEGIS SCAN RESULTS\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	for _, result := range results {
		sb.WriteString(fmt.Sprintf("Host: %s", result.IP))
		if result.Hostname != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", result.Hostname))
		}
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("Scan Time: %s\n", result.Timestamp.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Duration: %s\n", result.ScanTime))

		if result.Fingerprint != nil && result.Fingerprint.OS != nil {
			sb.WriteString(fmt.Sprintf("OS: %s (Confidence: %d%%)\n",
				result.Fingerprint.OS.Name, result.Fingerprint.OS.Confidence))
		}

		sb.WriteString("\n")
		sb.WriteString("Open Ports:\n")
		sb.WriteString("───────────────────────────────────────────────────────────────\n")
		
		for _, port := range result.Ports {
			if port.State == core.PortOpen {
				sb.WriteString(fmt.Sprintf("  %d/%s", port.Port, port.Protocol))
				if port.Service != "" {
					sb.WriteString(fmt.Sprintf("  %s", port.Service))
				}
				if port.Version != "" {
					sb.WriteString(fmt.Sprintf(" (%s)", port.Version))
				}
				sb.WriteString("\n")
			}
		}

		if len(result.Vulnerabilities) > 0 {
			sb.WriteString("\nVulnerabilities:\n")
			sb.WriteString("───────────────────────────────────────────────────────────────\n")
			
			for _, vulnService := range result.Vulnerabilities {
				for _, vuln := range vulnService.Vulnerabilities {
					sb.WriteString(fmt.Sprintf("  [%s] %s\n", vuln.Severity, vuln.CVE))
					sb.WriteString(fmt.Sprintf("    Service: %s", vulnService.Service))
					if vulnService.Version != "" {
						sb.WriteString(fmt.Sprintf(" %s", vulnService.Version))
					}
					sb.WriteString("\n")
					sb.WriteString(fmt.Sprintf("    %s\n", vuln.Description))
					if len(vuln.MITRE) > 0 {
						sb.WriteString(fmt.Sprintf("    MITRE: %s\n", strings.Join(vuln.MITRE, ", ")))
					}
					sb.WriteString("\n")
				}
			}
		}

		if result.Fingerprint != nil && result.Fingerprint.HTTP != nil {
			sb.WriteString("\nHTTP Information:\n")
			sb.WriteString("───────────────────────────────────────────────────────────────\n")
			if result.Fingerprint.HTTP.Server != "" {
				sb.WriteString(fmt.Sprintf("  Server: %s\n", result.Fingerprint.HTTP.Server))
			}
			if result.Fingerprint.HTTP.Title != "" {
				sb.WriteString(fmt.Sprintf("  Title: %s\n", result.Fingerprint.HTTP.Title))
			}
			if result.Fingerprint.HTTP.CMS != "" {
				sb.WriteString(fmt.Sprintf("  CMS: %s\n", result.Fingerprint.HTTP.CMS))
			}
			if result.Fingerprint.HTTP.Framework != "" {
				sb.WriteString(fmt.Sprintf("  Framework: %s\n", result.Fingerprint.HTTP.Framework))
			}
		}

		sb.WriteString("\n═══════════════════════════════════════════════════════════════\n\n")
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
