package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Vulnerability struct {
	CVE          string   `json:"cve"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Severity     string   `json:"severity"`
	CVSS         float64  `json:"cvss"`
	MITRE        []string `json:"mitre"`
	References   []string `json:"references"`
	Published    string   `json:"published"`
	LastModified string   `json:"last_modified"`
}

type ServiceVulnerability struct {
	Service        string
	Version        string
	Vulnerabilities []*Vulnerability
}

type VulnMapper struct {
	db     map[string][]*Vulnerability
	mu     sync.RWMutex
	dbPath string
}

func NewVulnMapper(dbPath string) (*VulnMapper, error) {
	vm := &VulnMapper{
		db:     make(map[string][]*Vulnerability),
		dbPath: dbPath,
	}

	if err := vm.loadDatabase(); err != nil {
		vm.initializeDefaultDB()
	}

	return vm, nil
}

func (vm *VulnMapper) MapVulnerabilities(ctx context.Context, ports []*PortResult, fingerprint *Fingerprint) ([]*ServiceVulnerability, error) {
	results := make([]*ServiceVulnerability, 0)

	for _, port := range ports {
		if port.State != PortOpen {
			continue
		}

		vulns := vm.findVulnerabilities(port.Service, port.Version)
		if len(vulns) > 0 {
			results = append(results, &ServiceVulnerability{
				Service:        port.Service,
				Version:        port.Version,
				Vulnerabilities: vulns,
			})
		}
	}

	if fingerprint != nil && fingerprint.HTTP != nil {
		if fingerprint.HTTP.CMS != "" {
			vulns := vm.findVulnerabilities(strings.ToLower(fingerprint.HTTP.CMS), "")
			if len(vulns) > 0 {
				results = append(results, &ServiceVulnerability{
					Service:        fingerprint.HTTP.CMS,
					Version:        "",
					Vulnerabilities: vulns,
				})
			}
		}

		if fingerprint.HTTP.Server != "" {
			serverParts := strings.Fields(fingerprint.HTTP.Server)
			if len(serverParts) > 0 {
				server := serverParts[0]
				version := ""
				if len(serverParts) > 1 {
					version = serverParts[1]
				}
				vulns := vm.findVulnerabilities(strings.ToLower(server), version)
				if len(vulns) > 0 {
					results = append(results, &ServiceVulnerability{
						Service:        server,
						Version:        version,
						Vulnerabilities: vulns,
					})
				}
			}
		}

		for _, tech := range fingerprint.Technologies {
			vulns := vm.findVulnerabilities(strings.ToLower(tech.Name), tech.Version)
			if len(vulns) > 0 {
				results = append(results, &ServiceVulnerability{
					Service:        tech.Name,
					Version:        tech.Version,
					Vulnerabilities: vulns,
				})
			}
		}
	}

	if fingerprint != nil && fingerprint.TLS != nil {
		tlsVulns := vm.checkTLSVulnerabilities(fingerprint.TLS)
		if len(tlsVulns) > 0 {
			results = append(results, &ServiceVulnerability{
				Service:        "TLS",
				Version:        fingerprint.TLS.Version,
				Vulnerabilities: tlsVulns,
			})
		}
	}

	return results, nil
}

func (vm *VulnMapper) findVulnerabilities(service, version string) []*Vulnerability {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	service = strings.ToLower(service)
	key := service

	if version != "" {
		key = fmt.Sprintf("%s:%s", service, version)
		if vulns, ok := vm.db[key]; ok {
			return vulns
		}
	}

	if vulns, ok := vm.db[service]; ok {
		return vulns
	}

	return nil
}

func (vm *VulnMapper) checkTLSVulnerabilities(tlsFP *TLSFingerprint) []*Vulnerability {
	vulns := make([]*Vulnerability, 0)

	if strings.Contains(tlsFP.Version, "1.0") || strings.Contains(tlsFP.Version, "1.1") {
		vulns = append(vulns, &Vulnerability{
			CVE:         "TLS-DEPREC",
			Title:       "Deprecated TLS Version",
			Description: fmt.Sprintf("TLS version %s is deprecated and should not be used", tlsFP.Version),
			Severity:    "MEDIUM",
			CVSS:        5.0,
			MITRE:       []string{"T1040"},
			Published:   "2021-01-01",
		})
	}

	weakCiphers := []string{"DES", "RC4", "MD5", "NULL"}
	for _, weak := range weakCiphers {
		if strings.Contains(tlsFP.CipherSuite, weak) {
			vulns = append(vulns, &Vulnerability{
				CVE:         "TLS-WEAK-CIPHER",
				Title:       "Weak Cipher Suite",
				Description: fmt.Sprintf("Weak cipher suite detected: %s", tlsFP.CipherSuite),
				Severity:    "HIGH",
				CVSS:        7.5,
				MITRE:       []string{"T1040", "T1557"},
				Published:   "2020-01-01",
			})
			break
		}
	}

	for _, cert := range tlsFP.Certificates {
		if cert.NotAfter.Before(context.Background().Value("timestamp").(time.Time)) {
			vulns = append(vulns, &Vulnerability{
				CVE:         "TLS-EXPIRED-CERT",
				Title:       "Expired TLS Certificate",
				Description: fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format("2006-01-02")),
				Severity:    "HIGH",
				CVSS:        7.5,
				MITRE:       []string{"T1040", "T1557"},
				Published:   "2020-01-01",
			})
		}
	}

	return vulns
}

func (vm *VulnMapper) AddVulnerability(service, version string, vuln *Vulnerability) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	key := service
	if version != "" {
		key = fmt.Sprintf("%s:%s", service, version)
	}

	if _, ok := vm.db[key]; !ok {
		vm.db[key] = make([]*Vulnerability, 0)
	}

	vm.db[key] = append(vm.db[key], vuln)
}

func (vm *VulnMapper) loadDatabase() error {
	if vm.dbPath == "" {
		return fmt.Errorf("no database path specified")
	}

	data, err := os.ReadFile(vm.dbPath)
	if err != nil {
		return err
	}

	var db map[string][]*Vulnerability
	if err := json.Unmarshal(data, &db); err != nil {
		return err
	}

	vm.mu.Lock()
	vm.db = db
	vm.mu.Unlock()

	return nil
}

func (vm *VulnMapper) SaveDatabase() error {
	if vm.dbPath == "" {
		return fmt.Errorf("no database path specified")
	}

	vm.mu.RLock()
	data, err := json.MarshalIndent(vm.db, "", "  ")
	vm.mu.RUnlock()

	if err != nil {
		return err
	}

	dir := filepath.Dir(vm.dbPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	return os.WriteFile(vm.dbPath, data, 0640)
}

func (vm *VulnMapper) initializeDefaultDB() {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	vm.db = map[string][]*Vulnerability{
		"ssh": {
			{
				CVE:         "CVE-2023-0001",
				Title:       "SSH Authentication Bypass",
				Description: "Example SSH vulnerability for demonstration",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				MITRE:       []string{"T1078", "T1021.004"},
				Published:   "2023-01-01",
			},
		},
		"apache:2.4.49": {
			{
				CVE:         "CVE-2021-41773",
				Title:       "Apache HTTP Server Path Traversal",
				Description: "Path traversal and RCE vulnerability in Apache 2.4.49",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				MITRE:       []string{"T1190", "T1083"},
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
				Published:   "2021-10-05",
			},
		},
		"apache:2.4.50": {
			{
				CVE:         "CVE-2021-42013",
				Title:       "Apache HTTP Server Path Traversal and RCE",
				Description: "Path traversal and remote code execution in Apache 2.4.50",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				MITRE:       []string{"T1190", "T1059"},
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
				Published:   "2021-10-07",
			},
		},
		"nginx": {
			{
				CVE:         "CVE-2021-23017",
				Title:       "nginx DNS Resolver Off-by-One",
				Description: "Off-by-one buffer overflow in nginx resolver",
				Severity:    "HIGH",
				CVSS:        8.1,
				MITRE:       []string{"T1190"},
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-23017"},
				Published:   "2021-05-25",
			},
		},
		"wordpress": {
			{
				CVE:         "CVE-2023-WORDPRESS",
				Title:       "WordPress SQL Injection",
				Description: "SQL injection vulnerability in WordPress core",
				Severity:    "HIGH",
				CVSS:        8.5,
				MITRE:       []string{"T1190", "T1213"},
				Published:   "2023-01-01",
			},
		},
		"drupal": {
			{
				CVE:         "CVE-2018-7600",
				Title:       "Drupalgeddon 2.0",
				Description: "Remote code execution in Drupal core (Drupalgeddon 2)",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				MITRE:       []string{"T1190", "T1059"},
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-7600"},
				Published:   "2018-03-28",
			},
		},
		"mysql": {
			{
				CVE:         "CVE-2023-MYSQL",
				Title:       "MySQL Authentication Bypass",
				Description: "Authentication bypass in MySQL server",
				Severity:    "CRITICAL",
				CVSS:        9.1,
				MITRE:       []string{"T1078", "T1210"},
				Published:   "2023-01-01",
			},
		},
		"postgresql": {
			{
				CVE:         "CVE-2023-PGSQL",
				Title:       "PostgreSQL SQL Injection",
				Description: "SQL injection vulnerability in PostgreSQL",
				Severity:    "HIGH",
				CVSS:        8.8,
				MITRE:       []string{"T1190", "T1213"},
				Published:   "2023-01-01",
			},
		},
		"ftp": {
			{
				CVE:         "FTP-CLEARTEXT",
				Title:       "FTP Cleartext Credentials",
				Description: "FTP transmits credentials in cleartext",
				Severity:    "HIGH",
				CVSS:        7.5,
				MITRE:       []string{"T1040", "T1110"},
				Published:   "2000-01-01",
			},
		},
		"telnet": {
			{
				CVE:         "TELNET-CLEARTEXT",
				Title:       "Telnet Cleartext Protocol",
				Description: "Telnet transmits all data including credentials in cleartext",
				Severity:    "HIGH",
				CVSS:        7.5,
				MITRE:       []string{"T1040", "T1021.002"},
				Published:   "2000-01-01",
			},
		},
		"smb": {
			{
				CVE:         "CVE-2017-0144",
				Title:       "EternalBlue SMB Vulnerability",
				Description: "Remote code execution vulnerability in SMBv1 (EternalBlue)",
				Severity:    "CRITICAL",
				CVSS:        10.0,
				MITRE:       []string{"T1190", "T1210"},
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-0144"},
				Published:   "2017-03-14",
			},
		},
		"rdp": {
			{
				CVE:         "CVE-2019-0708",
				Title:       "BlueKeep RDP Vulnerability",
				Description: "Remote code execution in Remote Desktop Services (BlueKeep)",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				MITRE:       []string{"T1190", "T1210"},
				References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-0708"},
				Published:   "2019-05-14",
			},
		},
	}
}

func (vm *VulnMapper) UpdateDatabase(newData map[string][]*Vulnerability) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	for key, vulns := range newData {
		vm.db[key] = vulns
	}
}

func (vm *VulnMapper) GetStatistics() map[string]int {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	stats := map[string]int{
		"total_services": len(vm.db),
		"total_vulns":    0,
		"critical":       0,
		"high":           0,
		"medium":         0,
		"low":            0,
	}

	for _, vulns := range vm.db {
		stats["total_vulns"] += len(vulns)
		for _, vuln := range vulns {
			switch strings.ToUpper(vuln.Severity) {
			case "CRITICAL":
				stats["critical"]++
			case "HIGH":
				stats["high"]++
			case "MEDIUM":
				stats["medium"]++
			case "LOW":
				stats["low"]++
			}
		}
	}

	return stats
}
