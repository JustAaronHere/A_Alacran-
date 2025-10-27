package core

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type PortState string

const (
	PortOpen     PortState = "open"
	PortClosed   PortState = "closed"
	PortFiltered PortState = "filtered"
)

type PortScanMode string

const (
	PortScanModeTCP     PortScanMode = "tcp"
	PortScanModeUDP     PortScanMode = "udp"
	PortScanModeSYN     PortScanMode = "syn"
	PortScanModeConnect PortScanMode = "connect"
)

type PortScanConfig struct {
	Ports         []int
	Timeout       time.Duration
	Mode          PortScanMode
	Concurrency   int
	RateLimit     int
	BannerGrab    bool
	ServiceDetect bool
}

type PortResult struct {
	Port      int
	Protocol  string
	State     PortState
	Service   string
	Version   string
	Banner    string
	Error     error
	ScanTime  time.Duration
	Timestamp time.Time
}

type PortScanner struct {
	config     *PortScanConfig
	rateLimiter chan struct{}
	mu         sync.RWMutex
}

func NewPortScanner(config *PortScanConfig) *PortScanner {
	if config.Timeout == 0 {
		config.Timeout = 3 * time.Second
	}
	if config.Concurrency == 0 {
		config.Concurrency = 100
	}
	if config.Mode == "" {
		config.Mode = PortScanModeConnect
	}

	var rateLimiter chan struct{}
	if config.RateLimit > 0 {
		rateLimiter = make(chan struct{}, config.RateLimit)
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for range ticker.C {
				for i := 0; i < config.RateLimit; i++ {
					select {
					case rateLimiter <- struct{}{}:
					default:
						return
					}
				}
			}
		}()
	}

	return &PortScanner{
		config:      config,
		rateLimiter: rateLimiter,
	}
}

func (ps *PortScanner) ScanHost(ctx context.Context, target string) ([]*PortResult, error) {
	results := make([]*PortResult, 0)
	resultsChan := make(chan *PortResult, len(ps.config.Ports))
	sem := make(chan struct{}, ps.config.Concurrency)
	var wg sync.WaitGroup

	for _, port := range ps.config.Ports {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			if ps.rateLimiter != nil {
				<-ps.rateLimiter
			}

			sem <- struct{}{}
			defer func() { <-sem }()

			result := ps.scanPort(ctx, target, p)
			resultsChan <- result
		}(port)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		if result.State == PortOpen || result.State == PortFiltered {
			results = append(results, result)
		}
	}

	return results, nil
}

func (ps *PortScanner) scanPort(ctx context.Context, host string, port int) *PortResult {
	result := &PortResult{
		Port:      port,
		Protocol:  "tcp",
		Timestamp: time.Now(),
	}

	start := time.Now()
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", addr, ps.config.Timeout)
	result.ScanTime = time.Since(start)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = PortFiltered
		} else {
			result.State = PortClosed
		}
		result.Error = err
		return result
	}

	defer conn.Close()
	result.State = PortOpen

	if ps.config.BannerGrab {
		banner, err := ps.grabBanner(conn, port)
		if err == nil {
			result.Banner = banner
		}
	}

	if ps.config.ServiceDetect {
		service, version := ps.detectService(port, result.Banner)
		result.Service = service
		result.Version = version
	}

	return result
}

func (ps *PortScanner) grabBanner(conn net.Conn, port int) (string, error) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	probes := getProbesForPort(port)
	for _, probe := range probes {
		conn.Write([]byte(probe))
		buffer := make([]byte, 4096)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			return strings.TrimSpace(string(buffer[:n])), nil
		}
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(buffer[:n])), nil
}

func (ps *PortScanner) detectService(port int, banner string) (string, string) {
	service := getServiceByPort(port)
	version := ""

	if banner != "" {
		if strings.Contains(banner, "SSH") {
			service = "ssh"
			version = extractVersion(banner, "SSH-")
		} else if strings.Contains(banner, "HTTP") {
			service = "http"
			version = extractVersion(banner, "Server: ")
		} else if strings.Contains(banner, "FTP") {
			service = "ftp"
			version = extractVersion(banner, "FTP")
		} else if strings.Contains(banner, "SMTP") {
			service = "smtp"
		} else if strings.Contains(banner, "mysql") || strings.Contains(banner, "MySQL") {
			service = "mysql"
		} else if strings.Contains(banner, "PostgreSQL") {
			service = "postgresql"
		}
	}

	return service, version
}

func getProbesForPort(port int) []string {
	switch port {
	case 21:
		return []string{"USER anonymous\r\n"}
	case 22:
		return []string{"\r\n"}
	case 25:
		return []string{"EHLO aegis\r\n"}
	case 80, 8080, 8000:
		return []string{"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"}
	case 443, 8443:
		return []string{"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"}
	case 3306:
		return []string{"\x00"}
	case 5432:
		return []string{"\x00"}
	default:
		return []string{"\r\n\r\n", "HELP\r\n"}
	}
}

func getServiceByPort(port int) string {
	services := map[int]string{
		20:    "ftp-data",
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "smb",
		465:   "smtps",
		587:   "submission",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		27017: "mongodb",
	}

	if service, ok := services[port]; ok {
		return service
	}

	return "unknown"
}

func extractVersion(banner, prefix string) string {
	idx := strings.Index(banner, prefix)
	if idx == -1 {
		return ""
	}

	version := banner[idx+len(prefix):]
	if spaceIdx := strings.IndexAny(version, " \r\n\t"); spaceIdx != -1 {
		version = version[:spaceIdx]
	}

	return version
}

func GetCommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
		143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
	}
}

func GetTop100Ports() []int {
	return []int{
		7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
		79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
		139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
		465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
		646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
		1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
		2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
		5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
		6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
		9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
	}
}

func GetTop1000Ports() []int {
	ports := GetTop100Ports()
	additional := []int{
		8, 10, 11, 12, 15, 17, 18, 19, 20, 24,
		27, 31, 33, 35, 42, 43, 49, 50, 51, 52,
		70, 85, 87, 99, 100, 105, 107, 109, 115, 117,
		118, 123, 125, 129, 133, 137, 138, 161, 174, 177,
		194, 195, 197, 201, 256, 264, 280, 308, 311, 312,
	}
	ports = append(ports, additional...)
	return ports
}
