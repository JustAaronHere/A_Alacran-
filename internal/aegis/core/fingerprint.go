package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Fingerprint struct {
	OS            *OSFingerprint
	HTTP          *HTTPFingerprint
	TLS           *TLSFingerprint
	Technologies  []Technology
	Vulnerabilities []string
}

type OSFingerprint struct {
	Name       string
	Version    string
	Confidence int
	TTL        int
	WindowSize int
}

type HTTPFingerprint struct {
	Server      string
	Technologies []string
	Headers     map[string]string
	Title       string
	StatusCode  int
	ContentType string
	Cookies     []string
	CMS         string
	Framework   string
	Languages   []string
}

type TLSFingerprint struct {
	Version      string
	CipherSuite  string
	Certificates []CertInfo
	ALPN         []string
	SNI          string
}

type CertInfo struct {
	Subject    string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	SANs       []string
	CommonName string
	Serial     string
}

type Technology struct {
	Name       string
	Version    string
	Category   string
	Confidence int
	Evidence   []string
}

type Fingerprinter struct {
	timeout    time.Duration
	userAgent  string
	httpClient *http.Client
}

func NewFingerprinter(timeout time.Duration) *Fingerprinter {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &Fingerprinter{
		timeout:   timeout,
		userAgent: "Mozilla/5.0 (compatible; AegisSentinel/1.0)",
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (f *Fingerprinter) FingerprintHost(ctx context.Context, ip string, ports []*PortResult) (*Fingerprint, error) {
	fp := &Fingerprint{
		Technologies: make([]Technology, 0),
	}

	fp.OS = f.fingerprintOS(ip, ports)

	for _, port := range ports {
		if port.State == PortOpen {
			if isHTTPPort(port.Port) {
				httpFP := f.fingerprintHTTP(ctx, ip, port.Port)
				if httpFP != nil {
					fp.HTTP = httpFP
					fp.Technologies = append(fp.Technologies, f.detectTechnologies(httpFP)...)
				}
			}

			if isHTTPSPort(port.Port) {
				tlsFP := f.fingerprintTLS(ctx, ip, port.Port)
				if tlsFP != nil {
					fp.TLS = tlsFP
				}

				httpFP := f.fingerprintHTTP(ctx, ip, port.Port)
				if httpFP != nil {
					if fp.HTTP == nil {
						fp.HTTP = httpFP
					}
					fp.Technologies = append(fp.Technologies, f.detectTechnologies(httpFP)...)
				}
			}
		}
	}

	return fp, nil
}

func (f *Fingerprinter) fingerprintOS(ip string, ports []*PortResult) *OSFingerprint {
	os := &OSFingerprint{
		Confidence: 0,
	}

	ttl := f.getTTL(ip)
	os.TTL = ttl

	switch {
	case ttl <= 64:
		os.Name = "Linux/Unix"
		os.Confidence = 60
	case ttl <= 128:
		os.Name = "Windows"
		os.Confidence = 60
	case ttl <= 255:
		os.Name = "Cisco/Network Device"
		os.Confidence = 50
	}

	for _, port := range ports {
		if port.Port == 3389 && port.State == PortOpen {
			os.Name = "Windows"
			os.Confidence = 90
		}
		if port.Port == 22 && port.State == PortOpen && strings.Contains(port.Banner, "Ubuntu") {
			os.Name = "Ubuntu Linux"
			os.Confidence = 95
		}
		if port.Port == 22 && port.State == PortOpen && strings.Contains(port.Banner, "Debian") {
			os.Name = "Debian Linux"
			os.Confidence = 95
		}
		if strings.Contains(port.Banner, "Microsoft") {
			os.Name = "Windows"
			os.Confidence = 90
		}
	}

	return os
}

func (f *Fingerprinter) getTTL(ip string) int {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), 2*time.Second)
	if err != nil {
		return 64
	}
	defer conn.Close()
	return 64
}

func (f *Fingerprinter) fingerprintHTTP(ctx context.Context, ip string, port int) *HTTPFingerprint {
	scheme := "http"
	if isHTTPSPort(port) {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", f.userAgent)

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

	fp := &HTTPFingerprint{
		Headers:    make(map[string]string),
		StatusCode: resp.StatusCode,
		Cookies:    make([]string, 0),
	}

	for k, v := range resp.Header {
		if len(v) > 0 {
			fp.Headers[k] = v[0]
		}
	}

	if server := resp.Header.Get("Server"); server != "" {
		fp.Server = server
	}

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		fp.ContentType = ct
	}

	for _, cookie := range resp.Cookies() {
		fp.Cookies = append(fp.Cookies, cookie.Name)
	}

	fp.Title = extractTitle(string(body))
	fp.CMS = detectCMS(string(body), fp.Headers)
	fp.Framework = detectFramework(string(body), fp.Headers)
	fp.Languages = detectLanguages(string(body), fp.Headers)

	return fp
}

func (f *Fingerprinter) fingerprintTLS(ctx context.Context, ip string, port int) *TLSFingerprint {
	dialer := &net.Dialer{
		Timeout: f.timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", ip, port), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ip,
	})

	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()

	alpn := []string{}
	if state.NegotiatedProtocol != "" {
		alpn = []string{state.NegotiatedProtocol}
	}

	fp := &TLSFingerprint{
		Version:      getTLSVersionString(state.Version),
		CipherSuite:  tls.CipherSuiteName(state.CipherSuite),
		ALPN:         alpn,
		SNI:          state.ServerName,
		Certificates: make([]CertInfo, 0),
	}

	for _, cert := range state.PeerCertificates {
		certInfo := CertInfo{
			Subject:    cert.Subject.String(),
			Issuer:     cert.Issuer.String(),
			NotBefore:  cert.NotBefore,
			NotAfter:   cert.NotAfter,
			SANs:       cert.DNSNames,
			CommonName: cert.Subject.CommonName,
			Serial:     cert.SerialNumber.String(),
		}
		fp.Certificates = append(fp.Certificates, certInfo)
	}

	return fp
}

func (f *Fingerprinter) detectTechnologies(httpFP *HTTPFingerprint) []Technology {
	techs := make([]Technology, 0)

	if httpFP.Server != "" {
		if strings.Contains(strings.ToLower(httpFP.Server), "nginx") {
			techs = append(techs, Technology{
				Name:       "Nginx",
				Category:   "Web Server",
				Confidence: 100,
				Evidence:   []string{fmt.Sprintf("Server header: %s", httpFP.Server)},
			})
		}
		if strings.Contains(strings.ToLower(httpFP.Server), "apache") {
			techs = append(techs, Technology{
				Name:       "Apache",
				Category:   "Web Server",
				Confidence: 100,
				Evidence:   []string{fmt.Sprintf("Server header: %s", httpFP.Server)},
			})
		}
		if strings.Contains(strings.ToLower(httpFP.Server), "iis") {
			techs = append(techs, Technology{
				Name:       "IIS",
				Category:   "Web Server",
				Confidence: 100,
				Evidence:   []string{fmt.Sprintf("Server header: %s", httpFP.Server)},
			})
		}
	}

	if httpFP.CMS != "" {
		techs = append(techs, Technology{
			Name:       httpFP.CMS,
			Category:   "CMS",
			Confidence: 90,
			Evidence:   []string{"CMS detected from patterns"},
		})
	}

	if httpFP.Framework != "" {
		techs = append(techs, Technology{
			Name:       httpFP.Framework,
			Category:   "Framework",
			Confidence: 85,
			Evidence:   []string{"Framework detected from patterns"},
		})
	}

	for _, lang := range httpFP.Languages {
		techs = append(techs, Technology{
			Name:       lang,
			Category:   "Programming Language",
			Confidence: 70,
			Evidence:   []string{"Language detected from headers/content"},
		})
	}

	if xPoweredBy, ok := httpFP.Headers["X-Powered-By"]; ok {
		techs = append(techs, Technology{
			Name:       xPoweredBy,
			Category:   "Framework",
			Confidence: 95,
			Evidence:   []string{fmt.Sprintf("X-Powered-By: %s", xPoweredBy)},
		})
	}

	return techs
}

func extractTitle(html string) string {
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func detectCMS(body string, headers map[string]string) string {
	body = strings.ToLower(body)

	if strings.Contains(body, "wp-content") || strings.Contains(body, "wordpress") {
		return "WordPress"
	}
	if strings.Contains(body, "/sites/default/files") || strings.Contains(body, "drupal") {
		return "Drupal"
	}
	if strings.Contains(body, "/skin/frontend") || strings.Contains(body, "magento") {
		return "Magento"
	}
	if strings.Contains(body, "joomla") {
		return "Joomla"
	}
	if strings.Contains(body, "shopify") {
		return "Shopify"
	}

	return ""
}

func detectFramework(body string, headers map[string]string) string {
	body = strings.ToLower(body)

	if xPoweredBy, ok := headers["X-Powered-By"]; ok {
		return xPoweredBy
	}

	if strings.Contains(body, "react") || strings.Contains(body, "__react") {
		return "React"
	}
	if strings.Contains(body, "angular") || strings.Contains(body, "ng-") {
		return "Angular"
	}
	if strings.Contains(body, "vue") || strings.Contains(body, "v-if") {
		return "Vue.js"
	}
	if strings.Contains(body, "next") || strings.Contains(body, "_next") {
		return "Next.js"
	}
	if strings.Contains(body, "nuxt") {
		return "Nuxt.js"
	}

	return ""
}

func detectLanguages(body string, headers map[string]string) []string {
	langs := make([]string, 0)
	body = strings.ToLower(body)

	if xPoweredBy, ok := headers["X-Powered-By"]; ok {
		xPoweredBy = strings.ToLower(xPoweredBy)
		if strings.Contains(xPoweredBy, "php") {
			langs = append(langs, "PHP")
		}
		if strings.Contains(xPoweredBy, "asp") {
			langs = append(langs, "ASP.NET")
		}
	}

	if strings.Contains(body, ".php") {
		langs = append(langs, "PHP")
	}
	if strings.Contains(body, ".aspx") || strings.Contains(body, ".asp") {
		langs = append(langs, "ASP.NET")
	}
	if strings.Contains(body, ".jsp") {
		langs = append(langs, "Java")
	}
	if strings.Contains(body, ".py") || strings.Contains(headers["Server"], "Python") {
		langs = append(langs, "Python")
	}

	return unique(langs)
}

func isHTTPPort(port int) bool {
	httpPorts := []int{80, 8000, 8008, 8080, 8888, 3000, 5000}
	for _, p := range httpPorts {
		if port == p {
			return true
		}
	}
	return false
}

func isHTTPSPort(port int) bool {
	httpsPorts := []int{443, 8443, 8843, 9443}
	for _, p := range httpsPorts {
		if port == p {
			return true
		}
	}
	return false
}

func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func unique(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}
