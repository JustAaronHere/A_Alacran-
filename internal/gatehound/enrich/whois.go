package enrich

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type WhoisInfo struct {
	IP           net.IP                 `json:"ip"`
	ASN          string                 `json:"asn,omitempty"`
	CIDR         string                 `json:"cidr,omitempty"`
	Organization string                 `json:"organization,omitempty"`
	NetName      string                 `json:"net_name,omitempty"`
	NetRange     string                 `json:"net_range,omitempty"`
	Country      string                 `json:"country,omitempty"`
	Created      time.Time              `json:"created,omitempty"`
	Updated      time.Time              `json:"updated,omitempty"`
	Raw          string                 `json:"raw,omitempty"`
	Extra        map[string]interface{} `json:"extra,omitempty"`
}

type WhoisEnricher struct {
	cache      map[string]*WhoisInfo
	cacheTTL   time.Duration
	mu         sync.RWMutex
	rateLimit  chan struct{}
}

func NewWhoisEnricher(cacheTTL time.Duration, rateLimit int) *WhoisEnricher {
	var rateLimitChan chan struct{}
	if rateLimit > 0 {
		rateLimitChan = make(chan struct{}, rateLimit)
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for range ticker.C {
				for i := 0; i < rateLimit; i++ {
					select {
					case rateLimitChan <- struct{}{}:
					default:
					}
				}
			}
		}()
	}

	return &WhoisEnricher{
		cache:     make(map[string]*WhoisInfo),
		cacheTTL:  cacheTTL,
		rateLimit: rateLimitChan,
	}
}

func (we *WhoisEnricher) Lookup(ip net.IP) (*WhoisInfo, error) {
	if ip == nil {
		return nil, fmt.Errorf("nil IP address")
	}

	if isPrivateIP(ip) {
		return &WhoisInfo{
			IP:           ip,
			Organization: "Private Network",
			NetName:      "RFC1918",
		}, nil
	}

	cacheKey := ip.String()

	we.mu.RLock()
	if cached, ok := we.cache[cacheKey]; ok {
		we.mu.RUnlock()
		return cached, nil
	}
	we.mu.RUnlock()

	if we.rateLimit != nil {
		<-we.rateLimit
	}

	info, err := we.queryWhois(ip)
	if err != nil {
		return nil, err
	}

	we.mu.Lock()
	we.cache[cacheKey] = info
	we.mu.Unlock()

	return info, nil
}

func (we *WhoisEnricher) queryWhois(ip net.IP) (*WhoisInfo, error) {
	info := &WhoisInfo{
		IP:    ip,
		Extra: make(map[string]interface{}),
	}

	server := we.determineWhoisServer(ip)
	if server == "" {
		return info, fmt.Errorf("no WHOIS server found for IP")
	}

	conn, err := net.DialTimeout("tcp", server+":43", 10*time.Second)
	if err != nil {
		return info, fmt.Errorf("failed to connect to WHOIS server: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	query := ip.String() + "\r\n"
	if _, err := conn.Write([]byte(query)); err != nil {
		return info, fmt.Errorf("failed to send WHOIS query: %w", err)
	}

	var response strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		response.WriteString(line)
		response.WriteString("\n")

		we.parseWhoisLine(line, info)
	}

	info.Raw = response.String()

	return info, nil
}

func (we *WhoisEnricher) determineWhoisServer(ip net.IP) string {
	if ip.To4() != nil {
		firstOctet := ip.To4()[0]
		switch {
		case firstOctet >= 1 && firstOctet <= 42:
			return "whois.arin.net"
		case firstOctet >= 43 && firstOctet <= 103:
			return "whois.apnic.net"
		case firstOctet >= 104 && firstOctet <= 200:
			return "whois.arin.net"
		case firstOctet >= 201 && firstOctet <= 223:
			return "whois.lacnic.net"
		}
	}

	return "whois.arin.net"
}

func (we *WhoisEnricher) parseWhoisLine(line string, info *WhoisInfo) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "%") {
		return
	}

	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return
	}

	key := strings.ToLower(strings.TrimSpace(parts[0]))
	value := strings.TrimSpace(parts[1])

	switch key {
	case "originasn", "originas", "asn":
		info.ASN = value
	case "cidr":
		info.CIDR = value
	case "organization", "org-name", "orgname":
		if info.Organization == "" {
			info.Organization = value
		}
	case "netname", "net-name":
		info.NetName = value
	case "netrange", "inetnum":
		info.NetRange = value
	case "country":
		info.Country = value
	}
}

func (we *WhoisEnricher) ClearCache() {
	we.mu.Lock()
	defer we.mu.Unlock()
	we.cache = make(map[string]*WhoisInfo)
}

func (we *WhoisEnricher) CacheSize() int {
	we.mu.RLock()
	defer we.mu.RUnlock()
	return len(we.cache)
}
