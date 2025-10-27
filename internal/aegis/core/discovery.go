package core

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type DiscoveryMethod string

const (
	DiscoveryICMP   DiscoveryMethod = "icmp"
	DiscoveryTCPSYN DiscoveryMethod = "tcp-syn"
	DiscoveryUDP    DiscoveryMethod = "udp"
	DiscoveryARP    DiscoveryMethod = "arp"
	DiscoveryHybrid DiscoveryMethod = "hybrid"
)

type DiscoveryConfig struct {
	Timeout     time.Duration
	Retries     int
	Methods     []DiscoveryMethod
	PingPorts   []int
	Concurrency int
}

type DiscoveryResult struct {
	IP       string
	MAC      string
	Hostname string
	RTT      time.Duration
	Method   DiscoveryMethod
	Alive    bool
}

type Discovery struct {
	config *DiscoveryConfig
	mu     sync.RWMutex
}

func NewDiscovery(config *DiscoveryConfig) *Discovery {
	if config.Timeout == 0 {
		config.Timeout = 2 * time.Second
	}
	if config.Retries == 0 {
		config.Retries = 1
	}
	if len(config.Methods) == 0 {
		config.Methods = []DiscoveryMethod{DiscoveryICMP}
	}
	if len(config.PingPorts) == 0 {
		config.PingPorts = []int{80, 443, 22}
	}
	if config.Concurrency == 0 {
		config.Concurrency = 100
	}

	return &Discovery{
		config: config,
	}
}

func (d *Discovery) DiscoverHosts(ctx context.Context, targets []string) ([]*DiscoveryResult, error) {
	results := make([]*DiscoveryResult, 0)
	resultsChan := make(chan *DiscoveryResult, len(targets))
	sem := make(chan struct{}, d.config.Concurrency)
	var wg sync.WaitGroup

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := d.discoverHost(ctx, t)
			if result != nil {
				resultsChan <- result
			}
		}(target)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		results = append(results, result)
	}

	return results, nil
}

func (d *Discovery) discoverHost(ctx context.Context, target string) *DiscoveryResult {
	ip := net.ParseIP(target)
	if ip == nil {
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			return nil
		}
		ip = ips[0]
	}

	for _, method := range d.config.Methods {
		var result *DiscoveryResult
		var err error

		switch method {
		case DiscoveryICMP:
			result, err = d.icmpPing(ctx, ip.String())
		case DiscoveryTCPSYN:
			result, err = d.tcpPing(ctx, ip.String())
		case DiscoveryUDP:
			result, err = d.udpPing(ctx, ip.String())
		case DiscoveryHybrid:
			result, err = d.hybridDiscovery(ctx, ip.String())
		}

		if err == nil && result != nil && result.Alive {
			hostname, _ := d.reverseLookup(ip.String())
			result.Hostname = hostname
			return result
		}
	}

	return nil
}

func (d *Discovery) icmpPing(ctx context.Context, ip string) (*DiscoveryResult, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return d.tcpPing(ctx, ip)
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("AEGIS"),
		},
	}

	data, err := msg.Marshal(nil)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	deadline := time.Now().Add(d.config.Timeout)
	conn.SetDeadline(deadline)

	_, err = conn.WriteTo(data, &net.IPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		return nil, err
	}

	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	rtt := time.Since(start)
	
	if err != nil {
		return nil, err
	}

	parsedMsg, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return nil, err
	}

	if parsedMsg.Type == ipv4.ICMPTypeEchoReply {
		return &DiscoveryResult{
			IP:     ip,
			RTT:    rtt,
			Method: DiscoveryICMP,
			Alive:  true,
		}, nil
	}

	return nil, fmt.Errorf("no echo reply")
}

func (d *Discovery) tcpPing(ctx context.Context, ip string) (*DiscoveryResult, error) {
	for _, port := range d.config.PingPorts {
		addr := fmt.Sprintf("%s:%d", ip, port)
		start := time.Now()
		
		conn, err := net.DialTimeout("tcp", addr, d.config.Timeout)
		rtt := time.Since(start)
		
		if err == nil {
			conn.Close()
			return &DiscoveryResult{
				IP:     ip,
				RTT:    rtt,
				Method: DiscoveryTCPSYN,
				Alive:  true,
			}, nil
		}

		if netErr, ok := err.(net.Error); ok && !netErr.Timeout() {
			return &DiscoveryResult{
				IP:     ip,
				RTT:    rtt,
				Method: DiscoveryTCPSYN,
				Alive:  true,
			}, nil
		}
	}

	return nil, fmt.Errorf("no response on TCP ports")
}

func (d *Discovery) udpPing(ctx context.Context, ip string) (*DiscoveryResult, error) {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:53", ip), d.config.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	start := time.Now()
	_, err = conn.Write([]byte("AEGIS"))
	
	if err == nil {
		return &DiscoveryResult{
			IP:     ip,
			RTT:    time.Since(start),
			Method: DiscoveryUDP,
			Alive:  true,
		}, nil
	}

	return nil, err
}

func (d *Discovery) hybridDiscovery(ctx context.Context, ip string) (*DiscoveryResult, error) {
	result, err := d.icmpPing(ctx, ip)
	if err == nil && result != nil {
		return result, nil
	}

	result, err = d.tcpPing(ctx, ip)
	if err == nil && result != nil {
		return result, nil
	}

	return d.udpPing(ctx, ip)
}

func (d *Discovery) reverseLookup(ip string) (string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return "", err
	}
	return names[0], nil
}

func ParseCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ParseIPRange(start, end string) ([]string, error) {
	startIP := net.ParseIP(start)
	endIP := net.ParseIP(end)
	
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP addresses")
	}

	var ips []string
	for ip := startIP; !ip.Equal(endIP); inc(ip) {
		ips = append(ips, ip.String())
	}
	ips = append(ips, endIP.String())

	return ips, nil
}
