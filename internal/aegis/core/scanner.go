package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/common/store"
	"github.com/aegis-sentinel/aegis-suite/internal/common/telemetry"
	"github.com/google/uuid"
)

type ScanMode string

const (
	ScanModeQuick        ScanMode = "quick"
	ScanModeComprehensive ScanMode = "comprehensive"
	ScanModeIntensive    ScanMode = "intensive"
	ScanModeStealthy     ScanMode = "stealthy"
)

type ScanConfig struct {
	Mode        ScanMode
	Targets     []string
	Ports       []int
	Concurrency int
	RateLimit   int
	Timeout     time.Duration
	
	DiscoveryEnabled   bool
	PortScanEnabled    bool
	FingerprintEnabled bool
	VulnScanEnabled    bool
	
	DryRun bool
	Output string
	
	DiscoveryMethods []DiscoveryMethod
	BannerGrab       bool
	ServiceDetect    bool
	
	VulnDBPath string
}

type ScanJob struct {
	ID        string
	Config    *ScanConfig
	Status    string
	StartTime time.Time
	EndTime   time.Time
	Results   []*HostScanResult
	Errors    []error
}

type HostScanResult struct {
	Host            string
	IP              string
	MAC             string
	Hostname        string
	Alive           bool
	RTT             time.Duration
	Ports           []*PortResult
	Fingerprint     *Fingerprint
	Vulnerabilities []*ServiceVulnerability
	ScanTime        time.Duration
	Timestamp       time.Time
}

type Scanner struct {
	config        *ScanConfig
	logger        *logging.Logger
	metrics       *telemetry.Metrics
	store         *store.Store
	discovery     *Discovery
	portScanner   *PortScanner
	fingerprinter *Fingerprinter
	vulnMapper    *VulnMapper
	
	mu            sync.RWMutex
	activeJobs    map[string]*ScanJob
	
	workerSem     chan struct{}
	rateLimiter   chan struct{}
}

func NewScanner(config *ScanConfig, logger *logging.Logger, metrics *telemetry.Metrics, st *store.Store) (*Scanner, error) {
	if config.Concurrency == 0 {
		config.Concurrency = 100
	}
	if config.Timeout == 0 {
		config.Timeout = 300 * time.Second
	}
	
	discoveryConfig := &DiscoveryConfig{
		Timeout:     config.Timeout / 10,
		Retries:     2,
		Methods:     config.DiscoveryMethods,
		Concurrency: config.Concurrency,
	}
	
	portScanConfig := &PortScanConfig{
		Ports:         config.Ports,
		Timeout:       config.Timeout / 10,
		Mode:          PortScanModeConnect,
		Concurrency:   config.Concurrency / 2,
		RateLimit:     config.RateLimit,
		BannerGrab:    config.BannerGrab,
		ServiceDetect: config.ServiceDetect,
	}
	
	vulnMapper, err := NewVulnMapper(config.VulnDBPath)
	if err != nil {
		logger.Warning("Failed to load vulnerability database", logging.WithError(err))
	}
	
	workerSem := make(chan struct{}, config.Concurrency)
	
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
					}
				}
			}
		}()
	}
	
	return &Scanner{
		config:        config,
		logger:        logger,
		metrics:       metrics,
		store:         st,
		discovery:     NewDiscovery(discoveryConfig),
		portScanner:   NewPortScanner(portScanConfig),
		fingerprinter: NewFingerprinter(config.Timeout / 10),
		vulnMapper:    vulnMapper,
		activeJobs:    make(map[string]*ScanJob),
		workerSem:     workerSem,
		rateLimiter:   rateLimiter,
	}, nil
}

func (s *Scanner) Scan(ctx context.Context) (*ScanJob, error) {
	job := &ScanJob{
		ID:        uuid.New().String(),
		Config:    s.config,
		Status:    "running",
		StartTime: time.Now(),
		Results:   make([]*HostScanResult, 0),
		Errors:    make([]error, 0),
	}
	
	s.mu.Lock()
	s.activeJobs[job.ID] = job
	s.mu.Unlock()
	
	s.logger.Info("Starting scan job",
		logging.WithAction("scan_start"),
		logging.WithExtra("job_id", job.ID),
		logging.WithExtra("targets", len(s.config.Targets)),
	)
	
	if s.config.DryRun {
		s.logger.Info("Dry run mode - no actual scanning will be performed")
		job.Status = "completed"
		job.EndTime = time.Now()
		return job, nil
	}
	
	targets := s.config.Targets
	
	if s.config.DiscoveryEnabled {
		discoveredHosts, err := s.discoverHosts(ctx, targets)
		if err != nil {
			s.logger.Error("Discovery phase failed", logging.WithError(err))
			return nil, err
		}
		s.logger.Info(fmt.Sprintf("Discovery completed: %d hosts found", len(discoveredHosts)))
		
		targets = make([]string, 0)
		for _, host := range discoveredHosts {
			if host.Alive {
				targets = append(targets, host.IP)
			}
		}
	}
	
	results, err := s.scanHosts(ctx, targets)
	if err != nil {
		s.logger.Error("Scan failed", logging.WithError(err))
		job.Status = "failed"
		job.Errors = append(job.Errors, err)
	} else {
		job.Status = "completed"
	}
	
	job.Results = results
	job.EndTime = time.Now()
	
	if err := s.persistResults(job); err != nil {
		s.logger.Error("Failed to persist results", logging.WithError(err))
	}
	
	s.logger.Info("Scan job completed",
		logging.WithAction("scan_complete"),
		logging.WithExtra("job_id", job.ID),
		logging.WithExtra("duration", job.EndTime.Sub(job.StartTime).String()),
		logging.WithExtra("hosts_scanned", len(job.Results)),
	)
	
	return job, nil
}

func (s *Scanner) discoverHosts(ctx context.Context, targets []string) ([]*DiscoveryResult, error) {
	s.logger.Info("Starting host discovery", logging.WithExtra("targets", len(targets)))
	start := time.Now()
	
	results, err := s.discovery.DiscoverHosts(ctx, targets)
	
	s.metrics.RecordLatency(time.Since(start))
	s.metrics.IncrementCustomCounter("discovery_runs")
	s.metrics.SetCustomGauge("discovered_hosts", int64(len(results)))
	
	return results, err
}

func (s *Scanner) scanHosts(ctx context.Context, hosts []string) ([]*HostScanResult, error) {
	results := make([]*HostScanResult, 0)
	resultsChan := make(chan *HostScanResult, len(hosts))
	errorsChan := make(chan error, len(hosts))
	
	var wg sync.WaitGroup
	
	s.metrics.SetQueueDepth(int64(len(hosts)))
	
	for _, host := range hosts {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}
		
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			
			if s.rateLimiter != nil {
				<-s.rateLimiter
			}
			
			s.workerSem <- struct{}{}
			defer func() { <-s.workerSem }()
			
			s.metrics.IncrementActiveWorkers()
			s.metrics.DecrementQueueDepth()
			defer s.metrics.DecrementActiveWorkers()
			
			result, err := s.scanHost(ctx, h)
			if err != nil {
				errorsChan <- err
				s.metrics.IncrementFailedTasks()
			} else {
				resultsChan <- result
				s.metrics.IncrementSuccessTasks()
			}
			
			s.metrics.IncrementScanCount()
		}(host)
	}
	
	go func() {
		wg.Wait()
		close(resultsChan)
		close(errorsChan)
	}()
	
	for result := range resultsChan {
		results = append(results, result)
	}
	
	return results, nil
}

func (s *Scanner) scanHost(ctx context.Context, host string) (*HostScanResult, error) {
	start := time.Now()
	
	result := &HostScanResult{
		Host:      host,
		IP:        host,
		Alive:     true,
		Timestamp: time.Now(),
	}
	
	s.logger.Debug(fmt.Sprintf("Scanning host: %s", host), logging.WithTarget(host))
	
	if s.config.PortScanEnabled {
		ports, err := s.portScanner.ScanHost(ctx, host)
		if err != nil {
			s.logger.Warning(fmt.Sprintf("Port scan failed for %s", host),
				logging.WithTarget(host),
				logging.WithError(err),
			)
		} else {
			result.Ports = ports
			s.logger.Debug(fmt.Sprintf("Found %d open ports on %s", len(ports), host),
				logging.WithTarget(host),
			)
		}
	}
	
	if s.config.FingerprintEnabled && len(result.Ports) > 0 {
		fingerprint, err := s.fingerprinter.FingerprintHost(ctx, host, result.Ports)
		if err != nil {
			s.logger.Warning(fmt.Sprintf("Fingerprinting failed for %s", host),
				logging.WithTarget(host),
				logging.WithError(err),
			)
		} else {
			result.Fingerprint = fingerprint
		}
	}
	
	if s.config.VulnScanEnabled && s.vulnMapper != nil {
		vulns, err := s.vulnMapper.MapVulnerabilities(ctx, result.Ports, result.Fingerprint)
		if err != nil {
			s.logger.Warning(fmt.Sprintf("Vulnerability mapping failed for %s", host),
				logging.WithTarget(host),
				logging.WithError(err),
			)
		} else {
			result.Vulnerabilities = vulns
			if len(vulns) > 0 {
				s.logger.Info(fmt.Sprintf("Found %d vulnerabilities on %s", len(vulns), host),
					logging.WithTarget(host),
					logging.WithExtra("vuln_count", len(vulns)),
				)
			}
		}
	}
	
	result.ScanTime = time.Since(start)
	s.metrics.RecordLatency(result.ScanTime)
	
	return result, nil
}

func (s *Scanner) persistResults(job *ScanJob) error {
	scanResult := &store.ScanResult{
		ID:        job.ID,
		Timestamp: job.StartTime,
		Target:    fmt.Sprintf("%d hosts", len(job.Config.Targets)),
		Status:    job.Status,
		Duration:  job.EndTime.Sub(job.StartTime),
		Findings:  make([]store.Finding, 0),
		Metadata: map[string]interface{}{
			"mode":        string(job.Config.Mode),
			"hosts_count": len(job.Results),
			"end_time":    job.EndTime,
		},
	}
	
	for _, hostResult := range job.Results {
		hostInfo := &store.HostInfo{
			IP:        hostResult.IP,
			Hostname:  hostResult.Hostname,
			MAC:       hostResult.MAC,
			Ports:     make([]store.PortInfo, 0),
			LastSeen:  hostResult.Timestamp,
			FirstSeen: hostResult.Timestamp,
			Metadata:  make(map[string]interface{}),
		}
		
		if hostResult.Fingerprint != nil && hostResult.Fingerprint.OS != nil {
			hostInfo.OS = hostResult.Fingerprint.OS.Name
			hostInfo.OSVersion = hostResult.Fingerprint.OS.Version
		}
		
		for _, port := range hostResult.Ports {
			portInfo := store.PortInfo{
				Port:      port.Port,
				Protocol:  port.Protocol,
				State:     string(port.State),
				Service:   port.Service,
				Version:   port.Version,
				Banner:    port.Banner,
				Timestamp: port.Timestamp,
			}
			hostInfo.Ports = append(hostInfo.Ports, portInfo)
		}
		
		if err := s.store.SaveHostInfo(hostInfo); err != nil {
			s.logger.Error("Failed to save host info", logging.WithError(err))
		}
		
		for _, vulnService := range hostResult.Vulnerabilities {
			for _, vuln := range vulnService.Vulnerabilities {
				finding := store.Finding{
					Type:        "vulnerability",
					Severity:    vuln.Severity,
					Target:      hostResult.IP,
					Service:     vulnService.Service,
					Version:     vulnService.Version,
					Description: vuln.Description,
					CVE:         []string{vuln.CVE},
					MITRE:       vuln.MITRE,
					Timestamp:   hostResult.Timestamp,
					Extra: map[string]interface{}{
						"cvss":       vuln.CVSS,
						"published":  vuln.Published,
						"references": vuln.References,
					},
				}
				scanResult.Findings = append(scanResult.Findings, finding)
				
				if err := s.store.SaveFinding(job.ID, &finding); err != nil {
					s.logger.Error("Failed to save finding", logging.WithError(err))
				}
			}
		}
	}
	
	return s.store.SaveScanResult(scanResult)
}

func (s *Scanner) GetJob(jobID string) (*ScanJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if job, ok := s.activeJobs[jobID]; ok {
		return job, nil
	}
	
	return nil, fmt.Errorf("job not found: %s", jobID)
}

func (s *Scanner) GetActiveJobs() []*ScanJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	jobs := make([]*ScanJob, 0, len(s.activeJobs))
	for _, job := range s.activeJobs {
		jobs = append(jobs, job)
	}
	
	return jobs
}

func DefaultScanConfig() *ScanConfig {
	return &ScanConfig{
		Mode:               ScanModeQuick,
		Ports:              GetCommonPorts(),
		Concurrency:        100,
		RateLimit:          1000,
		Timeout:            300 * time.Second,
		DiscoveryEnabled:   true,
		PortScanEnabled:    true,
		FingerprintEnabled: true,
		VulnScanEnabled:    true,
		DiscoveryMethods:   []DiscoveryMethod{DiscoveryICMP, DiscoveryTCPSYN},
		BannerGrab:         true,
		ServiceDetect:      true,
		DryRun:             false,
	}
}

func ComprehensiveScanConfig() *ScanConfig {
	config := DefaultScanConfig()
	config.Mode = ScanModeComprehensive
	config.Ports = GetTop100Ports()
	config.Concurrency = 500
	config.RateLimit = 5000
	return config
}

func IntensiveScanConfig() *ScanConfig {
	config := DefaultScanConfig()
	config.Mode = ScanModeIntensive
	config.Ports = GetTop1000Ports()
	config.Concurrency = 2000
	config.RateLimit = 10000
	return config
}
