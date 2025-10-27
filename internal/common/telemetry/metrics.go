package telemetry

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	mu sync.RWMutex

	ScanCount      atomic.Int64
	ActiveWorkers  atomic.Int64
	QueueDepth     atomic.Int64
	FailedTasks    atomic.Int64
	SuccessTasks   atomic.Int64
	
	latencySum   atomic.Int64
	latencyCount atomic.Int64

	customGauges   map[string]*atomic.Int64
	customCounters map[string]*atomic.Int64
}

var (
	globalMetrics *Metrics
	once          sync.Once
)

func Initialize() *Metrics {
	return &Metrics{
		customGauges:   make(map[string]*atomic.Int64),
		customCounters: make(map[string]*atomic.Int64),
	}
}

func Global() *Metrics {
	once.Do(func() {
		globalMetrics = Initialize()
	})
	return globalMetrics
}

func (m *Metrics) IncrementScanCount() {
	m.ScanCount.Add(1)
}

func (m *Metrics) IncrementActiveWorkers() {
	m.ActiveWorkers.Add(1)
}

func (m *Metrics) DecrementActiveWorkers() {
	m.ActiveWorkers.Add(-1)
}

func (m *Metrics) SetActiveWorkers(count int64) {
	m.ActiveWorkers.Store(count)
}

func (m *Metrics) IncrementQueueDepth() {
	m.QueueDepth.Add(1)
}

func (m *Metrics) DecrementQueueDepth() {
	m.QueueDepth.Add(-1)
}

func (m *Metrics) SetQueueDepth(depth int64) {
	m.QueueDepth.Store(depth)
}

func (m *Metrics) IncrementFailedTasks() {
	m.FailedTasks.Add(1)
}

func (m *Metrics) IncrementSuccessTasks() {
	m.SuccessTasks.Add(1)
}

func (m *Metrics) RecordLatency(duration time.Duration) {
	microseconds := duration.Microseconds()
	m.latencySum.Add(microseconds)
	m.latencyCount.Add(1)
}

func (m *Metrics) GetAverageLatency() time.Duration {
	count := m.latencyCount.Load()
	if count == 0 {
		return 0
	}
	sum := m.latencySum.Load()
	return time.Duration(sum/count) * time.Microsecond
}

func (m *Metrics) SetCustomGauge(name string, value int64) {
	m.mu.Lock()
	gauge, exists := m.customGauges[name]
	if !exists {
		gauge = &atomic.Int64{}
		m.customGauges[name] = gauge
	}
	m.mu.Unlock()
	gauge.Store(value)
}

func (m *Metrics) IncrementCustomCounter(name string) {
	m.mu.Lock()
	counter, exists := m.customCounters[name]
	if !exists {
		counter = &atomic.Int64{}
		m.customCounters[name] = counter
	}
	m.mu.Unlock()
	counter.Add(1)
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	
	fmt.Fprintf(w, "# HELP aegis_scan_count Total number of scans performed\n")
	fmt.Fprintf(w, "# TYPE aegis_scan_count counter\n")
	fmt.Fprintf(w, "aegis_scan_count %d\n", m.ScanCount.Load())
	
	fmt.Fprintf(w, "# HELP aegis_active_workers Current number of active workers\n")
	fmt.Fprintf(w, "# TYPE aegis_active_workers gauge\n")
	fmt.Fprintf(w, "aegis_active_workers %d\n", m.ActiveWorkers.Load())
	
	fmt.Fprintf(w, "# HELP aegis_queue_depth Current depth of the task queue\n")
	fmt.Fprintf(w, "# TYPE aegis_queue_depth gauge\n")
	fmt.Fprintf(w, "aegis_queue_depth %d\n", m.QueueDepth.Load())
	
	fmt.Fprintf(w, "# HELP aegis_failed_tasks Total number of failed tasks\n")
	fmt.Fprintf(w, "# TYPE aegis_failed_tasks counter\n")
	fmt.Fprintf(w, "aegis_failed_tasks %d\n", m.FailedTasks.Load())
	
	fmt.Fprintf(w, "# HELP aegis_success_tasks Total number of successful tasks\n")
	fmt.Fprintf(w, "# TYPE aegis_success_tasks counter\n")
	fmt.Fprintf(w, "aegis_success_tasks %d\n", m.SuccessTasks.Load())
	
	fmt.Fprintf(w, "# HELP aegis_avg_latency_microseconds Average task latency in microseconds\n")
	fmt.Fprintf(w, "# TYPE aegis_avg_latency_microseconds gauge\n")
	fmt.Fprintf(w, "aegis_avg_latency_microseconds %d\n", m.GetAverageLatency().Microseconds())
	
	m.mu.RLock()
	for name, gauge := range m.customGauges {
		fmt.Fprintf(w, "# HELP aegis_%s Custom gauge metric\n", name)
		fmt.Fprintf(w, "# TYPE aegis_%s gauge\n", name)
		fmt.Fprintf(w, "aegis_%s %d\n", name, gauge.Load())
	}
	for name, counter := range m.customCounters {
		fmt.Fprintf(w, "# HELP aegis_%s Custom counter metric\n", name)
		fmt.Fprintf(w, "# TYPE aegis_%s counter\n", name)
		fmt.Fprintf(w, "aegis_%s %d\n", name, counter.Load())
	}
	m.mu.RUnlock()
}

func (m *Metrics) StartMetricsServer(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	})
	
	return http.ListenAndServe(addr, mux)
}
