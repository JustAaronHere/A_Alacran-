package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/aegis-sentinel/aegis-suite/internal/common/telemetry"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type CaptureMode string

const (
	CaptureModeSpan   CaptureMode = "span"
	CaptureModeInline CaptureMode = "inline"
	CaptureModeLive   CaptureMode = "live"
	CaptureModeOffline CaptureMode = "offline"
)

type ListenerConfig struct {
	Interface      string
	Mode           CaptureMode
	PromiscMode    bool
	SnapLen        int
	Filter         string
	
	OutputPath     string
	MaxPcapSize    int64
	RotateInterval time.Duration
	Encrypted      bool
	
	BufferSize     int
	Workers        int
	
	PcapFile       string
}

type PcapListener struct {
	config     *ListenerConfig
	logger     *logging.Logger
	metrics    *telemetry.Metrics
	
	handle     *pcap.Handle
	parser     *PacketParser
	
	pcapWriter *pcapgo.Writer
	pcapFile   *os.File
	pcapMu     sync.Mutex
	
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	
	eventChan  chan *NetworkEvent
	deviceChan chan *DeviceInfo
	
	stats      *ListenerStats
	statsMu    sync.RWMutex
}

type ListenerStats struct {
	TotalPackets    uint64
	ProcessedEvents uint64
	DroppedPackets  uint64
	BytesProcessed  uint64
	StartTime       time.Time
	LastPacketTime  time.Time
	ErrorCount      uint64
}

func NewPcapListener(config *ListenerConfig, logger *logging.Logger, metrics *telemetry.Metrics) (*PcapListener, error) {
	if config.SnapLen == 0 {
		config.SnapLen = 65536
	}
	if config.MaxPcapSize == 0 {
		config.MaxPcapSize = 100 * 1024 * 1024
	}
	if config.RotateInterval == 0 {
		config.RotateInterval = 1 * time.Hour
	}
	if config.BufferSize == 0 {
		config.BufferSize = 10000
	}
	if config.Workers == 0 {
		config.Workers = 4
	}

	ctx, cancel := context.WithCancel(context.Background())

	listener := &PcapListener{
		config:     config,
		logger:     logger,
		metrics:    metrics,
		ctx:        ctx,
		cancel:     cancel,
		eventChan:  make(chan *NetworkEvent, config.BufferSize),
		deviceChan: make(chan *DeviceInfo, config.BufferSize/10),
		stats: &ListenerStats{
			StartTime: time.Now(),
		},
	}

	listener.parser = NewPacketParser(logger)

	return listener, nil
}

func (pl *PcapListener) Start(ctx context.Context) error {
	pl.logger.Info("Starting packet capture listener",
		logging.WithExtra("interface", pl.config.Interface),
		logging.WithExtra("mode", pl.config.Mode),
	)

	var err error
	if pl.config.Mode == CaptureModeOffline {
		pl.handle, err = pcap.OpenOffline(pl.config.PcapFile)
	} else {
		pl.handle, err = pcap.OpenLive(
			pl.config.Interface,
			int32(pl.config.SnapLen),
			pl.config.PromiscMode,
			pcap.BlockForever,
		)
	}

	if err != nil {
		return fmt.Errorf("failed to open capture: %w", err)
	}

	if pl.config.Filter != "" {
		if err := pl.handle.SetBPFFilter(pl.config.Filter); err != nil {
			pl.handle.Close()
			return fmt.Errorf("failed to set BPF filter: %w", err)
		}
		pl.logger.Info("Applied BPF filter", logging.WithExtra("filter", pl.config.Filter))
	}

	if pl.config.OutputPath != "" {
		if err := pl.openPcapOutput(); err != nil {
			pl.handle.Close()
			return fmt.Errorf("failed to open pcap output: %w", err)
		}
	}

	pl.wg.Add(1)
	go pl.captureLoop(ctx)

	if pl.config.RotateInterval > 0 && pl.config.OutputPath != "" {
		pl.wg.Add(1)
		go pl.rotationLoop(ctx)
	}

	for i := 0; i < pl.config.Workers; i++ {
		pl.wg.Add(1)
		go pl.processingWorker(ctx, i)
	}

	pl.logger.Info("Packet capture listener started",
		logging.WithExtra("workers", pl.config.Workers),
	)

	return nil
}

func (pl *PcapListener) openPcapOutput() error {
	dir := filepath.Dir(pl.config.OutputPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(dir, fmt.Sprintf("capture-%s.pcap", timestamp))

	file, err := os.Create(filename)
	if err != nil {
		return err
	}

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(uint32(pl.config.SnapLen), layers.LinkTypeEthernet); err != nil {
		file.Close()
		return err
	}

	pl.pcapMu.Lock()
	if pl.pcapFile != nil {
		pl.pcapFile.Close()
	}
	pl.pcapFile = file
	pl.pcapWriter = writer
	pl.pcapMu.Unlock()

	pl.logger.Info("Opened PCAP output file", logging.WithExtra("filename", filename))

	return nil
}

func (pl *PcapListener) captureLoop(ctx context.Context) {
	defer pl.wg.Done()

	packetSource := gopacket.NewPacketSource(pl.handle, pl.handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			pl.logger.Info("Capture loop stopping")
			return
		case packet, ok := <-packets:
			if !ok {
				pl.logger.Info("Packet source closed")
				return
			}

			pl.handlePacket(packet)
		}
	}
}

func (pl *PcapListener) handlePacket(packet gopacket.Packet) {
	pl.statsMu.Lock()
	pl.stats.TotalPackets++
	pl.stats.BytesProcessed += uint64(len(packet.Data()))
	pl.stats.LastPacketTime = packet.Metadata().Timestamp
	pl.statsMu.Unlock()

	pl.metrics.IncrementCustomCounter("gatehound_packets_captured")

	if pl.pcapWriter != nil {
		pl.pcapMu.Lock()
		err := pl.pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		pl.pcapMu.Unlock()

		if err != nil {
			pl.statsMu.Lock()
			pl.stats.ErrorCount++
			pl.statsMu.Unlock()
			pl.logger.Warning("Failed to write packet to pcap", logging.WithError(err))
		}
	}

	events := pl.parser.ParsePacket(packet)
	for _, event := range events {
		select {
		case pl.eventChan <- event:
			pl.statsMu.Lock()
			pl.stats.ProcessedEvents++
			pl.statsMu.Unlock()
			pl.metrics.IncrementCustomCounter("gatehound_events_processed")
		default:
			pl.statsMu.Lock()
			pl.stats.DroppedPackets++
			pl.statsMu.Unlock()
			pl.metrics.IncrementCustomCounter("gatehound_events_dropped")
		}
	}
}

func (pl *PcapListener) processingWorker(ctx context.Context, id int) {
	defer pl.wg.Done()

	pl.logger.Debug(fmt.Sprintf("Processing worker %d started", id))

	for {
		select {
		case <-ctx.Done():
			return
		case event := <-pl.eventChan:
			pl.processEvent(event)
		}
	}
}

func (pl *PcapListener) processEvent(event *NetworkEvent) {
	pl.logger.Debug("Processing network event",
		logging.WithExtra("type", event.Type),
		logging.WithExtra("src_ip", event.SrcIP),
		logging.WithExtra("dst_ip", event.DstIP),
	)
}

func (pl *PcapListener) rotationLoop(ctx context.Context) {
	defer pl.wg.Done()

	ticker := time.NewTicker(pl.config.RotateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := pl.rotatePcap(); err != nil {
				pl.logger.Error("Failed to rotate pcap file", logging.WithError(err))
			}
		}
	}
}

func (pl *PcapListener) rotatePcap() error {
	pl.logger.Info("Rotating PCAP file")

	pl.pcapMu.Lock()
	defer pl.pcapMu.Unlock()

	if pl.pcapFile != nil {
		if err := pl.pcapFile.Close(); err != nil {
			return err
		}
	}

	pl.pcapMu.Unlock()
	err := pl.openPcapOutput()
	pl.pcapMu.Lock()

	return err
}

func (pl *PcapListener) Events() <-chan *NetworkEvent {
	return pl.eventChan
}

func (pl *PcapListener) Devices() <-chan *DeviceInfo {
	return pl.deviceChan
}

func (pl *PcapListener) Stats() *ListenerStats {
	pl.statsMu.RLock()
	defer pl.statsMu.RUnlock()

	statsCopy := *pl.stats
	return &statsCopy
}

func (pl *PcapListener) Stop() error {
	pl.logger.Info("Stopping packet capture listener")

	pl.cancel()
	pl.wg.Wait()

	if pl.handle != nil {
		pl.handle.Close()
	}

	pl.pcapMu.Lock()
	if pl.pcapFile != nil {
		pl.pcapFile.Close()
	}
	pl.pcapMu.Unlock()

	close(pl.eventChan)
	close(pl.deviceChan)

	stats := pl.Stats()
	pl.logger.Info("Packet capture listener stopped",
		logging.WithExtra("total_packets", stats.TotalPackets),
		logging.WithExtra("processed_events", stats.ProcessedEvents),
		logging.WithExtra("duration", time.Since(stats.StartTime).String()),
	)

	return nil
}

func DefaultListenerConfig() *ListenerConfig {
	return &ListenerConfig{
		Interface:      "eth0",
		Mode:           CaptureModeLive,
		PromiscMode:    true,
		SnapLen:        65536,
		Filter:         "",
		OutputPath:     "./data/pcaps",
		MaxPcapSize:    100 * 1024 * 1024,
		RotateInterval: 1 * time.Hour,
		Encrypted:      true,
		BufferSize:     10000,
		Workers:        4,
	}
}
