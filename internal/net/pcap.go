package net

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type CaptureConfig struct {
	Interface   string
	PromiscMode bool
	SnapLen     int
	Timeout     time.Duration
	Filter      string
	OutputPath  string
	MaxSize     int64
	MaxDuration time.Duration
}

type PacketCapture struct {
	config  *CaptureConfig
	handle  *pcap.Handle
	writer  *pcapgo.Writer
	file    *os.File
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	packets chan gopacket.Packet
	errors  chan error
}

type PacketStats struct {
	TotalPackets   uint64
	TCPPackets     uint64
	UDPPackets     uint64
	ICMPPackets    uint64
	OtherPackets   uint64
	TotalBytes     uint64
	StartTime      time.Time
	LastPacketTime time.Time
}

func NewPacketCapture(config *CaptureConfig) (*PacketCapture, error) {
	if config.SnapLen == 0 {
		config.SnapLen = 65536
	}
	if config.Timeout == 0 {
		config.Timeout = pcap.BlockForever
	}
	if config.MaxSize == 0 {
		config.MaxSize = 100 * 1024 * 1024
	}
	if config.MaxDuration == 0 {
		config.MaxDuration = 1 * time.Hour
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &PacketCapture{
		config:  config,
		ctx:     ctx,
		cancel:  cancel,
		packets: make(chan gopacket.Packet, 1000),
		errors:  make(chan error, 100),
	}, nil
}

func (pc *PacketCapture) Start() error {
	handle, err := pcap.OpenLive(
		pc.config.Interface,
		int32(pc.config.SnapLen),
		pc.config.PromiscMode,
		pc.config.Timeout,
	)
	if err != nil {
		return fmt.Errorf("failed to open interface: %w", err)
	}

	if pc.config.Filter != "" {
		if err := handle.SetBPFFilter(pc.config.Filter); err != nil {
			handle.Close()
			return fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	pc.handle = handle

	if pc.config.OutputPath != "" {
		if err := pc.openOutputFile(); err != nil {
			handle.Close()
			return fmt.Errorf("failed to open output file: %w", err)
		}
	}

	go pc.captureLoop()

	return nil
}

func (pc *PacketCapture) openOutputFile() error {
	dir := filepath.Dir(pc.config.OutputPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	file, err := os.Create(pc.config.OutputPath)
	if err != nil {
		return err
	}

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(uint32(pc.config.SnapLen), layers.LinkTypeEthernet); err != nil {
		file.Close()
		return err
	}

	pc.file = file
	pc.writer = writer

	return nil
}

func (pc *PacketCapture) captureLoop() {
	packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())
	
	for {
		select {
		case <-pc.ctx.Done():
			return
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			if pc.writer != nil {
				pc.mu.Lock()
				err := pc.writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				pc.mu.Unlock()
				
				if err != nil {
					select {
					case pc.errors <- err:
					default:
					}
				}
			}

			select {
			case pc.packets <- packet:
			default:
			}
		}
	}
}

func (pc *PacketCapture) Packets() <-chan gopacket.Packet {
	return pc.packets
}

func (pc *PacketCapture) Errors() <-chan error {
	return pc.errors
}

func (pc *PacketCapture) Stop() error {
	pc.cancel()

	if pc.handle != nil {
		pc.handle.Close()
	}

	if pc.file != nil {
		pc.mu.Lock()
		defer pc.mu.Unlock()
		return pc.file.Close()
	}

	return nil
}

func (pc *PacketCapture) Stats() (*PacketStats, error) {
	if pc.handle == nil {
		return nil, fmt.Errorf("capture not started")
	}

	stats, err := pc.handle.Stats()
	if err != nil {
		return nil, err
	}

	return &PacketStats{
		TotalPackets: uint64(stats.PacketsReceived),
	}, nil
}

func ReadPcapFile(filename string) ([]gopacket.Packet, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file: %w", err)
	}
	defer handle.Close()

	packets := make([]gopacket.Packet, 0)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		packets = append(packets, packet)
	}

	return packets, nil
}

func AnalyzePackets(packets []gopacket.Packet) *PacketStats {
	stats := &PacketStats{
		StartTime: time.Now(),
	}

	for _, packet := range packets {
		stats.TotalPackets++
		stats.TotalBytes += uint64(len(packet.Data()))
		stats.LastPacketTime = packet.Metadata().Timestamp

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			stats.TCPPackets++
		}
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			stats.UDPPackets++
		}
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			stats.ICMPPackets++
		}
		
		if packet.Layer(layers.LayerTypeTCP) == nil &&
			packet.Layer(layers.LayerTypeUDP) == nil &&
			packet.Layer(layers.LayerTypeICMPv4) == nil {
			stats.OtherPackets++
		}
	}

	return stats
}

func GetInterfaces() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}

func ValidateInterface(name string) error {
	interfaces, err := GetInterfaces()
	if err != nil {
		return err
	}

	for _, iface := range interfaces {
		if iface.Name == name {
			return nil
		}
	}

	return fmt.Errorf("interface %s not found", name)
}
