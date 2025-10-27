package monitor

import (
	"encoding/binary"
	"strings"

	"github.com/aegis-sentinel/aegis-suite/internal/common/logging"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

type PacketParser struct {
	logger *logging.Logger
}

func NewPacketParser(logger *logging.Logger) *PacketParser {
	return &PacketParser{
		logger: logger,
	}
}

func (pp *PacketParser) ParsePacket(packet gopacket.Packet) []*NetworkEvent {
	events := make([]*NetworkEvent, 0)

	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		if event := pp.parseARP(packet, arpLayer.(*layers.ARP)); event != nil {
			events = append(events, event)
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)

		if udp.DstPort == 67 || udp.SrcPort == 67 {
			if event := pp.parseDHCP(packet); event != nil {
				events = append(events, event)
			}
		}

		if udp.DstPort == 53 || udp.SrcPort == 53 {
			if event := pp.parseDNS(packet); event != nil {
				events = append(events, event)
			}
		}

		if udp.DstPort == 5353 || udp.SrcPort == 5353 {
			if event := pp.parseMDNS(packet); event != nil {
				events = append(events, event)
			}
		}
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)

		if tcp.SYN && !tcp.ACK {
			if event := pp.parseTCPSYN(packet, tcp); event != nil {
				events = append(events, event)
			}
		}

		if tcp.DstPort == 80 || tcp.SrcPort == 80 || tcp.DstPort == 8080 || tcp.SrcPort == 8080 {
			if event := pp.parseHTTP(packet, tcp); event != nil {
				events = append(events, event)
			}
		}

		if tcp.DstPort == 443 || tcp.SrcPort == 443 {
			if event := pp.parseTLS(packet, tcp); event != nil {
				events = append(events, event)
			}
		}
	}

	return events
}

func (pp *PacketParser) parseARP(packet gopacket.Packet, arp *layers.ARP) *NetworkEvent {
	event := &NetworkEvent{
		ID:        uuid.New().String(),
		Type:      EventTypeARP,
		Timestamp: packet.Metadata().Timestamp,
		SrcMAC:    arp.SourceHwAddress,
		SrcIP:     arp.SourceProtAddress,
		DstMAC:    arp.DstHwAddress,
		DstIP:     arp.DstProtAddress,
		Protocol:  "ARP",
		Extra:     make(map[string]interface{}),
	}

	event.Extra["operation"] = arp.Operation
	event.Extra["is_gratuitous"] = string(arp.SourceProtAddress) == string(arp.DstProtAddress)

	return event
}

func (pp *PacketParser) parseDHCP(packet gopacket.Packet) *NetworkEvent {
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer == nil {
		return nil
	}

	dhcp := dhcpLayer.(*layers.DHCPv4)

	event := &NetworkEvent{
		ID:        uuid.New().String(),
		Type:      EventTypeDHCP,
		Timestamp: packet.Metadata().Timestamp,
		SrcMAC:    dhcp.ClientHWAddr,
		Protocol:  "DHCP",
		Extra:     make(map[string]interface{}),
	}

	for _, opt := range dhcp.Options {
		switch opt.Type {
		case layers.DHCPOptHostname:
			event.Hostname = string(opt.Data)
		case layers.DHCPOptRequestIP:
			if len(opt.Data) == 4 {
				event.Extra["requested_ip"] = opt.Data
			}
		case layers.DHCPOptClassID:
			event.Extra["vendor_class"] = string(opt.Data)
		case layers.DHCPOptParamsRequest:
			event.Extra["params_request"] = opt.Data
		case layers.DHCPOptMessageType:
			if len(opt.Data) > 0 {
				event.Extra["message_type"] = opt.Data[0]
			}
		}
	}

	return event
}

func (pp *PacketParser) parseDNS(packet gopacket.Packet) *NetworkEvent {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}

	dns := dnsLayer.(*layers.DNS)

	if len(dns.Questions) == 0 {
		return nil
	}

	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil
	}
	ipv4 := ipv4Layer.(*layers.IPv4)

	event := &NetworkEvent{
		ID:        uuid.New().String(),
		Type:      EventTypeDNS,
		Timestamp: packet.Metadata().Timestamp,
		SrcIP:     ipv4.SrcIP,
		DstIP:     ipv4.DstIP,
		Protocol:  "DNS",
		Extra:     make(map[string]interface{}),
	}

	question := dns.Questions[0]
	event.Extra["query_name"] = string(question.Name)
	event.Extra["query_type"] = question.Type.String()
	event.Extra["response_code"] = dns.ResponseCode.String()

	if len(dns.Answers) > 0 {
		ips := make([]string, 0)
		for _, answer := range dns.Answers {
			if answer.Type == layers.DNSTypeA && len(answer.IP) > 0 {
				ips = append(ips, answer.IP.String())
			}
		}
		event.Extra["response_ips"] = ips
	}

	return event
}

func (pp *PacketParser) parseMDNS(packet gopacket.Packet) *NetworkEvent {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}

	dns := dnsLayer.(*layers.DNS)

	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil
	}
	ipv4 := ipv4Layer.(*layers.IPv4)

	event := &NetworkEvent{
		ID:        uuid.New().String(),
		Type:      EventTypeMDNS,
		Timestamp: packet.Metadata().Timestamp,
		SrcIP:     ipv4.SrcIP,
		DstIP:     ipv4.DstIP,
		Protocol:  "mDNS",
		Extra:     make(map[string]interface{}),
	}

	if len(dns.Questions) > 0 {
		event.Extra["query_name"] = string(dns.Questions[0].Name)
	}

	if len(dns.Answers) > 0 {
		for _, answer := range dns.Answers {
			if answer.Type == layers.DNSTypeA && len(answer.IP) > 0 {
				event.Extra["announced_ip"] = answer.IP.String()
			}
			if answer.Type == layers.DNSTypePTR {
				event.Extra["service_name"] = string(answer.PTR)
			}
		}
	}

	return event
}

func (pp *PacketParser) parseTCPSYN(packet gopacket.Packet, tcp *layers.TCP) *NetworkEvent {
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil
	}
	ipv4 := ipv4Layer.(*layers.IPv4)

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	var srcMAC, dstMAC []byte
	if ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		srcMAC = eth.SrcMAC
		dstMAC = eth.DstMAC
	}

	event := &NetworkEvent{
		ID:        uuid.New().String(),
		Type:      EventTypeTCPSYN,
		Timestamp: packet.Metadata().Timestamp,
		SrcIP:     ipv4.SrcIP,
		DstIP:     ipv4.DstIP,
		SrcMAC:    srcMAC,
		DstMAC:    dstMAC,
		SrcPort:   uint16(tcp.SrcPort),
		DstPort:   uint16(tcp.DstPort),
		TTL:       ipv4.TTL,
		Protocol:  "TCP",
		Extra:     make(map[string]interface{}),
	}

	event.Extra["window_size"] = tcp.Window
	event.Extra["mss"] = pp.extractMSS(tcp)

	return event
}

func (pp *PacketParser) parseHTTP(packet gopacket.Packet, tcp *layers.TCP) *NetworkEvent {
	if len(tcp.Payload) == 0 {
		return nil
	}

	payload := string(tcp.Payload)

	if !strings.HasPrefix(payload, "GET ") &&
		!strings.HasPrefix(payload, "POST ") &&
		!strings.HasPrefix(payload, "HTTP/") {
		return nil
	}

	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil
	}
	ipv4 := ipv4Layer.(*layers.IPv4)

	event := &NetworkEvent{
		ID:        uuid.New().String(),
		Type:      EventTypeHTTP,
		Timestamp: packet.Metadata().Timestamp,
		SrcIP:     ipv4.SrcIP,
		DstIP:     ipv4.DstIP,
		SrcPort:   uint16(tcp.SrcPort),
		DstPort:   uint16(tcp.DstPort),
		Protocol:  "HTTP",
		Extra:     make(map[string]interface{}),
	}

	lines := strings.Split(payload, "\r\n")
	if len(lines) > 0 {
		event.Extra["request_line"] = lines[0]
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "User-Agent:") {
			event.UserAgent = strings.TrimSpace(strings.TrimPrefix(line, "User-Agent:"))
		} else if strings.HasPrefix(line, "Host:") {
			event.Extra["host"] = strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
		} else if strings.HasPrefix(line, "Server:") {
			event.Extra["server"] = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		}
	}

	return event
}

func (pp *PacketParser) parseTLS(packet gopacket.Packet, tcp *layers.TCP) *NetworkEvent {
	if len(tcp.Payload) < 6 {
		return nil
	}

	payload := tcp.Payload

	if payload[0] != 0x16 {
		return nil
	}

	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil
	}
	ipv4 := ipv4Layer.(*layers.IPv4)

	event := &NetworkEvent{
		ID:        uuid.New().String(),
		Type:      EventTypeTLS,
		Timestamp: packet.Metadata().Timestamp,
		SrcIP:     ipv4.SrcIP,
		DstIP:     ipv4.DstIP,
		SrcPort:   uint16(tcp.SrcPort),
		DstPort:   uint16(tcp.DstPort),
		Protocol:  "TLS",
		Extra:     make(map[string]interface{}),
	}

	version := binary.BigEndian.Uint16(payload[1:3])
	event.Extra["tls_version"] = pp.tlsVersionString(version)

	if payload[5] == 0x01 {
		event.Extra["handshake_type"] = "ClientHello"
		if sni := pp.extractSNI(payload); sni != "" {
			event.Extra["sni"] = sni
		}
	}

	return event
}

func (pp *PacketParser) extractMSS(tcp *layers.TCP) uint16 {
	for _, opt := range tcp.Options {
		if opt.OptionType == 2 && len(opt.OptionData) == 2 {
			return binary.BigEndian.Uint16(opt.OptionData)
		}
	}
	return 0
}

func (pp *PacketParser) tlsVersionString(version uint16) string {
	switch version {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func (pp *PacketParser) extractSNI(payload []byte) string {
	if len(payload) < 43 {
		return ""
	}

	offset := 43

	if offset+1 >= len(payload) {
		return ""
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen

	if offset+2 >= len(payload) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2 + cipherSuitesLen

	if offset+1 >= len(payload) {
		return ""
	}
	compressionLen := int(payload[offset])
	offset += 1 + compressionLen

	if offset+2 >= len(payload) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	end := offset + extensionsLen
	if end > len(payload) {
		return ""
	}

	for offset+4 <= end {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		if extType == 0 && offset+5 <= end {
			listLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
			offset += 2

			if offset+listLen <= end && listLen >= 3 {
				nameType := payload[offset]
				nameLen := int(binary.BigEndian.Uint16(payload[offset+1 : offset+3]))
				offset += 3

				if nameType == 0 && offset+nameLen <= end {
					return string(payload[offset : offset+nameLen])
				}
			}
			break
		}

		offset += extLen
	}

	return ""
}
