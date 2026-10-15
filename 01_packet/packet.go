package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"unicode"
)

const (
	ethernetHeaderLen = 14
	ipv4MinHeaderLen  = 20
	tcpMinHeaderLen   = 20
	udpHeaderLen      = 8

	etherTypeIPv4 = 0x0800

	protocolTCP = 6
	protocolUDP = 17
)

func readFrame(r io.Reader) ([]byte, error) {
	hexDump, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}

	filt := func(c rune) rune {
		if c == ':' || unicode.IsSpace(c) {
			return -1
		}
		return c
	}

	digits := bytes.Map(filt, hexDump)

	frame := make([]byte, hex.DecodedLen(len(digits)))

	if _, err := hex.Decode(frame, digits); err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}

	return frame, nil
}

type EthernetFrame struct {
	dst       net.HardwareAddr
	src       net.HardwareAddr
	ethertype uint16
	payload   []byte
}

func parseEthernet(frame []byte) (*EthernetFrame, error) {
	if len(frame) < ethernetHeaderLen {
		return nil, fmt.Errorf("frame too short for ethernet header: got %d bytes, need %d",
			len(frame), ethernetHeaderLen)
	}

	return &EthernetFrame{
		dst:       net.HardwareAddr(frame[:6]),
		src:       net.HardwareAddr(frame[6:12]),
		ethertype: binary.BigEndian.Uint16(frame[12:14]),
		payload:   frame[ethernetHeaderLen:],
	}, nil
}

func (e *EthernetFrame) print(w io.Writer) {
	fmt.Fprintln(w, "eth.dst", e.dst)
	fmt.Fprintln(w, "eth.src", e.src)
	fmt.Fprintf(w, "eth.ethertype 0x%04x\n", e.ethertype)
}

type IPv4Packet struct {
	version       uint8
	ihlBytes      uint8
	totalLength   uint16
	id            uint16
	flags         uint8 // | 0 | 0 | 0 | 0 | 0 | R | DF | MF |
	fragOffset    uint16
	ttl           uint8
	protocol      uint8
	src           netip.Addr
	dst           netip.Addr
	checksumValid bool
	payload       []byte
}

const (
	ipFlagReserved = 0b100
	ipFlagDF       = 0b010
	ipFlagMF       = 0b001
)

func parseIPv4(packet []byte) (*IPv4Packet, error) {
	if len(packet) < ipv4MinHeaderLen {
		return nil, fmt.Errorf("packet too short for IPv4 header: got %d bytes, need %d",
			len(packet), ipv4MinHeaderLen)
	}

	version := packet[0] >> 4

	ihlBytes := int(packet[0]&0x0f) * 4

	if version != 4 {
		return nil, fmt.Errorf("unexpected IP version %d", version)
	}
	if ihlBytes < ipv4MinHeaderLen {
		return nil, fmt.Errorf("IPv4 header length %d is less than %d", ihlBytes, ipv4MinHeaderLen)
	}
	if ihlBytes > len(packet) {
		return nil, fmt.Errorf("IPv4 header length %d exceeds packet size %d", ihlBytes, len(packet))
	}

	totalLength := binary.BigEndian.Uint16(packet[2:4])
	if int(totalLength) < ihlBytes {
		return nil, fmt.Errorf("IPv4 total length %d is less than header length %d", totalLength, ihlBytes)
	}
	if int(totalLength) > len(packet) {
		slog.Warn(
			"ip.total_length is larger than packet size",
			slog.Int("total_length", int(totalLength)),
			slog.Int("packet_size", len(packet)),
		)
	}

	flagsAndOffset := binary.BigEndian.Uint16(packet[6:8])

	flags := uint8(flagsAndOffset >> 13)
	if flags&ipFlagReserved != 0 {
		slog.Warn("reserved IPv4 flag bit is set")
	}

	header := packet[:ihlBytes]

	return &IPv4Packet{
		version:       version,
		ihlBytes:      uint8(ihlBytes),
		totalLength:   totalLength,
		id:            binary.BigEndian.Uint16(packet[4:6]),
		flags:         flags,
		fragOffset:    uint16(flagsAndOffset&0x1fff) * 8,
		ttl:           packet[8],
		protocol:      packet[9],
		src:           netip.AddrFrom4([4]byte(packet[12:16])),
		dst:           netip.AddrFrom4([4]byte(packet[16:20])),
		checksumValid: ipv4Checksum(header) == binary.BigEndian.Uint16(packet[10:12]),
		payload:       packet[ihlBytes:min(int(totalLength), len(packet))],
	}, nil
}

func ipv4Checksum(header []byte) uint16 {
	const checksumOffset = 10

	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		if i == checksumOffset {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}

	return ^uint16(sum)
}

func (p *IPv4Packet) print(w io.Writer) {
	fmt.Fprintln(w, "ip.version", p.version)
	fmt.Fprintln(w, "ip.ihl_bytes", p.ihlBytes)
	fmt.Fprintln(w, "ip.total_length", p.totalLength)
	fmt.Fprintf(w, "ip.id 0x%04x\n", p.id)
	var strFlags []string
	if p.flags&ipFlagDF != 0 {
		strFlags = append(strFlags, "DF")
	}
	if p.flags&ipFlagMF != 0 {
		strFlags = append(strFlags, "MF")
	}
	fmt.Fprintln(w, "ip.flags", joinFlags(strFlags))
	fmt.Fprintln(w, "ip.frag_offset", p.fragOffset)
	fmt.Fprintln(w, "ip.ttl", p.ttl)
	fmt.Fprintln(w, "ip.protocol", p.protocol)
	fmt.Fprintln(w, "ip.src", p.src)
	fmt.Fprintln(w, "ip.dst", p.dst)
	fmt.Fprintln(w, "ip.checksum_valid", p.checksumValid)
}

type TCPSegment struct {
	srcPort         uint16
	dstPort         uint16
	seq             uint32
	ack             uint32
	dataOffsetBytes uint8
	flags           uint8
	window          uint16
	payload         []byte
}

func parseTCP(segment []byte) (*TCPSegment, error) {
	if len(segment) < tcpMinHeaderLen {
		return nil, fmt.Errorf("segment too short for TCP header: got %d bytes, need %d",
			len(segment), tcpMinHeaderLen)
	}

	dataOffsetBytes := int(segment[12]>>4) * 4
	if dataOffsetBytes < tcpMinHeaderLen {
		return nil, fmt.Errorf("TCP header length %d is less than %d", dataOffsetBytes, tcpMinHeaderLen)
	}
	if dataOffsetBytes > len(segment) {
		return nil, fmt.Errorf("TCP header length %d exceeds segment size %d", dataOffsetBytes, len(segment))
	}

	return &TCPSegment{
		srcPort:         binary.BigEndian.Uint16(segment[0:2]),
		dstPort:         binary.BigEndian.Uint16(segment[2:4]),
		seq:             binary.BigEndian.Uint32(segment[4:8]),
		ack:             binary.BigEndian.Uint32(segment[8:12]),
		dataOffsetBytes: uint8(dataOffsetBytes),
		flags:           segment[13],
		window:          binary.BigEndian.Uint16(segment[14:16]),
		payload:         segment[dataOffsetBytes:],
	}, nil
}

var tcpFlagNames = []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG"}

func (s *TCPSegment) print(w io.Writer) {
	fmt.Fprintln(w, "tcp.src_port", s.srcPort)
	fmt.Fprintln(w, "tcp.dst_port", s.dstPort)
	fmt.Fprintln(w, "tcp.seq", s.seq)
	fmt.Fprintln(w, "tcp.ack", s.ack)
	fmt.Fprintln(w, "tcp.data_offset_bytes", s.dataOffsetBytes)
	var strFlags []string
	for bit, name := range tcpFlagNames {
		if s.flags&(1<<bit) != 0 {
			strFlags = append(strFlags, name)
		}
	}
	fmt.Fprintln(w, "tcp.flags", joinFlags(strFlags))
	fmt.Fprintln(w, "tcp.window", s.window)
}

type UDPDatagram struct {
	srcPort uint16
	dstPort uint16
	length  uint16
	payload []byte
}

func parseUDP(datagram []byte) (*UDPDatagram, error) {
	if len(datagram) < udpHeaderLen {
		return nil, fmt.Errorf("datagram too short for UDP header: got %d bytes, need %d",
			len(datagram), udpHeaderLen)
	}

	length := binary.BigEndian.Uint16(datagram[4:6])

	end := len(datagram)
	if length < udpHeaderLen {
		slog.Warn("udp.length is shorter than udp header size", slog.Int("length", int(length)))
	} else if int(length) != len(datagram) {
		slog.Warn(
			"udp.length and datagram size are different",
			slog.Int("length", int(length)),
			slog.Int("datagram_size", len(datagram)),
		)
		end = min(int(length), len(datagram))
	}

	return &UDPDatagram{
		srcPort: binary.BigEndian.Uint16(datagram[0:2]),
		dstPort: binary.BigEndian.Uint16(datagram[2:4]),
		length:  length,
		payload: datagram[udpHeaderLen:end],
	}, nil
}

func (d *UDPDatagram) print(w io.Writer) {
	fmt.Fprintln(w, "udp.src_port", d.srcPort)
	fmt.Fprintln(w, "udp.dst_port", d.dstPort)
	fmt.Fprintln(w, "udp.length", d.length)
}

func joinFlags(flags []string) string {
	if len(flags) == 0 {
		return "none"
	}
	return strings.Join(flags, ",")
}

func main() {
	frame, err := readFrame(os.Stdin)
	if err != nil {
		slog.Error("failed to read frame", slog.Any("error", err))
		os.Exit(1)
	}

	eth, err := parseEthernet(frame)
	if err != nil {
		slog.Error("failed to parse ethernet frame", slog.Any("error", err))
		os.Exit(1)
	}
	eth.print(os.Stdout)

	if eth.ethertype != etherTypeIPv4 {
		return
	}

	ip, err := parseIPv4(eth.payload)
	if err != nil {
		slog.Error("failed to parse IPv4 packet", slog.Any("error", err))
		os.Exit(1)
	}
	ip.print(os.Stdout)

	payload := ip.payload

	if ip.fragOffset == 0 {
		switch ip.protocol {
		case protocolTCP:
			tcp, err := parseTCP(ip.payload)
			if err != nil {
				slog.Error("failed to parse TCP segment", slog.Any("error", err))
				os.Exit(1)
			}
			tcp.print(os.Stdout)
			payload = tcp.payload
		case protocolUDP:
			udp, err := parseUDP(ip.payload)
			if err != nil {
				slog.Error("failed to parse UDP datagram", slog.Any("error", err))
				os.Exit(1)
			}
			udp.print(os.Stdout)
			payload = udp.payload
		}
	}

	fmt.Println("payload.length", len(payload))
}
