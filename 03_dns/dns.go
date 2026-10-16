package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	headerLen       = 12
	recordHeaderLen = 10
	maxMessageLen   = 65535
	maxLabelLen     = 63
	maxNameLen      = 255
	maxPointerJumps = 128

	responseTimeout = 5 * time.Second

	classIN       = 1
	flagResponse  = 0x8000 // QR bit
	flagTruncated = 0x0200 // TC bit
	flagRecursion = 0x0100 // RD bit
	rcodeMask     = 0x000F
	rcodeNoError  = 0

	typeA     = 1
	typeNS    = 2
	typeCNAME = 5
	typeMX    = 15
	typeTXT   = 16
	typeAAAA  = 28
)

var errTimeout = errors.New("no response within timeout")

var typeCodes = map[string]uint16{
	"A":     typeA,
	"NS":    typeNS,
	"CNAME": typeCNAME,
	"MX":    typeMX,
	"TXT":   typeTXT,
	"AAAA":  typeAAAA,
}

var typeNames = map[uint16]string{
	typeA:     "A",
	typeNS:    "NS",
	typeCNAME: "CNAME",
	typeMX:    "MX",
	typeTXT:   "TXT",
	typeAAAA:  "AAAA",
}

var rcodeNames = map[int]string{
	0: "NOERROR",
	1: "FORMERR",
	2: "SERVFAIL",
	3: "NXDOMAIN",
	5: "REFUSED",
}

type question struct {
	name     string
	typeName string
	qtype    uint16
	wireName []byte
}

type answer struct {
	typeName string
	value    string
	ttl      uint32
}

type response struct {
	rcode     int
	truncated bool
	answers   []answer
	minTTL    uint32
}

type cacheKey struct {
	name  string // lower case, without trailing dot
	qtype uint16
}

type cacheEntry struct {
	answers []answer
	expires time.Time
}

func parseServer(addrArg string, portArg string) (netip.AddrPort, error) {
	addr, err := netip.ParseAddr(addrArg)
	if err != nil {
		return netip.AddrPort{}, err
	}

	port, err := strconv.ParseUint(portArg, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, fmt.Errorf("port must be a number from 1 to 65535, got %q", portArg)
	}

	return netip.AddrPortFrom(addr, uint16(port)), nil
}

func parseQuestion(line string) (question, error) {
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return question{}, fmt.Errorf("line must look like \"<name> <type>\", got %q", line)
	}

	qtype, ok := typeCodes[strings.ToUpper(fields[1])]
	if !ok {
		return question{}, fmt.Errorf("unsupported type %q", fields[1])
	}

	wireName, err := encodeName(fields[0])
	if err != nil {
		return question{}, err
	}

	return question{name: fields[0], typeName: fields[1], qtype: qtype, wireName: wireName}, nil
}

func newCacheKey(q question) cacheKey {
	return cacheKey{
		name:  strings.ToLower(strings.TrimSuffix(q.name, ".")),
		qtype: q.qtype,
	}
}

func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")

	var buf []byte
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > maxLabelLen {
				return nil, fmt.Errorf("label %q must be 1 to %d bytes long", label, maxLabelLen)
			}
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
		}
	}
	buf = append(buf, 0)

	if len(buf) > maxNameLen {
		return nil, fmt.Errorf("name %q is longer than %d bytes", name, maxNameLen)
	}

	return buf, nil
}

func buildQuery(id uint16, q question) []byte {
	msg := make([]byte, headerLen, headerLen+len(q.wireName)+4)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], flagRecursion)
	binary.BigEndian.PutUint16(msg[4:6], 1)

	msg = append(msg, q.wireName...)
	msg = binary.BigEndian.AppendUint16(msg, q.qtype)
	msg = binary.BigEndian.AppendUint16(msg, classIN)

	return msg
}

func readName(msg []byte, offset int) (string, int, error) {
	var labels []string
	end := -1
	jumps := 0

	for {
		if offset >= len(msg) {
			return "", 0, errors.New("name runs past the end of message")
		}
		length := int(msg[offset])

		switch {
		case length&0xC0 == 0xC0:
			if offset+1 >= len(msg) {
				return "", 0, errors.New("name pointer is truncated")
			}
			if end < 0 {
				end = offset + 2
			}
			jumps++
			if jumps > maxPointerJumps {
				return "", 0, errors.New("too many name pointers, probably a loop")
			}
			offset = int(binary.BigEndian.Uint16(msg[offset:offset+2]) & 0x3FFF)
		case length&0xC0 != 0:
			return "", 0, fmt.Errorf("unsupported label type 0x%02x", length)
		case length == 0:
			if end < 0 {
				end = offset + 1
			}
			return strings.Join(labels, ".") + ".", end, nil
		default:
			offset++
			if offset+length > len(msg) {
				return "", 0, errors.New("label runs past the end of message")
			}
			labels = append(labels, string(msg[offset:offset+length]))
			offset += length
		}
	}
}

func formatRecordData(msg []byte, rtype uint16, start int, end int) (string, error) {
	rdata := msg[start:end]

	switch rtype {
	case typeA:
		if len(rdata) != 4 {
			return "", fmt.Errorf("A data must be 4 bytes, got %d", len(rdata))
		}
		return netip.AddrFrom4([4]byte(rdata)).String(), nil
	case typeAAAA:
		if len(rdata) != 16 {
			return "", fmt.Errorf("AAAA data must be 16 bytes, got %d", len(rdata))
		}
		return netip.AddrFrom16([16]byte(rdata)).String(), nil
	case typeCNAME, typeNS:
		// msg[:end] does not let the name run into the next record
		name, _, err := readName(msg[:end], start)
		return name, err
	case typeMX:
		if len(rdata) < 3 {
			return "", fmt.Errorf("MX data is too short: %d bytes", len(rdata))
		}
		preference := binary.BigEndian.Uint16(rdata[0:2])
		host, _, err := readName(msg[:end], start+2)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d %s", preference, host), nil
	case typeTXT:
		var sb strings.Builder
		for i := 0; i < len(rdata); {
			length := int(rdata[i])
			i++
			if i+length > len(rdata) {
				return "", errors.New("TXT string runs past record data")
			}
			sb.Write(rdata[i : i+length])
			i += length
		}
		return sb.String(), nil
	default:
		return "", fmt.Errorf("unsupported type %d", rtype)
	}
}

func parseResponse(msg []byte) (response, error) {
	flags := binary.BigEndian.Uint16(msg[2:4])
	qdcount := int(binary.BigEndian.Uint16(msg[4:6]))
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))

	resp := response{
		rcode:     int(flags & rcodeMask),
		truncated: flags&flagTruncated != 0,
	}
	offset := headerLen

	for range qdcount {
		_, end, err := readName(msg, offset)
		if err != nil {
			return response{}, fmt.Errorf("question: %w", err)
		}
		offset = end + 4
	}

	for i := range ancount {
		_, end, err := readName(msg, offset)
		if err != nil {
			return response{}, fmt.Errorf("answer %d: %w", i+1, err)
		}
		if end+recordHeaderLen > len(msg) {
			return response{}, fmt.Errorf("answer %d: record header is truncated", i+1)
		}

		rtype := binary.BigEndian.Uint16(msg[end : end+2])
		ttl := binary.BigEndian.Uint32(msg[end+4 : end+8])
		rdLength := int(binary.BigEndian.Uint16(msg[end+8 : end+10]))

		dataStart := end + recordHeaderLen
		dataEnd := dataStart + rdLength
		if dataEnd > len(msg) {
			return response{}, fmt.Errorf("answer %d: record data is truncated", i+1)
		}
		offset = dataEnd

		if i == 0 || ttl < resp.minTTL {
			resp.minTTL = ttl
		}

		typeName, ok := typeNames[rtype]
		if !ok {
			continue
		}

		value, err := formatRecordData(msg, rtype, dataStart, dataEnd)
		if err != nil {
			slog.Warn("skip malformed record",
				slog.Int("answer", i+1),
				slog.String("type", typeName),
				slog.Any("error", err),
			)
			continue
		}
		resp.answers = append(resp.answers, answer{typeName: typeName, value: value, ttl: ttl})
	}

	return resp, nil
}

func exchange(conn *net.UDPConn, q question) (response, error) {
	var idBytes [2]byte
	rand.Read(idBytes[:])
	id := binary.BigEndian.Uint16(idBytes[:])

	if _, err := conn.Write(buildQuery(id, q)); err != nil {
		return response{}, fmt.Errorf("send query: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(responseTimeout)); err != nil {
		return response{}, fmt.Errorf("set deadline: %w", err)
	}

	buf := make([]byte, maxMessageLen)
	for {
		n, err := conn.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return response{}, errTimeout
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			// ICMP port unreachable: nobody answers, wait for the deadline
			continue
		}
		if err != nil {
			return response{}, fmt.Errorf("receive response: %w", err)
		}

		msg := buf[:n]
		if len(msg) < headerLen {
			continue
		}

		msgID := binary.BigEndian.Uint16(msg[0:2])
		flags := binary.BigEndian.Uint16(msg[2:4])
		if msgID != id || flags&flagResponse == 0 {
			continue
		}

		resp, err := parseResponse(msg)
		if err != nil {
			slog.Warn("skip malformed response", slog.Any("error", err))
			continue
		}
		return resp, nil
	}
}

func rcodeName(rcode int) string {
	if name, ok := rcodeNames[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", rcode)
}

func printBlock(q question, status string, answers []answer) {
	fmt.Printf("query %s %s\n", q.name, q.typeName)
	fmt.Printf("status %s\n", status)
	for _, a := range answers {
		fmt.Printf("answer %s %s %d\n", a.typeName, a.value, a.ttl)
	}
	fmt.Println("end")
}

func main() {
	if len(os.Args) != 3 {
		slog.Error("program must have 2 args in command line: <server address> <port>")
		os.Exit(1)
	}

	server, err := parseServer(os.Args[1], os.Args[2])
	if err != nil {
		slog.Error("incorrect args in command line", slog.Any("error", err))
		os.Exit(1)
	}

	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(server))
	if err != nil {
		slog.Error("failed to open udp socket", slog.Any("error", err))
		os.Exit(1)
	}
	defer conn.Close()

	cache := make(map[cacheKey]cacheEntry)

	lineNum := 0
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		q, err := parseQuestion(line)
		if err != nil {
			slog.Warn("skip incorrect line in input",
				slog.Int("line_num", lineNum),
				slog.String("line", line),
				slog.Any("error", err),
			)
			continue
		}

		key := newCacheKey(q)
		if entry, ok := cache[key]; ok {
			if time.Now().Before(entry.expires) {
				printBlock(q, rcodeName(rcodeNoError), entry.answers)
				continue
			}
			delete(cache, key)
		}

		resp, err := exchange(conn, q)
		if errors.Is(err, errTimeout) {
			printBlock(q, "TIMEOUT", nil)
			os.Exit(1)
		}
		if err != nil {
			slog.Error("failed to resolve", slog.Any("error", err), slog.String("query", line))
			os.Exit(1)
		}

		if resp.truncated {
			slog.Warn("truncated response is not cached, answers may be incomplete", slog.String("query", line))
		} else if resp.rcode == rcodeNoError && len(resp.answers) > 0 && resp.minTTL > 0 {
			cache[key] = cacheEntry{
				answers: resp.answers,
				expires: time.Now().Add(time.Duration(resp.minTTL) * time.Second),
			}
		}

		printBlock(q, rcodeName(resp.rcode), resp.answers)
	}

	if err := scanner.Err(); err != nil {
		slog.Error("failed to read input", slog.Any("error", err))
		os.Exit(1)
	}
}
