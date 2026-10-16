package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
)

var errUnreachable = errors.New("unreachable")

type ipv4 uint32

func (ip ipv4) String() string {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(ip))
	return netip.AddrFrom4(tmp).String()
}

func ipv4FromAddr(a netip.Addr) (ipv4, error) {
	if !a.Is4() {
		return 0, errors.New("not an IPv4 address")
	}

	aAs4 := a.As4()
	return ipv4(binary.BigEndian.Uint32(aAs4[:])), nil
}

func parseAddr(str string) (ipv4, error) {
	a, err := netip.ParseAddr(str)
	if err != nil {
		return 0, err
	}

	return ipv4FromAddr(a)
}

func parseAddrAndPrefix(str string) (ipv4, int, error) {
	p, err := netip.ParsePrefix(str)
	if err != nil {
		return 0, 0, err
	}

	addr, err := ipv4FromAddr(p.Addr())
	if err != nil {
		return 0, 0, err
	}

	return addr, p.Bits(), nil
}

func maskFromPrefix(prefix int) ipv4 {
	return ipv4(^uint32(0) << uint32(32-prefix))
}

func runSubnet(w io.Writer, addr ipv4, prefix int) {
	netmask := maskFromPrefix(prefix)
	network := addr & netmask
	end := network | ^netmask
	broadcast := "none"
	first := network
	last := end
	hosts := uint64(1) << (32 - prefix)

	if prefix < 31 {
		broadcast = end.String()
		first++
		last--
		hosts -= 2
	}

	fmt.Fprintln(w, "network", network)
	fmt.Fprintln(w, "broadcast", broadcast)
	fmt.Fprintln(w, "netmask", netmask)
	fmt.Fprintln(w, "prefix", prefix)
	fmt.Fprintln(w, "first", first)
	fmt.Fprintln(w, "last", last)
	fmt.Fprintln(w, "hosts", hosts)
}

func runRoute(w io.Writer, path string, addr ipv4) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var bestNetInterface string
	bestPrefix := -1
	bestLineNum := -1
	conflictLineNum := -1

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) == 0 || fields[0][0] == '#' {
			continue
		}

		if len(fields) != 2 {
			slog.Warn(
				"file line must have only 2 fields: <network>/<prefix> <interface>",
				slog.Int("line_num", lineNum),
				slog.String("line", line),
			)
			continue
		}

		network, prefix, err := parseAddrAndPrefix(fields[0])
		if err != nil {
			slog.Warn(
				"failed to parse line first field",
				slog.Any("error", err),
				slog.Int("line_num", lineNum),
				slog.String("line", line),
			)
			continue
		}

		netmask := maskFromPrefix(prefix)

		if network&netmask != addr&netmask {
			continue
		}

		if prefix > bestPrefix {
			bestNetInterface = fields[1]
			bestPrefix = prefix
			bestLineNum = lineNum
			conflictLineNum = -1
		} else if prefix == bestPrefix && fields[1] != bestNetInterface {
			conflictLineNum = lineNum
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if bestLineNum == -1 {
		return errUnreachable
	}

	if conflictLineNum != -1 {
		return fmt.Errorf(
			"ambiguous route: same prefix with different interfaces: line %d and %d",
			bestLineNum,
			conflictLineNum,
		)
	}

	fmt.Fprintln(w, "via", bestNetInterface)
	fmt.Fprintln(w, "prefix", bestPrefix)

	return nil
}

func main() {
	if len(os.Args) < 2 {
		slog.Error("program must have run mode as first arg in command line: \"route\" or \"subnet\"")
		os.Exit(1)
	}

	args := os.Args[1:]

	switch args[0] {
	case "subnet":
		if len(args) != 2 {
			slog.Error("program must have exactly one argument after subnet mode: <addr>/<prefix>")
			os.Exit(1)
		}

		addr, prefix, err := parseAddrAndPrefix(args[1])
		if err != nil {
			slog.Error("incorrect arg in command line", slog.Any("error", err), slog.String("arg", args[1]))
			os.Exit(1)
		}

		runSubnet(os.Stdout, addr, prefix)
	case "route":
		if len(args) != 3 {
			slog.Error("program must have exactly two arguments after route mode: <route_file> <dst_addr>")
			os.Exit(1)
		}

		addr, err := parseAddr(args[2])
		if err != nil {
			slog.Error("incorrect arg in command line", slog.Any("error", err), slog.String("arg", args[2]))
			os.Exit(1)
		}

		err = runRoute(os.Stdout, args[1], addr)
		if errors.Is(err, errUnreachable) {
			fmt.Println("unreachable true")
			os.Exit(1)
		} else if err != nil {
			slog.Error("failed to run route", slog.Any("error", err))
			os.Exit(1)
		}
	default:
		slog.Error("unknown first arg in command line (only \"route\" and \"subnet\" allowed)", slog.String("arg", args[0]))
		os.Exit(1)
	}
}
