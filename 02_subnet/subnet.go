package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
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

func parseAddr(str string) (addr ipv4, err error) {
	a, err := netip.ParseAddr(str)
	if err != nil {
		return 0, err
	}

	if !a.Is4() {
		err = errors.New("unsupported ip protocol")
		return 0, err
	}

	tmp := a.As4()
	addr = ipv4(binary.BigEndian.Uint32(tmp[:]))
	return addr, nil
}

func parseAddrAndPrefix(str string) (addr ipv4, prefix int, err error) {
	p, err := netip.ParsePrefix(str)
	if err != nil {
		return 0, 0, err
	}

	if !p.Addr().Is4() {
		err = errors.New("unsupported ip protocol")
		return 0, 0, err
	}

	a := p.Addr().As4()
	addr = ipv4(binary.BigEndian.Uint32(a[:]))
	prefix = p.Bits()
	return addr, prefix, nil
}

func runSubnet(addr ipv4, prefix int) {
	netmask := ipv4(^uint32(0) << uint32(32-prefix))
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

	fmt.Printf("network %s\n", network)
	fmt.Printf("broadcast %s\n", broadcast)
	fmt.Printf("netmask %s\n", netmask)
	fmt.Printf("prefix %d\n", prefix)
	fmt.Printf("first %s\n", first)
	fmt.Printf("last %s\n", last)
	fmt.Printf("hosts %d\n", hosts)
}

func runRoute(path string, addr ipv4) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var bestNetInterface string
	bestPrefix := -1
	foundBest := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0][0] != '#' {
			if len(fields) != 2 {
				return errors.New("bad line in file")
			}

			network, prefix, err := parseAddrAndPrefix(fields[0])
			if err != nil {
				return err
			}
			netmask := ipv4(^uint32(0) << uint32(32-prefix))
			if network&netmask == addr&netmask && prefix > bestPrefix {
				bestNetInterface = fields[1]
				bestPrefix = prefix
				foundBest = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if !foundBest {
		return errUnreachable
	}

	fmt.Printf("via %s\n", bestNetInterface)
	fmt.Printf("prefix %d\n", bestPrefix)

	return nil
}

func main() {
	if len(os.Args) < 3 {
		slog.Error("program must have 2 or 3 args in command line")
		os.Exit(1)
	}

	args := os.Args[1:]

	switch args[0] {
	case "subnet":
		addr, prefix, err := parseAddrAndPrefix(args[1])
		if err != nil {
			slog.Error("incorrect arg in command line", slog.Any("error", err), slog.String("arg", args[1]))
			os.Exit(1)
		}

		runSubnet(addr, prefix)
	case "route":
		if len(args) < 3 {
			slog.Error("route mode needs 3 args in command line")
			os.Exit(1)
		}

		addr, err := parseAddr(args[2])
		if err != nil {
			slog.Error("incorrect arg in command line", slog.Any("error", err), slog.String("arg", args[2]))
			os.Exit(1)
		}

		err = runRoute(args[1], addr)
		if errors.Is(err, errUnreachable) {
			fmt.Println("unreachable true")
			os.Exit(1)
		} else if err != nil {
			slog.Error("failed to run route", slog.Any("error", err))
			os.Exit(1)
		}
	default:
		slog.Error("unknown arg in command line", slog.String("arg", args[0]))
		os.Exit(1)
	}
}
