package iplist

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

// Parse reads an IP list file and returns all individual IPs.
// Supported formats per line:
//   - Single IP:   192.168.1.1
//   - CIDR:        192.168.70.5/31
//   - Range:       192.168.60.5-192.168.60.10
func Parse(path string) ([]net.IP, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open target list: %w", err)
	}
	defer f.Close()

	var ips []net.IP
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parsed, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
		ips = append(ips, parsed...)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read target list: %w", err)
	}

	return ips, nil
}

func parseLine(line string) ([]net.IP, error) {
	// Range format: 192.168.60.5-192.168.60.10
	if strings.Contains(line, "-") {
		return parseRange(line)
	}

	// CIDR format: 192.168.70.5/31
	if strings.Contains(line, "/") {
		return parseCIDR(line)
	}

	// Single IP
	ip := net.ParseIP(line)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", line)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 supported: %s", line)
	}
	return []net.IP{ip}, nil
}

func parseCIDR(cidr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 CIDR supported: %s", cidr)
	}

	var ips []net.IP
	for current := ip.Mask(ipNet.Mask); ipNet.Contains(current); incIP(current) {
		dup := make(net.IP, 4)
		copy(dup, current)
		ips = append(ips, dup)
	}
	return ips, nil
}

func parseRange(r string) ([]net.IP, error) {
	parts := strings.SplitN(r, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: %s", r)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	endIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IPs in range: %s", r)
	}

	start := binary.BigEndian.Uint32(startIP)
	end := binary.BigEndian.Uint32(endIP)

	if start > end {
		return nil, fmt.Errorf("start IP > end IP in range: %s", r)
	}

	ips := make([]net.IP, 0, end-start+1)
	for i := start; i <= end; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ips = append(ips, ip)
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
