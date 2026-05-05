package packet

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/ParsaKSH/spoof-tester/internal/config"
)

// RunReceiver listens for responses and writes responding IPs to output file.
func RunReceiver(cfg *config.Config, targets []net.IP) error {
	// Build target set for O(1) lookups.
	targetSet := make(map[string]struct{}, len(targets))
	for _, ip := range targets {
		targetSet[ip.To4().String()] = struct{}{}
	}

	log.Printf("[receiver] protocol=%s targets=%d timeout=%ds output=%s",
		cfg.Protocol, len(targets), cfg.Timeout, cfg.Output)

	var proto int
	switch cfg.Protocol {
	case "tcp":
		proto = syscall.IPPROTO_TCP
	case "icmp":
		proto = syscall.IPPROTO_ICMP
	default:
		return fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
	if err != nil {
		return fmt.Errorf("raw socket: %w (need root/CAP_NET_RAW)", err)
	}
	defer syscall.Close(fd)

	// Set socket receive timeout to 1s intervals so we can check deadline.
	tv := syscall.Timeval{Sec: 1}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("setsockopt SO_RCVTIMEO: %w", err)
	}

	responded := make(map[string]struct{})
	buf := make([]byte, 65535)
	deadline := time.Now().Add(time.Duration(cfg.Timeout) * time.Second)

	log.Printf("[receiver] listening for responses until %s ...", deadline.Format("15:04:05"))

	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			// Timeout — loop continues until deadline.
			continue
		}

		if n < 20 {
			continue
		}

		// Parse IP header to get source IP.
		ihl := int(buf[0]&0x0f) * 4
		if n < ihl {
			continue
		}
		srcIP := net.IP(make([]byte, 4))
		copy(srcIP, buf[12:16])
		srcStr := srcIP.String()

		// Only care about IPs in our target list.
		if _, ok := targetSet[srcStr]; !ok {
			continue
		}

		// Already recorded?
		if _, exists := responded[srcStr]; exists {
			continue
		}

		payload := buf[ihl:n]
		if !isValidResponse(cfg.Protocol, payload) {
			continue
		}

		responded[srcStr] = struct{}{}
		log.Printf("[receiver] ← response from %s (%d/%d)",
			srcStr, len(responded), len(targets))
	}

	// Write results to output file.
	f, err := os.Create(cfg.Output)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	for ip := range responded {
		fmt.Fprintln(f, ip)
	}

	log.Printf("[receiver] done — %d/%d IPs responded → %s",
		len(responded), len(targets), cfg.Output)
	return nil
}

// isValidResponse checks if the received payload matches the expected response type.
func isValidResponse(protocol string, payload []byte) bool {
	switch protocol {
	case "tcp":
		// TCP header minimum 20 bytes, flags at offset 13.
		// SYN-ACK = 0x12, RST = 0x04, RST-ACK = 0x14
		// Any of these means the target host is alive.
		if len(payload) < 14 {
			return false
		}
		flags := payload[13]
		return flags&0x12 == 0x12 || flags&0x04 != 0

	case "icmp":
		// ICMP Echo Reply: type=0, code=0
		if len(payload) < 1 {
			return false
		}
		return payload[0] == 0

	default:
		return false
	}
}
