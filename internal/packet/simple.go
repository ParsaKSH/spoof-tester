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

// RunSimpleSender sends one spoofed packet per source IP to dst_ip, one by one in order.
func RunSimpleSender(cfg *config.Config, srcIPs []net.IP, dstIP net.IP) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("raw socket: %w (need root/CAP_NET_RAW)", err)
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("setsockopt IP_HDRINCL: %w", err)
	}

	addr := syscall.SockaddrInet4{}
	copy(addr.Addr[:], dstIP.To4())

	log.Printf("[sender] protocol=%s dst=%s sources=%d", cfg.Protocol, dstIP, len(srcIPs))

	var sent, errCount int
	for i, srcIP := range srcIPs {
		var pkt []byte
		switch cfg.Protocol {
		case "tcp":
			pkt = BuildTCPSyn(srcIP, dstIP, cfg.DstPort)
		case "icmp":
			pkt = BuildICMPEcho(srcIP, dstIP, uint16(i+1), uint16(i+1))
		}

		if err := syscall.Sendto(fd, pkt, 0, &addr); err != nil {
			log.Printf("[sender] error sending as %s: %v", srcIP, err)
			errCount++
			continue
		}
		sent++

		if sent%1000 == 0 || i == len(srcIPs)-1 {
			log.Printf("[sender] progress: %d/%d", i+1, len(srcIPs))
		}
	}

	log.Printf("[sender] done -- sent: %d, errors: %d", sent, errCount)
	return nil
}

// RunSimpleReceiver listens for packets whose source IP is in srcIPs, logs them to output.
func RunSimpleReceiver(cfg *config.Config, srcIPs []net.IP) error {
	// Build lookup set from source IPs.
	srcSet := make(map[string]struct{}, len(srcIPs))
	for _, ip := range srcIPs {
		srcSet[ip.To4().String()] = struct{}{}
	}

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

	tv := syscall.Timeval{Sec: 1}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("setsockopt SO_RCVTIMEO: %w", err)
	}

	log.Printf("[receiver] protocol=%s sources=%d timeout=%ds output=%s",
		cfg.Protocol, len(srcIPs), cfg.Timeout, cfg.Output)

	responded := make(map[string]struct{})
	buf := make([]byte, 65535)
	deadline := time.Now().Add(time.Duration(cfg.Timeout) * time.Second)

	log.Printf("[receiver] listening until %s ...", deadline.Format("15:04:05"))

	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
		}
		if n < 20 {
			continue
		}

		// Parse source IP from IP header.
		ihl := int(buf[0]&0x0f) * 4
		if n < ihl {
			continue
		}
		srcIP := net.IP(make([]byte, 4))
		copy(srcIP, buf[12:16])
		srcStr := srcIP.String()

		if _, ok := srcSet[srcStr]; !ok {
			continue
		}
		if _, exists := responded[srcStr]; exists {
			continue
		}

		responded[srcStr] = struct{}{}
		log.Printf("[receiver] <- packet from %s (%d/%d)",
			srcStr, len(responded), len(srcIPs))
	}

	// Write results.
	f, err := os.Create(cfg.Output)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer f.Close()

	for ip := range responded {
		fmt.Fprintln(f, ip)
	}

	log.Printf("[receiver] done -- %d/%d source IPs arrived -> %s",
		len(responded), len(srcIPs), cfg.Output)
	return nil
}

// ============================================================
// V2: multi-packet sender/receiver with packet loss measurement
// ============================================================

// RunSimpleSenderV2 sends packet_count packets per source IP to dst_ip.
func RunSimpleSenderV2(cfg *config.Config, srcIPs []net.IP, dstIP net.IP) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("raw socket: %w (need root/CAP_NET_RAW)", err)
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("setsockopt IP_HDRINCL: %w", err)
	}

	addr := syscall.SockaddrInet4{}
	copy(addr.Addr[:], dstIP.To4())

	totalPkts := len(srcIPs) * cfg.PacketCount
	log.Printf("[sender-v2] protocol=%s dst=%s sources=%d packet_count=%d total_packets=%d",
		cfg.Protocol, dstIP, len(srcIPs), cfg.PacketCount, totalPkts)

	var sent, errCount int
	for i, srcIP := range srcIPs {
		for p := 0; p < cfg.PacketCount; p++ {
			var pkt []byte
			seq := uint16((i*cfg.PacketCount + p) % 65536)
			switch cfg.Protocol {
			case "tcp":
				pkt = BuildTCPSyn(srcIP, dstIP, cfg.DstPort)
			case "icmp":
				pkt = BuildICMPEcho(srcIP, dstIP, uint16(i+1), seq)
			}

			if err := syscall.Sendto(fd, pkt, 0, &addr); err != nil {
				errCount++
				continue
			}
			sent++
		}

		if (i+1)%1000 == 0 || i == len(srcIPs)-1 {
			log.Printf("[sender-v2] progress: %d/%d IPs done (%d pkts sent)",
				i+1, len(srcIPs), sent)
		}
	}

	log.Printf("[sender-v2] done -- sent: %d, errors: %d", sent, errCount)
	return nil
}

// RunSimpleReceiverV2 counts packets per source IP and filters by max_packet_loss.
func RunSimpleReceiverV2(cfg *config.Config, srcIPs []net.IP) error {
	// Build lookup set from source IPs.
	srcSet := make(map[string]struct{}, len(srcIPs))
	for _, ip := range srcIPs {
		srcSet[ip.To4().String()] = struct{}{}
	}

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

	tv := syscall.Timeval{Sec: 1}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("setsockopt SO_RCVTIMEO: %w", err)
	}

	log.Printf("[receiver-v2] protocol=%s sources=%d packet_count=%d max_loss=%.1f%% timeout=%ds",
		cfg.Protocol, len(srcIPs), cfg.PacketCount, cfg.MaxPacketLoss, cfg.Timeout)

	// Count packets received per source IP.
	received := make(map[string]int, len(srcIPs))
	buf := make([]byte, 65535)
	deadline := time.Now().Add(time.Duration(cfg.Timeout) * time.Second)
	totalReceived := 0

	log.Printf("[receiver-v2] listening until %s ...", deadline.Format("15:04:05"))

	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
		}
		if n < 20 {
			continue
		}

		ihl := int(buf[0]&0x0f) * 4
		if n < ihl {
			continue
		}
		srcIP := net.IP(make([]byte, 4))
		copy(srcIP, buf[12:16])
		srcStr := srcIP.String()

		if _, ok := srcSet[srcStr]; !ok {
			continue
		}

		received[srcStr]++
		totalReceived++

		if totalReceived%5000 == 0 {
			log.Printf("[receiver-v2] %d packets received so far from %d unique IPs",
				totalReceived, len(received))
		}
	}

	// Calculate packet loss and filter.
	f, err := os.Create(cfg.Output)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer f.Close()

	var passed, filtered int
	for _, ip := range srcIPs {
		ipStr := ip.To4().String()
		count := received[ipStr]
		lossPercent := float64(cfg.PacketCount-count) / float64(cfg.PacketCount) * 100.0

		if lossPercent <= cfg.MaxPacketLoss {
			fmt.Fprintf(f, "%s %d/%d %.1f%%\n", ipStr, count, cfg.PacketCount, lossPercent)
			passed++
		} else {
			filtered++
		}
	}

	log.Printf("[receiver-v2] done -- %d IPs passed (loss <= %.1f%%), %d filtered out -> %s",
		passed, cfg.MaxPacketLoss, filtered, cfg.Output)
	return nil
}
