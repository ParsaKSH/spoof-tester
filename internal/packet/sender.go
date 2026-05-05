package packet

import (
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/ParsaKSH/spoof-tester/internal/config"
)

type target struct {
	IP  net.IP
	Seq uint16
}

// RunSender sends spoofed packets to all targets, iterating source IPs one by one in order.
func RunSender(cfg *config.Config, srcIPs []net.IP, targets []net.IP) error {
	for i, srcIP := range srcIPs {
		log.Printf("[sender] source IP %d/%d: %s", i+1, len(srcIPs), srcIP)
		if err := sendForSource(cfg, srcIP, targets); err != nil {
			log.Printf("[sender] error for %s: %v", srcIP, err)
		}
	}
	return nil
}

func sendForSource(cfg *config.Config, srcIP net.IP, targets []net.IP) error {
	total := len(targets)
	log.Printf("[sender] protocol=%s src=%s targets=%d concurrency=%d",
		cfg.Protocol, srcIP, total, cfg.Concurrency)

	if cfg.Protocol == "tcp" {
		log.Printf("[sender] dst_port=%d", cfg.DstPort)
	}

	ch := make(chan target, cfg.Concurrency*2)
	var wg sync.WaitGroup
	var sent atomic.Int64
	var errCount atomic.Int64

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			senderWorker(workerID, cfg, srcIP, ch, &sent, &errCount, total)
		}(i)
	}

	for i, ip := range targets {
		ch <- target{IP: ip, Seq: uint16(i % 65536)}
	}
	close(ch)

	wg.Wait()
	log.Printf("[sender] done for %s — sent: %d, errors: %d", srcIP, sent.Load(), errCount.Load())
	return nil
}

func senderWorker(id int, cfg *config.Config, srcIP net.IP, ch <-chan target, sent, errCount *atomic.Int64, total int) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Printf("[worker-%d] socket create failed: %v", id, err)
		return
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		log.Printf("[worker-%d] setsockopt IP_HDRINCL failed: %v", id, err)
		return
	}

	icmpID := uint16(rand.Intn(65535))

	for t := range ch {
		var pkt []byte
		switch cfg.Protocol {
		case "tcp":
			pkt = BuildTCPSyn(srcIP, t.IP, cfg.DstPort)
		case "icmp":
			pkt = BuildICMPEcho(srcIP, t.IP, icmpID, t.Seq)
		}

		addr := syscall.SockaddrInet4{}
		copy(addr.Addr[:], t.IP.To4())

		if err := syscall.Sendto(fd, pkt, 0, &addr); err != nil {
			errCount.Add(1)
			continue
		}

		n := sent.Add(1)
		if n%5000 == 0 || n == int64(total) {
			log.Printf("[sender] progress: %d / %d", n, total)
		}
	}
}
