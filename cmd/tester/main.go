package main


import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/ParsaKSH/spoof-tester/internal/config"
	"github.com/ParsaKSH/spoof-tester/internal/iplist"
	"github.com/ParsaKSH/spoof-tester/internal/packet"
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to config.json")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	switch cfg.AppMode {
	case "simple":
		runSimple(cfg)
	case "pro":
		runPro(cfg)
	}
}

func runSimple(cfg *config.Config) {
	srcIPs, err := iplist.Parse(cfg.SrcList)
	if err != nil {
		log.Fatalf("src_list: %v", err)
	}
	log.Printf("loaded %d source IPs from %s", len(srcIPs), cfg.SrcList)

	dstIP := net.ParseIP(cfg.DstIP).To4()
	if dstIP == nil {
		log.Fatalf("invalid dst_ip: %s", cfg.DstIP)
	}

	switch cfg.Version {
	case "v1":
		switch cfg.Mode {
		case "sender":
			if err := packet.RunSimpleSender(cfg, srcIPs, dstIP); err != nil {
				log.Fatalf("sender: %v", err)
			}
		case "receiver":
			if err := packet.RunSimpleReceiver(cfg, srcIPs); err != nil {
				log.Fatalf("receiver: %v", err)
			}
		}
	case "v2":
		log.Printf("[v2] packet_count=%d max_packet_loss=%.1f%%", cfg.PacketCount, cfg.MaxPacketLoss)
		switch cfg.Mode {
		case "sender":
			if err := packet.RunSimpleSenderV2(cfg, srcIPs, dstIP); err != nil {
				log.Fatalf("sender-v2: %v", err)
			}
		case "receiver":
			if err := packet.RunSimpleReceiverV2(cfg, srcIPs); err != nil {
				log.Fatalf("receiver-v2: %v", err)
			}
		}
	}
}

func runPro(cfg *config.Config) {
	targets, err := iplist.Parse(cfg.TargetList)
	if err != nil {
		log.Fatalf("targets: %v", err)
	}
	log.Printf("loaded %d target IPs from %s", len(targets), cfg.TargetList)

	switch cfg.Mode {
	case "sender":
		srcIPs, err := loadSourceIPs(cfg)
		if err != nil {
			log.Fatalf("source IPs: %v", err)
		}
		log.Printf("loaded %d source IPs", len(srcIPs))
		if err := packet.RunSender(cfg, srcIPs, targets); err != nil {
			log.Fatalf("sender: %v", err)
		}
	case "receiver":
		if err := packet.RunReceiver(cfg, targets); err != nil {
			log.Fatalf("receiver: %v", err)
		}
	}
}

func loadSourceIPs(cfg *config.Config) ([]net.IP, error) {
	if cfg.SrcList != "" {
		return iplist.Parse(cfg.SrcList)
	}
	ip := net.ParseIP(cfg.SrcIP).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid source IP: %s", cfg.SrcIP)
	}
	return []net.IP{ip}, nil
}
