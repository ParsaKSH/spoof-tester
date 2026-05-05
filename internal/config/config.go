package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	AppMode       string  `json:"app_mode"`        // "simple" or "pro" (default: "pro")
	Version       string  `json:"version"`         // "v1" or "v2" (simple mode only, default: "v1")
	Mode          string  `json:"mode"`            // "sender" or "receiver"
	Protocol      string  `json:"protocol"`        // "tcp" or "icmp"
	SrcIP         string  `json:"src_ip"`          // single spoofed source IP (pro sender)
	SrcList       string  `json:"src_list"`        // path to source IPs file
	DstIP         string  `json:"dst_ip"`          // destination IP (simple mode — the receiver server)
	TargetList    string  `json:"target_list"`     // path to target IPs file (pro mode)
	Concurrency   int     `json:"concurrency"`     // number of concurrent sender goroutines
	DstPort       int     `json:"dst_port"`        // destination port (tcp mode only)
	Timeout       int     `json:"timeout"`         // receiver listen timeout in seconds
	Output        string  `json:"output"`          // output file path (receiver)
	PacketCount   int     `json:"packet_count"`    // packets per source IP (v2 only, default: 10)
	MaxPacketLoss float64 `json:"max_packet_loss"` // max allowed packet loss % (v2 only, default: 20)
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{
		AppMode:       "pro",
		Version:       "v1",
		Concurrency:   100,
		DstPort:       80,
		Timeout:       30,
		Output:        "output.txt",
		PacketCount:   10,
		MaxPacketLoss: 20.0,
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.AppMode != "simple" && c.AppMode != "pro" {
		return fmt.Errorf("app_mode must be 'simple' or 'pro', got %q", c.AppMode)
	}
	if c.Protocol != "tcp" && c.Protocol != "icmp" {
		return fmt.Errorf("protocol must be 'tcp' or 'icmp', got %q", c.Protocol)
	}
	if c.Mode != "sender" && c.Mode != "receiver" {
		return fmt.Errorf("mode must be 'sender' or 'receiver', got %q", c.Mode)
	}

	switch c.AppMode {
	case "simple":
		if c.Version != "v1" && c.Version != "v2" {
			return fmt.Errorf("version must be 'v1' or 'v2', got %q", c.Version)
		}
		if c.SrcList == "" {
			return fmt.Errorf("src_list is required in simple mode")
		}
		if c.DstIP == "" {
			return fmt.Errorf("dst_ip is required in simple mode")
		}
		if c.Version == "v2" {
			if c.PacketCount < 1 {
				return fmt.Errorf("packet_count must be >= 1 for v2")
			}
			if c.MaxPacketLoss < 0 || c.MaxPacketLoss > 100 {
				return fmt.Errorf("max_packet_loss must be 0-100, got %.1f", c.MaxPacketLoss)
			}
		}
	case "pro":
		if c.TargetList == "" {
			return fmt.Errorf("target_list is required in pro mode")
		}
		if c.Mode == "sender" {
			if c.SrcIP == "" && c.SrcList == "" {
				return fmt.Errorf("src_ip or src_list is required for sender")
			}
			if c.Concurrency < 1 {
				return fmt.Errorf("concurrency must be >= 1")
			}
		}
	}

	if c.Protocol == "tcp" && (c.DstPort < 1 || c.DstPort > 65535) {
		return fmt.Errorf("dst_port must be 1-65535, got %d", c.DstPort)
	}
	return nil
}
