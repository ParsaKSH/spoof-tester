package packet

import (
	"encoding/binary"
	"math/rand"
	"net"
)

// BuildTCPSyn crafts a raw IP packet containing a TCP SYN segment.
func BuildTCPSyn(srcIP, dstIP net.IP, dstPort int) []byte {
	src := srcIP.To4()
	dst := dstIP.To4()

	// IP header (20) + TCP header (20) = 40 bytes
	pkt := make([]byte, 40)

	// --- IP Header ---
	pkt[0] = 0x45 // Version=4, IHL=5
	pkt[1] = 0    // TOS
	binary.BigEndian.PutUint16(pkt[2:], 40)                       // Total Length
	binary.BigEndian.PutUint16(pkt[4:], uint16(rand.Intn(65535))) // ID
	pkt[6] = 0x40                                                 // Flags: Don't Fragment
	pkt[7] = 0                                                    // Fragment Offset
	pkt[8] = 64                                                   // TTL
	pkt[9] = 6                                                    // Protocol: TCP
	// pkt[10:12] = IP checksum (filled below)
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[10:], internetChecksum(pkt[:20]))

	// --- TCP Header ---
	tcp := pkt[20:]
	srcPort := uint16(1024 + rand.Intn(64511))
	binary.BigEndian.PutUint16(tcp[0:], srcPort)          // Source Port
	binary.BigEndian.PutUint16(tcp[2:], uint16(dstPort))  // Dest Port
	binary.BigEndian.PutUint32(tcp[4:], rand.Uint32())    // Sequence Number
	binary.BigEndian.PutUint32(tcp[8:], 0)                // Ack Number
	tcp[12] = 0x50                                        // Data Offset: 5 words (20 bytes)
	tcp[13] = 0x02                                        // Flags: SYN
	binary.BigEndian.PutUint16(tcp[14:], 65535)           // Window Size
	binary.BigEndian.PutUint16(tcp[18:], 0)               // Urgent Pointer
	binary.BigEndian.PutUint16(tcp[16:], tcpChecksum(src, dst, tcp))

	return pkt
}

// BuildICMPEcho crafts a raw IP packet containing an ICMP Echo Request.
func BuildICMPEcho(srcIP, dstIP net.IP, id uint16, seq uint16) []byte {
	src := srcIP.To4()
	dst := dstIP.To4()

	// IP header (20) + ICMP header (8) = 28 bytes
	pkt := make([]byte, 28)

	// --- IP Header ---
	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:], 28)
	binary.BigEndian.PutUint16(pkt[4:], uint16(rand.Intn(65535)))
	pkt[6] = 0x40
	pkt[7] = 0
	pkt[8] = 64
	pkt[9] = 1 // Protocol: ICMP
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[10:], internetChecksum(pkt[:20]))

	// --- ICMP Header ---
	icmp := pkt[20:]
	icmp[0] = 8 // Type: Echo Request
	icmp[1] = 0 // Code: 0
	binary.BigEndian.PutUint16(icmp[4:], id)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	binary.BigEndian.PutUint16(icmp[2:], internetChecksum(icmp))

	return pkt
}
