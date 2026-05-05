package packet

import "encoding/binary"

// internetChecksum computes the standard Internet checksum (RFC 1071).
func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// tcpChecksum computes TCP checksum including the pseudo-header.
func tcpChecksum(srcIP, dstIP []byte, tcpSegment []byte) uint16 {
	pseudo := make([]byte, 12+len(tcpSegment))
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[8] = 0
	pseudo[9] = 6 // TCP protocol number
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcpSegment)))
	copy(pseudo[12:], tcpSegment)
	return internetChecksum(pseudo)
}
