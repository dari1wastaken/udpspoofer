package netutil

import (
	"encoding/binary"
	"net"
)

// IPv4ToUint32 converts a 4-byte IPv4 net.IP into a big-endian uint32.
// Caller must ensure ip is exactly 4 bytes (e.g. ip = ip.To4()).
func IPv4ToUint32(ip4 net.IP) uint32 {
	return binary.BigEndian.Uint32(ip4)
}

type Packet struct {
	Timestamp int64
	Flush     bool `default:"false"`
}

type IpPacket struct {
	Packet
	SrcIP, DstIP uint32
	IHL          uint8
	TOS          uint8
	Length       uint16
	IpId         uint16
	Flags        uint8
	FragOffset   uint16
	TTL          uint8
	Protocol     uint8
	Checksum     uint16
}

type TcpPacket struct {
	IpPacket
	SrcPort, DstPort                           uint16
	Seq                                        uint32
	Ack                                        uint32
	DataOffset                                 uint8
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	Window                                     uint16
	TCPChecksum                                uint16
	Urgent                                     uint16
	Options                                    string
	Payload                                    string
}

type UdpPacket struct {
	IpPacket
	SrcPort, DstPort uint16
	UDPLength        uint16
	UDPChecksum      uint16
	Payload          string
}
