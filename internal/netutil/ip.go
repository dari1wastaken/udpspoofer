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
