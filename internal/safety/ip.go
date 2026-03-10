package safety

import (
	"net"
	"strings"
)

func IsLoopbackIP(v string) bool {
	ip := net.ParseIP(strings.TrimSpace(v))
	return ip != nil && ip.IsLoopback()
}

// IsPrivateOrLocalIP returns true for loopback, private (RFC 1918),
// link-local, and unspecified addresses — IPs that should skip GeoIP lookup.
func IsPrivateOrLocalIP(v string) bool {
	ip := net.ParseIP(strings.TrimSpace(v))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
