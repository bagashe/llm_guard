package safety

import (
	"net"
	"strings"
)

func IsLoopbackIP(v string) bool {
	ip := net.ParseIP(strings.TrimSpace(v))
	return ip != nil && ip.IsLoopback()
}
