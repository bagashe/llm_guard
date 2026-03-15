package safety

import (
	"net"
	"strings"
)

// NormalizeHost normalizes a host string (domain or IP) to a canonical form.
// IPs are canonicalized via net.ParseIP (e.g. IPv6 zero-compression).
// Domains are lowercased with trailing dots and "www." prefix stripped.
// Returns "" for invalid or empty input.
func NormalizeHost(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.Trim(v, "[]")
	v = strings.TrimSuffix(v, ".")
	if v == "" {
		return ""
	}
	if ip := net.ParseIP(v); ip != nil {
		return ip.String()
	}
	if strings.ContainsAny(v, " /\\") {
		return ""
	}
	if !strings.Contains(v, ".") {
		return ""
	}
	return v
}
