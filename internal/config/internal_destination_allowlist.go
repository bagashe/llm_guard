package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

type InternalDestinationAllowlist struct {
	Domains map[string]struct{}
	IPs     map[string]struct{}
	CIDRs   []*net.IPNet
}

func LoadInternalDestinationAllowlist(path string) (InternalDestinationAllowlist, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return InternalDestinationAllowlist{}, fmt.Errorf("internal destination allowlist path is required")
	}

	f, err := os.Open(path)
	if err != nil {
		return InternalDestinationAllowlist{}, fmt.Errorf("open internal destination allowlist file: %w", err)
	}
	defer f.Close()

	out := InternalDestinationAllowlist{
		Domains: map[string]struct{}{},
		IPs:     map[string]struct{}{},
		CIDRs:   make([]*net.IPNet, 0),
	}

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := normalizeAllowlistLine(scanner.Text())
		if line == "" {
			continue
		}

		if _, cidr, err := net.ParseCIDR(line); err == nil {
			out.CIDRs = append(out.CIDRs, cidr)
			continue
		}

		if ip := net.ParseIP(line); ip != nil {
			out.IPs[ip.String()] = struct{}{}
			continue
		}

		if !isPlausibleAllowlistHost(line) {
			return InternalDestinationAllowlist{}, fmt.Errorf("invalid allowlist entry at line %d: %q", lineNo, line)
		}
		out.Domains[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return InternalDestinationAllowlist{}, fmt.Errorf("read internal destination allowlist file: %w", err)
	}

	return out, nil
}

func normalizeAllowlistLine(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "#") {
		return ""
	}
	if i := strings.Index(v, "#"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, ".")
	v = strings.TrimSuffix(v, ".")
	return v
}

func isPlausibleAllowlistHost(v string) bool {
	if v == "" || strings.Contains(v, " ") {
		return false
	}
	for _, p := range strings.Split(v, ".") {
		if p == "" {
			return false
		}
		for i, r := range p {
			isAlphaNum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			if r == '-' {
				if i == 0 || i == len(p)-1 {
					return false
				}
				continue
			}
			if !isAlphaNum {
				return false
			}
		}
	}
	return true
}
