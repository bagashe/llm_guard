package rules

import (
	"context"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"llm_guard/internal/safety"
)

var httpURLFinder = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)

func extractToolCallURLs(message string) []string {
	values := collectStringsFromPayload(message)
	if len(values) == 0 {
		return nil
	}

	set := make(map[string]struct{}, len(values))
	for _, s := range values {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if u := parseHTTPURL(s); u != "" {
			set[u] = struct{}{}
		}
		for _, match := range httpURLFinder.FindAllString(s, 20) {
			if u := parseHTTPURL(match); u != "" {
				set[u] = struct{}{}
			}
		}
	}

	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func extractToolCallHosts(message string) []string {
	values := collectStringsFromPayload(message)
	if len(values) == 0 {
		return nil
	}

	set := make(map[string]struct{}, len(values))
	for _, s := range values {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		if h := normalizeHost(s); h != "" {
			set[h] = struct{}{}
		}

		if u := parseHTTPURL(s); u != "" {
			if parsed, err := url.Parse(u); err == nil {
				if h := normalizeHost(parsed.Hostname()); h != "" {
					set[h] = struct{}{}
				}
			}
		}

		for _, m := range httpURLFinder.FindAllString(s, 20) {
			if parsed, err := url.Parse(m); err == nil {
				if h := normalizeHost(parsed.Hostname()); h != "" {
					set[h] = struct{}{}
				}
			}
		}
	}

	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func parseHTTPURL(v string) string {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if strings.TrimSpace(u.Hostname()) == "" {
		return ""
	}
	return u.String()
}

func normalizeHost(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.Trim(v, "[]")
	v = strings.TrimSuffix(v, ".")
	if v == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(v); err == nil {
		v = strings.TrimSpace(strings.ToLower(host))
	}
	v = strings.TrimSuffix(v, ".")
	if v == "" {
		return ""
	}
	if strings.ContainsAny(v, " /\\") {
		return ""
	}
	return v
}

func isAllowlistedHost(host string, domains map[string]struct{}, ips map[string]struct{}, cidrs []*net.IPNet) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}

	if ip := net.ParseIP(host); ip != nil {
		if _, ok := ips[ip.String()]; ok {
			return true
		}
		for _, cidr := range cidrs {
			if cidr.Contains(ip) {
				return true
			}
		}
		return false
	}

	for d := host; d != ""; {
		if _, ok := domains[d]; ok {
			return true
		}
		i := strings.Index(d, ".")
		if i < 0 {
			break
		}
		d = d[i+1:]
	}

	return false
}

func isInternalOrLocalHost(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return safety.IsPrivateOrLocalIP(ip.String())
	}
	return false
}

func resolvesToInternalOrLocal(ctx context.Context, host string, timeout time.Duration) (bool, error) {
	host = normalizeHost(host)
	if host == "" {
		return false, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return safety.IsPrivateOrLocalIP(ip.String()), nil
	}

	rCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(rCtx, host)
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		if safety.IsPrivateOrLocalIP(addr.IP.String()) {
			return true, nil
		}
	}
	return false, nil
}
