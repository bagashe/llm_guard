package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"llm_guard/internal/safety"
)

func LoadDomainBlacklist(path string) (map[string]struct{}, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("domain blacklist path is required")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open domain blacklist file: %w", err)
	}
	defer f.Close()

	blocked := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := normalizeDomainBlacklistLine(scanner.Text())
		if line == "" {
			continue
		}
		normalized := safety.NormalizeHost(line)
		if normalized == "" {
			return nil, fmt.Errorf("invalid host in blacklist at line %d: %q", lineNo, line)
		}
		blocked[normalized] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read domain blacklist file: %w", err)
	}

	return blocked, nil
}

func normalizeDomainBlacklistLine(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "#") {
		return ""
	}
	if i := strings.Index(v, "#"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	v = strings.TrimPrefix(strings.ToLower(v), "www.")
	v = strings.TrimSuffix(v, ".")
	return strings.TrimSpace(v)
}

func isPlausibleDomain(v string) bool {
	if strings.Contains(v, " ") || !strings.Contains(v, ".") {
		return false
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
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
