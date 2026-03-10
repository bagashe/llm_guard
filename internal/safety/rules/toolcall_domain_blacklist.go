package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"llm_guard/internal/safety"
)

type ToolCallDomainBlacklistRule struct {
	blocked         map[string]struct{}
	domainFinder    *regexp.Regexp
	minDomainPrefix int
}

func NewToolCallDomainBlacklistRule(blocked map[string]struct{}) safety.Rule {
	normalized := make(map[string]struct{}, len(blocked))
	for domain := range blocked {
		d := normalizeDomain(domain)
		if d != "" {
			normalized[d] = struct{}{}
		}
	}

	return ToolCallDomainBlacklistRule{
		blocked:      normalized,
		domainFinder:    regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)\b`),
		minDomainPrefix: 5,
	}
}

func (r ToolCallDomainBlacklistRule) ID() string {
	return "tool_call.domain_blacklist"
}

func (r ToolCallDomainBlacklistRule) Evaluate(_ context.Context, in safety.Input) (safety.Match, error) {
	if in.MessageType != safety.MessageTypeToolCall || len(r.blocked) == 0 {
		return safety.Match{}, nil
	}

	domains := extractDomainsFromToolCallPayload(in.Message, r.domainFinder, r.minDomainPrefix)
	if len(domains) == 0 {
		return safety.Match{}, nil
	}

	matched := make([]string, 0, 1)
	for _, d := range domains {
		if isBlockedDomain(d, r.blocked) {
			matched = append(matched, d)
		}
	}
	if len(matched) == 0 {
		return safety.Match{}, nil
	}

	sort.Strings(matched)
	matched = compactSortedStrings(matched)

	return safety.Match{
		Matched: true,
		Score:   1.0,
		Reason: safety.Reason{
			RuleID:   r.ID(),
			Severity: "high",
			Detail:   fmt.Sprintf("tool call references blacklisted domain(s): %s", strings.Join(matched, ",")),
		},
	}, nil
}

func extractDomainsFromToolCallPayload(message string, finder *regexp.Regexp, minPrefix int) []string {
	message = strings.TrimSpace(message)
	if message == "" {
		return nil
	}

	var payload any
	if err := json.Unmarshal([]byte(message), &payload); err == nil {
		collector := make([]string, 0)
		collectDomainsFromAny(payload, finder, minPrefix, &collector)
		return normalizeDomainList(collector)
	}

	return normalizeDomainList(extractDomainsFromString(message, finder, minPrefix))
}

func collectDomainsFromAny(v any, finder *regexp.Regexp, minPrefix int, out *[]string) {
	switch typed := v.(type) {
	case map[string]any:
		for _, child := range typed {
			collectDomainsFromAny(child, finder, minPrefix, out)
		}
	case []any:
		for _, child := range typed {
			collectDomainsFromAny(child, finder, minPrefix, out)
		}
	case string:
		*out = append(*out, extractDomainsFromString(typed, finder, minPrefix)...)
	}
}

func extractDomainsFromString(s string, finder *regexp.Regexp, minPrefix int) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	results := make([]string, 0)
	if u, err := url.Parse(s); err == nil {
		if host := normalizeDomain(u.Hostname()); host != "" {
			results = append(results, host)
		}
	}

	matches := finder.FindAllStringSubmatch(s, 100)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		d := m[1]
		if minPrefix > 0 && domainPrefixLen(d) < minPrefix {
			continue
		}
		results = append(results, d)
	}

	return results
}

// domainPrefixLen returns the length of the domain excluding the final TLD segment.
// e.g. "login.evil.com" → len("login.evil") = 10, "evil.com" → len("evil") = 4
func domainPrefixLen(d string) int {
	i := strings.LastIndex(d, ".")
	if i < 0 {
		return len(d)
	}
	return i
}

func normalizeDomainList(domains []string) []string {
	normalized := make([]string, 0, len(domains))
	for _, d := range domains {
		if n := normalizeDomain(d); n != "" {
			normalized = append(normalized, n)
		}
	}
	sort.Strings(normalized)
	return compactSortedStrings(normalized)
}

func compactSortedStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:1]
	for _, v := range in[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

func normalizeDomain(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimSuffix(v, ".")
	v = strings.TrimPrefix(v, "www.")
	if v == "" {
		return ""
	}
	if ip := net.ParseIP(v); ip != nil {
		return ""
	}
	if !strings.Contains(v, ".") {
		return ""
	}
	return v
}

func isBlockedDomain(candidate string, blocked map[string]struct{}) bool {
	// Walk up parent domains: "a.b.evil.com" checks "a.b.evil.com", "b.evil.com", "evil.com"
	for d := candidate; d != ""; {
		if _, ok := blocked[d]; ok {
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
