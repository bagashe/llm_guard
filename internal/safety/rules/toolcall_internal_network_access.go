package rules

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"llm_guard/internal/safety"
)

type ToolCallInternalNetworkAccessRule struct {
	allowedDomains map[string]struct{}
	allowedIPs     map[string]struct{}
	allowedCIDRs   []*net.IPNet
	dnsTimeout     time.Duration
}

func NewToolCallInternalNetworkAccessRule(allowedDomains map[string]struct{}, allowedIPs map[string]struct{}, allowedCIDRs []*net.IPNet) safety.Rule {
	domains := make(map[string]struct{}, len(allowedDomains))
	for d := range allowedDomains {
		if normalized := normalizeHost(d); normalized != "" {
			domains[normalized] = struct{}{}
		}
	}

	ips := make(map[string]struct{}, len(allowedIPs))
	for ipStr := range allowedIPs {
		if ip := net.ParseIP(strings.TrimSpace(ipStr)); ip != nil {
			ips[ip.String()] = struct{}{}
		}
	}

	return ToolCallInternalNetworkAccessRule{
		allowedDomains: domains,
		allowedIPs:     ips,
		allowedCIDRs:   allowedCIDRs,
		dnsTimeout:     2 * time.Second,
	}
}

func (r ToolCallInternalNetworkAccessRule) ID() string {
	return "tool_call.internal_network_access"
}

func (r ToolCallInternalNetworkAccessRule) Evaluate(ctx context.Context, in safety.Input) (safety.Match, error) {
	if in.MessageType != safety.MessageTypeToolCall {
		return safety.Match{}, nil
	}

	hosts := extractToolCallHosts(in.Message)
	if len(hosts) == 0 {
		return safety.Match{}, nil
	}

	blocked := make([]string, 0)
	for _, host := range hosts {
		if isAllowlistedHost(host, r.allowedDomains, r.allowedIPs, r.allowedCIDRs) {
			continue
		}
		if isInternalOrLocalHost(host) {
			blocked = append(blocked, host)
			continue
		}
		internal, err := resolvesToInternalOrLocal(ctx, host, r.dnsTimeout)
		if err != nil {
			continue
		}
		if internal {
			blocked = append(blocked, host)
		}
	}

	if len(blocked) == 0 {
		return safety.Match{}, nil
	}

	sort.Strings(blocked)
	blocked = compactSortedStrings(blocked)

	return safety.Match{
		Matched: true,
		Score:   1.0,
		Reason: safety.Reason{
			RuleID:   r.ID(),
			Severity: "high",
			Detail:   fmt.Sprintf("tool call targets internal/local destination(s): %s", strings.Join(blocked, ",")),
		},
	}, nil
}
