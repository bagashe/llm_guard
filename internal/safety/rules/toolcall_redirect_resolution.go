package rules

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"llm_guard/internal/safety"
)

type ToolCallRedirectResolutionRule struct {
	blockedDomains map[string]struct{}
	allowedDomains map[string]struct{}
	allowedIPs     map[string]struct{}
	allowedCIDRs   []*net.IPNet
	maxHops        int
	dnsTimeout     time.Duration
	httpClient     *http.Client
}

func NewToolCallRedirectResolutionRule(blockedDomains map[string]struct{}, allowedDomains map[string]struct{}, allowedIPs map[string]struct{}, allowedCIDRs []*net.IPNet) safety.Rule {
	blocked := make(map[string]struct{}, len(blockedDomains))
	for d := range blockedDomains {
		if normalized := normalizeDomain(d); normalized != "" {
			blocked[normalized] = struct{}{}
		}
	}

	allowedDomainSet := make(map[string]struct{}, len(allowedDomains))
	for d := range allowedDomains {
		if normalized := normalizeHost(d); normalized != "" {
			allowedDomainSet[normalized] = struct{}{}
		}
	}

	allowedIPSet := make(map[string]struct{}, len(allowedIPs))
	for ipStr := range allowedIPs {
		if ip := net.ParseIP(strings.TrimSpace(ipStr)); ip != nil {
			allowedIPSet[ip.String()] = struct{}{}
		}
	}

	return ToolCallRedirectResolutionRule{
		blockedDomains: blocked,
		allowedDomains: allowedDomainSet,
		allowedIPs:     allowedIPSet,
		allowedCIDRs:   allowedCIDRs,
		maxHops:        5,
		dnsTimeout:     2 * time.Second,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (r ToolCallRedirectResolutionRule) ID() string {
	return "tool_call.redirect_resolution"
}

func (r ToolCallRedirectResolutionRule) Evaluate(ctx context.Context, in safety.Input) (safety.Match, error) {
	if in.MessageType != safety.MessageTypeToolCall {
		return safety.Match{}, nil
	}

	urls := extractToolCallURLs(in.Message)
	if len(urls) == 0 {
		return safety.Match{}, nil
	}

	for _, rawURL := range urls {
		violation, detail, err := r.validateURLWithRedirects(ctx, rawURL)
		if err != nil {
			return r.blockMatch(fmt.Sprintf("redirect validation failed for %q: %v", rawURL, err)), nil
		}
		if violation {
			return r.blockMatch(detail), nil
		}
	}

	return safety.Match{}, nil
}

func (r ToolCallRedirectResolutionRule) validateURLWithRedirects(ctx context.Context, raw string) (bool, string, error) {
	current, err := url.Parse(raw)
	if err != nil {
		return false, "", fmt.Errorf("parse url: %w", err)
	}

	for hop := 0; hop <= r.maxHops; hop++ {
		host := normalizeHost(current.Hostname())
		if host == "" {
			return false, "", fmt.Errorf("missing host")
		}

		allowlisted := isAllowlistedHost(host, r.allowedDomains, r.allowedIPs, r.allowedCIDRs)

		if ip := net.ParseIP(host); ip == nil {
			if isBlockedDomain(normalizeDomain(host), r.blockedDomains) {
				return true, fmt.Sprintf("redirect hop %d targets blacklisted domain: %s", hop, host), nil
			}
		}

		if !allowlisted && isInternalOrLocalHost(host) {
			return true, fmt.Sprintf("redirect hop %d targets internal/local host: %s", hop, host), nil
		}

		if !allowlisted {
			internal, err := resolvesToInternalOrLocal(ctx, host, r.dnsTimeout)
			if err != nil {
				return false, "", fmt.Errorf("resolve host %q: %w", host, err)
			}
			if internal {
				return true, fmt.Sprintf("redirect hop %d resolves to internal/local address: %s", hop, host), nil
			}
		}

		if hop == r.maxHops {
			return false, "", fmt.Errorf("max redirect hops exceeded")
		}

		next, redirected, err := r.nextRedirect(ctx, current)
		if err != nil {
			return false, "", err
		}
		if !redirected {
			return false, "", nil
		}
		current = next
	}

	return false, "", nil
}

func (r ToolCallRedirectResolutionRule) nextRedirect(ctx context.Context, current *url.URL) (*url.URL, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
	if err != nil {
		return nil, false, fmt.Errorf("build request: %w", err)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 256)

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return nil, false, nil
	}

	location := strings.TrimSpace(resp.Header.Get("Location"))
	if location == "" {
		return nil, false, fmt.Errorf("redirect response missing location header")
	}

	next, err := current.Parse(location)
	if err != nil {
		return nil, false, fmt.Errorf("parse redirect location: %w", err)
	}
	if next.Scheme != "http" && next.Scheme != "https" {
		return nil, false, fmt.Errorf("unsupported redirect scheme: %s", next.Scheme)
	}

	return next, true, nil
}

func (r ToolCallRedirectResolutionRule) blockMatch(detail string) safety.Match {
	return safety.Match{
		Matched: true,
		Score:   1.0,
		Reason: safety.Reason{
			RuleID:   r.ID(),
			Severity: "high",
			Detail:   detail,
		},
	}
}
