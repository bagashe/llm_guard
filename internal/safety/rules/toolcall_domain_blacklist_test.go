package rules

import (
	"context"
	"strings"
	"testing"

	"llm_guard/internal/safety"
)

func TestToolCallDomainBlacklistRule(t *testing.T) {
	rule := NewToolCallDomainBlacklistRule(map[string]struct{}{
		"evil.com":     {},
		"malware.test": {},
	})

	tests := []struct {
		name        string
		messageType safety.MessageType
		message     string
		wantMatch   bool
		wantDetail  []string
	}{
		{
			name:        "blocks exact domain in url",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"browser.open","arguments":{"url":"https://evil.com/login"}}`,
			wantMatch:   true,
			wantDetail:  []string{"evil.com"},
		},
		{
			name:        "blocks subdomain",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"browser.open","arguments":{"url":"https://cdn.evil.com/assets"}}`,
			wantMatch:   true,
			wantDetail:  []string{"cdn.evil.com"},
		},
		{
			name:        "blocks domain in plain text argument",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"browser.search","arguments":{"query":"visit malware.test now"}}`,
			wantMatch:   true,
			wantDetail:  []string{"malware.test"},
		},
		{
			name:        "allows non-blacklisted domain",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"browser.open","arguments":{"url":"https://example.com"}}`,
			wantMatch:   false,
		},
		{
			name:        "skips non-toolcall messages",
			messageType: safety.MessageTypeUser,
			message:     `{"tool":"browser.open","arguments":{"url":"https://evil.com"}}`,
			wantMatch:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match, err := rule.Evaluate(context.Background(), safety.Input{
				Message:     tc.message,
				MessageType: tc.messageType,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if match.Matched != tc.wantMatch {
				t.Fatalf("matched=%v want=%v", match.Matched, tc.wantMatch)
			}
			if !tc.wantMatch {
				return
			}
			if match.Reason.RuleID != "tool_call.domain_blacklist" {
				t.Fatalf("unexpected rule id: %s", match.Reason.RuleID)
			}
			if match.Reason.Severity != "high" {
				t.Fatalf("unexpected severity: %s", match.Reason.Severity)
			}
			for _, want := range tc.wantDetail {
				if !strings.Contains(match.Reason.Detail, want) {
					t.Fatalf("expected detail to contain %q, got %q", want, match.Reason.Detail)
				}
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	if got := normalizeDomain("WWW.Example.COM."); got != "example.com" {
		t.Fatalf("unexpected normalized domain: %s", got)
	}
	if got := normalizeDomain("127.0.0.1"); got != "" {
		t.Fatalf("expected ip to be ignored, got %q", got)
	}
}
