package rules

import (
	"context"
	"strings"
	"testing"

	"llm_guard/internal/safety"
)

func TestToolCallInternalNetworkAccessRule(t *testing.T) {
	rule := NewToolCallInternalNetworkAccessRule(nil, nil, nil)

	tests := []struct {
		name       string
		message    string
		wantMatch  bool
		wantDetail string
	}{
		{
			name:       "blocks loopback ip url",
			message:    `{"tool":"browser.open","arguments":{"url":"http://127.0.0.1:8080"}}`,
			wantMatch:  true,
			wantDetail: "127.0.0.1",
		},
		{
			name:       "blocks localhost host",
			message:    `{"tool":"browser.open","arguments":{"url":"http://localhost:3000"}}`,
			wantMatch:  true,
			wantDetail: "localhost",
		},
		{
			name:       "blocks rfc1918 private ip",
			message:    `{"tool":"browser.open","arguments":{"url":"http://10.0.0.1/admin"}}`,
			wantMatch:  true,
			wantDetail: "10.0.0.1",
		},
		{
			name:      "allows public host",
			message:   `{"tool":"browser.open","arguments":{"url":"https://example.com"}}`,
			wantMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match, err := rule.Evaluate(context.Background(), safety.Input{MessageType: safety.MessageTypeToolCall, Message: tc.message})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if match.Matched != tc.wantMatch {
				t.Fatalf("matched=%v want=%v", match.Matched, tc.wantMatch)
			}
			if !tc.wantMatch {
				return
			}
			if match.Reason.RuleID != "tool_call.internal_network_access" {
				t.Fatalf("unexpected rule id: %s", match.Reason.RuleID)
			}
			if !strings.Contains(match.Reason.Detail, tc.wantDetail) {
				t.Fatalf("expected detail to contain %q, got %q", tc.wantDetail, match.Reason.Detail)
			}
		})
	}
}

func TestToolCallInternalNetworkAccessRuleAllowlist(t *testing.T) {
	rule := NewToolCallInternalNetworkAccessRule(map[string]struct{}{"internal.local": {}}, map[string]struct{}{"127.0.0.1": {}}, nil)

	match, err := rule.Evaluate(context.Background(), safety.Input{
		MessageType: safety.MessageTypeToolCall,
		Message:     `{"tool":"browser.open","arguments":{"url":"http://127.0.0.1:8080","backup":"http://api.internal.local:9000"}}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match.Matched {
		t.Fatalf("expected allowlisted internal destinations to pass, got %+v", match)
	}
}
