package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"llm_guard/internal/safety"
)

func TestToolCallRedirectResolutionRule(t *testing.T) {
	t.Run("blocks redirect to blacklisted domain", func(t *testing.T) {
		redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://login.evil.com/path", http.StatusFound)
		}))
		defer redirectSrv.Close()

		rule := NewToolCallRedirectResolutionRule(
			map[string]struct{}{"evil.com": {}},
			nil,
			map[string]struct{}{"127.0.0.1": {}},
			nil,
		)

		match, err := rule.Evaluate(context.Background(), safety.Input{
			MessageType: safety.MessageTypeToolCall,
			Message:     `{"tool":"browser.open","arguments":{"url":"` + redirectSrv.URL + `"}}`,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !match.Matched {
			t.Fatalf("expected redirect to blacklisted domain to match")
		}
		if match.Reason.RuleID != "tool_call.redirect_resolution" {
			t.Fatalf("unexpected rule id: %s", match.Reason.RuleID)
		}
		if !strings.Contains(match.Reason.Detail, "blacklisted host") {
			t.Fatalf("unexpected detail: %s", match.Reason.Detail)
		}
	})

	t.Run("blocks redirect to blacklisted ip", func(t *testing.T) {
		redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://12.12.12.12/path", http.StatusFound)
		}))
		defer redirectSrv.Close()

		rule := NewToolCallRedirectResolutionRule(
			map[string]struct{}{"12.12.12.12": {}},
			nil,
			map[string]struct{}{"127.0.0.1": {}},
			nil,
		)

		match, err := rule.Evaluate(context.Background(), safety.Input{
			MessageType: safety.MessageTypeToolCall,
			Message:     `{"tool":"browser.open","arguments":{"url":"` + redirectSrv.URL + `"}}`,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !match.Matched {
			t.Fatalf("expected redirect to blacklisted ip to match")
		}
		if !strings.Contains(match.Reason.Detail, "12.12.12.12") {
			t.Fatalf("unexpected detail: %s", match.Reason.Detail)
		}
	})

	t.Run("fails closed on redirect resolution error", func(t *testing.T) {
		rule := NewToolCallRedirectResolutionRule(nil, nil, nil, nil)

		match, err := rule.Evaluate(context.Background(), safety.Input{
			MessageType: safety.MessageTypeToolCall,
			Message:     `{"tool":"browser.open","arguments":{"url":"http://nonexistent-hostname.invalid/path"}}`,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !match.Matched {
			t.Fatalf("expected fail-closed redirect resolution match")
		}
		if match.Reason.RuleID != "tool_call.redirect_resolution" {
			t.Fatalf("unexpected rule id: %s", match.Reason.RuleID)
		}
		if !strings.Contains(match.Reason.Detail, "redirect validation failed") {
			t.Fatalf("unexpected detail: %s", match.Reason.Detail)
		}
	})
}
