package rules

import (
	"context"
	"testing"

	"llm_guard/internal/safety"
)

func TestCountryBlacklistRule(t *testing.T) {
	blocked := map[string]struct{}{"KP": {}}

	t.Run("blocked country", func(t *testing.T) {
		rule := NewCountryBlacklistRule(blocked, true)
		match, err := rule.Evaluate(context.Background(), safety.Input{CountryCode: "KP"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !match.Matched {
			t.Fatal("expected blacklist rule to match")
		}
		if match.Reason.RuleID != "country_blacklist.blocked_country" {
			t.Fatalf("unexpected reason id: %s", match.Reason.RuleID)
		}
	})

	t.Run("unknown country fail closed", func(t *testing.T) {
		rule := NewCountryBlacklistRule(blocked, true)
		match, err := rule.Evaluate(context.Background(), safety.Input{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !match.Matched {
			t.Fatal("expected unknown country to match in fail-closed mode")
		}
		if match.Reason.RuleID != "country_blacklist.unknown_country" {
			t.Fatalf("unexpected reason id: %s", match.Reason.RuleID)
		}
	})

	t.Run("unknown country fail open", func(t *testing.T) {
		rule := NewCountryBlacklistRule(blocked, false)
		match, err := rule.Evaluate(context.Background(), safety.Input{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if match.Matched {
			t.Fatal("did not expect match when unknown country and fail-open")
		}
	})

	t.Run("empty blacklist", func(t *testing.T) {
		rule := NewCountryBlacklistRule(map[string]struct{}{}, true)
		match, err := rule.Evaluate(context.Background(), safety.Input{CountryCode: "KP"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if match.Matched {
			t.Fatal("did not expect match for empty blacklist")
		}
	})

	t.Run("localhost bypasses country blacklist and unknown country", func(t *testing.T) {
		rule := NewCountryBlacklistRule(blocked, true)
		for _, input := range []safety.Input{{ClientIP: "127.0.0.1", CountryCode: "KP"}, {ClientIP: "::1"}} {
			match, err := rule.Evaluate(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if match.Matched {
				t.Fatalf("did not expect match for localhost input: %+v", input)
			}
		}
	})
}
