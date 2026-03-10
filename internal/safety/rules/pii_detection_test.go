package rules

import (
	"context"
	"strings"
	"testing"

	"llm_guard/internal/safety"
)

func TestPIIDetectionRule(t *testing.T) {
	rule := NewPIIDetectionRule()

	tests := []struct {
		name         string
		message      string
		messageType  safety.MessageType
		wantMatch    bool
		wantScore    float64
		wantContains []string
	}{
		{
			name:         "detects email",
			message:      "Reach me at jane.doe@example.com for follow up.",
			messageType:  safety.MessageTypeUser,
			wantMatch:    true,
			wantScore:    0.25,
			wantContains: []string{"email"},
		},
		{
			name:         "detects ssn",
			message:      "My SSN is 123-45-6789.",
			messageType:  safety.MessageTypeUser,
			wantMatch:    true,
			wantScore:    0.25,
			wantContains: []string{"ssn"},
		},
		{
			name:         "detects credit card with luhn",
			message:      "Use card 4111 1111 1111 1111 for this test flow.",
			messageType:  safety.MessageTypeUser,
			wantMatch:    true,
			wantScore:    0.25,
			wantContains: []string{"credit_card"},
		},
		{
			name:         "detects phone",
			message:      "Call me at (415) 555-2671 tomorrow.",
			messageType:  safety.MessageTypeUser,
			wantMatch:    true,
			wantScore:    0.25,
			wantContains: []string{"phone"},
		},
		{
			name:        "scales score with multiple categories and caps",
			message:     "jane.doe@example.com, SSN 123-45-6789, card 4111 1111 1111 1111, phone (415) 555-2671",
			messageType: safety.MessageTypeUser,
			wantMatch:   true,
			wantScore:   0.50,
			wantContains: []string{
				"email",
				"ssn",
				"credit_card",
				"phone",
			},
		},
		{
			name:         "scales score with two categories",
			message:      "jane.doe@example.com, SSN 123-45-6789",
			messageType:  safety.MessageTypeUser,
			wantMatch:    true,
			wantScore:    0.35,
			wantContains: []string{"email", "ssn"},
		},
		{
			name:         "scales score with three categories",
			message:      "jane.doe@example.com, SSN 123-45-6789, card 4111 1111 1111 1111",
			messageType:  safety.MessageTypeUser,
			wantMatch:    true,
			wantScore:    0.45,
			wantContains: []string{"email", "ssn", "credit_card"},
		},
		{
			name:        "does not match invalid card number",
			message:     "Order number is 4111 1111 1111 1112 and should not be treated as PII.",
			messageType: safety.MessageTypeUser,
			wantMatch:   false,
		},
		{
			name:        "does not match invalid ssn area 000",
			message:     "ID 000-12-3456 is not a valid SSN.",
			messageType: safety.MessageTypeUser,
			wantMatch:   false,
		},
		{
			name:        "does not match invalid ssn area 666",
			message:     "ID 666-12-3456 is not a valid SSN.",
			messageType: safety.MessageTypeUser,
			wantMatch:   false,
		},
		{
			name:        "does not match invalid ssn area 900",
			message:     "ID 900-12-3456 is not a valid SSN.",
			messageType: safety.MessageTypeUser,
			wantMatch:   false,
		},
		{
			name:        "does not match non user messages",
			message:     "You can email me at jane.doe@example.com",
			messageType: safety.MessageTypeAssistant,
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
				t.Fatalf("matched=%v want=%v for message %q", match.Matched, tc.wantMatch, tc.message)
			}
			if !tc.wantMatch {
				return
			}

			if match.Reason.RuleID != "input.pii_detection" {
				t.Fatalf("unexpected rule id: %s", match.Reason.RuleID)
			}
			if match.Reason.Severity != "medium" {
				t.Fatalf("unexpected severity: %s", match.Reason.Severity)
			}
			if match.Score != tc.wantScore {
				t.Fatalf("score=%f want=%f", match.Score, tc.wantScore)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(match.Reason.Detail, want) {
					t.Fatalf("expected detail to contain %q, got %q", want, match.Reason.Detail)
				}
			}
		})
	}
}

func TestIsLuhnValid(t *testing.T) {
	if !isLuhnValid("4111111111111111") {
		t.Fatal("expected known Visa test number to be luhn valid")
	}
	if isLuhnValid("4111111111111112") {
		t.Fatal("expected invalid test number to fail luhn")
	}
}
