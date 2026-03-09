package rules

import (
	"context"
	"strings"
	"testing"

	"llm_guard/internal/safety"
)

func TestSecretLeakRule(t *testing.T) {
	rule := NewSecretLeakRule()

	tests := []struct {
		name        string
		message     string
		messageType safety.MessageType
		wantMatch   bool
		wantDetail  string
	}{
		{
			name:        "AWS access key",
			message:     "Your key is AKIAIOSFODNN7EXAMPLE.",
			messageType: safety.MessageTypeAssistant,
			wantMatch:   true,
			wantDetail:  "AWS access key",
		},
		{
			name:        "GitHub token",
			message:     "Use this token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			messageType: safety.MessageTypeAssistant,
			wantMatch:   true,
			wantDetail:  "GitHub token",
		},
		{
			name:        "private key",
			message:     "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...",
			messageType: safety.MessageTypeAssistant,
			wantMatch:   true,
			wantDetail:  "private key",
		},
		{
			name:        "EC private key",
			message:     "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...",
			messageType: safety.MessageTypeAssistant,
			wantMatch:   true,
			wantDetail:  "private key",
		},
		{
			name:        "generic API key assignment",
			message:     "Set api_key=sk_prod_8fj29dkLmN3pQrStUvWxYz01234567890abc",
			messageType: safety.MessageTypeAssistant,
			wantMatch:   true,
			wantDetail:  "generic API key",
		},
		{
			name:        "bearer token",
			message:     "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
			messageType: safety.MessageTypeAssistant,
			wantMatch:   true,
			wantDetail:  "bearer token",
		},
		{
			name:        "connection string",
			message:     "Use this: postgresql://admin:s3cretP4ss@db.example.com:5432/mydb",
			messageType: safety.MessageTypeAssistant,
			wantMatch:   true,
			wantDetail:  "connection string",
		},
		{
			name:        "Stripe key",
			message:     "Your Stripe key is " + "sk_" + "live_" + "abc123def456ghi789jkl012mno",
			messageType: safety.MessageTypeAssistant,
			wantMatch:   true,
			wantDetail:  "Stripe key",
		},
		{
			name:        "Slack token",
			message:     "Use " + "xoxb" + "-1234567890-abcdefghijklmnop to authenticate.",
			messageType: safety.MessageTypeAssistant,
			wantMatch:   true,
			wantDetail:  "Slack token",
		},
		{
			name:        "Google API key",
			message:     "The API key is AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
			messageType: safety.MessageTypeAssistant,
			wantMatch:   true,
			wantDetail:  "Google API key",
		},
		{
			name:        "benign assistant response",
			message:     "Here is a summary of the quarterly report with three key takeaways.",
			messageType: safety.MessageTypeAssistant,
			wantMatch:   false,
		},
		{
			name:        "user message with secret skipped",
			message:     "My API key is AKIAIOSFODNN7EXAMPLE, is it leaked?",
			messageType: safety.MessageTypeUser,
			wantMatch:   false,
		},
		{
			name:        "short tokens not flagged",
			message:     "Use code ABC123 for the discount.",
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
			if tc.wantMatch {
				if match.Reason.RuleID != "output.secret_leak" {
					t.Fatalf("unexpected rule id: %s", match.Reason.RuleID)
				}
				if tc.wantDetail != "" && !strings.Contains(match.Reason.Detail, tc.wantDetail) {
					t.Fatalf("expected detail to contain %q, got %q", tc.wantDetail, match.Reason.Detail)
				}
			}
		})
	}
}

func TestSecretLeakRuleEntropyDetection(t *testing.T) {
	rule := NewSecretLeakRule()

	match, err := rule.Evaluate(context.Background(), safety.Input{
		Message:     "The token is aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3x",
		MessageType: safety.MessageTypeAssistant,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match.Matched {
		t.Fatal("expected high-entropy string to be flagged")
	}
	if !strings.Contains(match.Reason.Detail, "high-entropy") {
		t.Fatalf("expected entropy-based detection, got: %s", match.Reason.Detail)
	}
}

func TestShannonEntropy(t *testing.T) {
	low := ShannonEntropy("aaaaaaaaaaaaaaaaaaaaaa")
	if low > 1.0 {
		t.Fatalf("expected low entropy for repeated chars, got %f", low)
	}

	high := ShannonEntropy("aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3x")
	if high < 4.0 {
		t.Fatalf("expected high entropy for mixed chars, got %f", high)
	}
}
