package rules

import (
	"context"
	"fmt"
	"math"
	"regexp"

	"llm_guard/internal/safety"
)

type secretPattern struct {
	name  string
	regex *regexp.Regexp
}

type SecretLeakRule struct {
	patterns       []secretPattern
	candidateRegex *regexp.Regexp
}

func NewSecretLeakRule() safety.Rule {
	raw := []struct {
		name    string
		pattern string
	}{
		{"AWS access key", `AKIA[0-9A-Z]{16}`},
		{"AWS secret key", `(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*[A-Za-z0-9/+=]{40}`},
		{"GitHub token", `ghp_[A-Za-z0-9]{36}`},
		{"GitHub fine-grained token", `github_pat_[A-Za-z0-9_]{22,}`},
		{"generic API key", `(?i)(api[_-]?key|api[_-]?secret|apikey)\s*[=:]\s*["']?[A-Za-z0-9\-_]{20,}`},
		{"bearer token", `(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}`},
		{"private key", `-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----`},
		{"connection string", `(?i)(mongodb(\+srv)?://|postgres(ql)?://|mysql://|redis://)[^\s]+:[^\s]+@`},
		{"Slack token", `xox[bpras]-[0-9a-zA-Z\-]{10,}`},
		{"Stripe key", `sk_(live|test)_[A-Za-z0-9]{20,}`},
		{"Google API key", `AIza[0-9A-Za-z\-_]{35}`},
	}

	patterns := make([]secretPattern, 0, len(raw))
	for _, r := range raw {
		patterns = append(patterns, secretPattern{
			name:  r.name,
			regex: regexp.MustCompile(r.pattern),
		})
	}

	return &SecretLeakRule{
		patterns:       patterns,
		candidateRegex: regexp.MustCompile(`[A-Za-z0-9+/=_\-]{20,}`),
	}
}

func (r *SecretLeakRule) ID() string {
	return "output.secret_leak"
}

func (r *SecretLeakRule) Evaluate(_ context.Context, in safety.Input) (safety.Match, error) {
	if in.MessageType != safety.MessageTypeAssistant {
		return safety.Match{}, nil
	}

	for _, p := range r.patterns {
		if p.regex.MatchString(in.Message) {
			return safety.Match{
				Matched: true,
				Score:   1.0,
				Reason: safety.Reason{
					RuleID:   "output.secret_leak",
					Severity: "high",
					Detail:   fmt.Sprintf("detected potential %s in output", p.name),
				},
			}, nil
		}
	}

	candidates := r.candidateRegex.FindAllString(in.Message, 100)
	for _, c := range candidates {
		if len(c) >= 20 && shannonEntropy(c) >= 4.5 {
			return safety.Match{
				Matched: true,
				Score:   0.8,
				Reason: safety.Reason{
					RuleID:   "output.secret_leak",
					Severity: "high",
					Detail:   "detected high-entropy string that may be a secret",
				},
			}, nil
		}
	}

	return safety.Match{}, nil
}

func shannonEntropy(s string) float64 {
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// ShannonEntropy exports the entropy function for testing.
func ShannonEntropy(s string) float64 {
	return shannonEntropy(s)
}
