package rules

import (
	"context"
	"regexp"
	"strings"

	"llm_guard/internal/safety"
)

type SystemPromptLeakRule struct {
	patterns []*regexp.Regexp
}

func NewSystemPromptLeakRule() safety.Rule {
	raw := []string{
		`my\s+(system\s+)?instructions?\s+(are|say|tell|state|include)`,
		`as\s+(stated\s+)?in\s+my\s+(system\s+)?(prompt|instructions?)`,
		`here\s+(are|is)\s+my\s+(system\s+)?(prompt|instructions?)`,
		`my\s+system\s+prompt\s+(is|reads|says|states)`,
		`i\s+(was|am)\s+(instructed|told|programmed)\s+to\s+(never|always|not)`,
		`do\s+not\s+reveal\s+(these|this|my|your)\s+(instructions?|prompt)`,
		`you\s+are\s+a\s+helpful\s+assistant`,
		`\[system\s*(prompt|message|instructions?)\]`,
		`<<\s*system\s*>>`,
		`###\s*system\s*(prompt|instructions?)`,
		`internal\s+(instructions?|guidelines?|rules?|policy)\s*:`,
	}
	patterns := make([]*regexp.Regexp, 0, len(raw))
	for _, r := range raw {
		patterns = append(patterns, regexp.MustCompile(`(?i)`+r))
	}
	return &SystemPromptLeakRule{patterns: patterns}
}

func (r *SystemPromptLeakRule) ID() string {
	return "output.system_prompt_leak"
}

func (r *SystemPromptLeakRule) Evaluate(_ context.Context, in safety.Input) (safety.Match, error) {
	if in.MessageType != safety.MessageTypeAssistant {
		return safety.Match{}, nil
	}

	lower := strings.ToLower(in.Message)
	for _, p := range r.patterns {
		if p.MatchString(lower) {
			return safety.Match{
				Matched: true,
				Score:   0.9,
				Reason: safety.Reason{
					RuleID:   "output.system_prompt_leak",
					Severity: "high",
					Detail:   "response may contain leaked system prompt or internal instructions",
				},
			}, nil
		}
	}

	return safety.Match{}, nil
}
