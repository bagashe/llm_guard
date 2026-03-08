package rules

import (
	"context"
	"strings"

	"llm_guard/internal/safety"
)

type keywordRule struct {
	id       string
	severity string
	detail   string
	score    float64
	phrases  []string
}

func (r keywordRule) ID() string {
	return r.id
}

func (r keywordRule) Evaluate(_ context.Context, in safety.Input) (safety.Match, error) {
	msg := strings.ToLower(in.Message)
	for _, phrase := range r.phrases {
		if strings.Contains(msg, phrase) {
			return safety.Match{
				Matched: true,
				Score:   r.score,
				Reason: safety.Reason{
					RuleID:   r.id,
					Severity: r.severity,
					Detail:   r.detail,
				},
			}, nil
		}
	}

	return safety.Match{}, nil
}

func NewPromptInjectionRule() safety.Rule {
	return keywordRule{
		id:       "prompt_injection.override_instructions",
		severity: "high",
		detail:   "detected prompt-injection override pattern",
		score:    0.55,
		phrases: []string{
			"ignore previous instructions",
			"ignore all previous",
			"system prompt",
			"reveal your hidden instructions",
			"developer instructions",
			"jailbreak",
		},
	}
}

func NewExfiltrationRule() safety.Rule {
	return keywordRule{
		id:       "data_exfiltration.secrets_request",
		severity: "high",
		detail:   "detected secret extraction pattern",
		score:    0.60,
		phrases: []string{
			"print env",
			"environment variables",
			"ssh private key",
			"api key",
			"database password",
			"cat /etc/passwd",
		},
	}
}

func NewHostTakeoverRule() safety.Rule {
	return keywordRule{
		id:       "host_takeover.command_execution",
		severity: "high",
		detail:   "detected command execution or takeover pattern",
		score:    0.65,
		phrases: []string{
			"run this shell command",
			"sudo rm -rf",
			"download and execute",
			"reverse shell",
			"powershell -enc",
		},
	}
}
