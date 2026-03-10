package rules

import (
	"context"

	"llm_guard/internal/safety"
)

type CountryBlacklistRule struct {
	blocked       map[string]struct{}
	failOnUnknown bool
}

func NewCountryBlacklistRule(blocked map[string]struct{}, failOnUnknown bool) safety.Rule {
	return CountryBlacklistRule{blocked: blocked, failOnUnknown: failOnUnknown}
}

func (r CountryBlacklistRule) ID() string {
	return "country_blacklist.blocked_country"
}

func (r CountryBlacklistRule) Evaluate(_ context.Context, in safety.Input) (safety.Match, error) {
	if len(r.blocked) == 0 {
		return safety.Match{}, nil
	}

	if safety.IsPrivateOrLocalIP(in.ClientIP) {
		return safety.Match{}, nil
	}

	if in.CountryCode == "" {
		if r.failOnUnknown {
			return safety.Match{
				Matched: true,
				Score:   1.0,
				Reason: safety.Reason{
					RuleID:   "country_blacklist.unknown_country",
					Severity: "high",
					Detail:   "country could not be resolved from client ip",
				},
			}, nil
		}
		return safety.Match{}, nil
	}

	if _, ok := r.blocked[in.CountryCode]; ok {
		return safety.Match{
			Matched: true,
			Score:   1.0,
			Reason: safety.Reason{
				RuleID:   "country_blacklist.blocked_country",
				Severity: "high",
				Detail:   "request country is blacklisted",
			},
		}, nil
	}

	return safety.Match{}, nil
}
