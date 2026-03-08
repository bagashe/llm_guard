package safety

import (
	"context"
	"strings"
)

type Input struct {
	Message     string
	ClientIP    string
	CountryCode string
}

type Reason struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type Match struct {
	Matched bool
	Score   float64
	Reason  Reason
}

type Rule interface {
	ID() string
	Evaluate(ctx context.Context, in Input) (Match, error)
}

type Result struct {
	Safe      bool     `json:"safe"`
	Reasons   []Reason `json:"reasons"`
	RiskScore float64  `json:"risk_score"`
}

type Engine struct {
	rules         []Rule
	failClosed    bool
	riskThreshold float64
}

func NewEngine(failClosed bool, riskThreshold float64) *Engine {
	if riskThreshold < 0 {
		riskThreshold = 0
	}
	if riskThreshold > 1 {
		riskThreshold = 1
	}
	return &Engine{failClosed: failClosed, riskThreshold: riskThreshold}
}

func (e *Engine) Register(rule Rule) {
	e.rules = append(e.rules, rule)
}

func (e *Engine) Evaluate(ctx context.Context, in Input) Result {
	result := Result{Safe: true, Reasons: make([]Reason, 0)}
	hasHighSeverity := false

	for _, rule := range e.rules {
		match, err := rule.Evaluate(ctx, in)
		if err != nil {
			if e.failClosed {
				result.Safe = false
				result.RiskScore = 1.0
				result.Reasons = append(result.Reasons, Reason{
					RuleID:   "engine.rule_error",
					Severity: "high",
					Detail:   "rule evaluation failed",
				})
				return result
			}
			continue
		}

		if !match.Matched {
			continue
		}

		result.Reasons = append(result.Reasons, match.Reason)
		result.RiskScore += match.Score
		if isTerminalCountryBlock(match.Reason.RuleID) {
			result.Safe = false
			if result.RiskScore < 0 {
				result.RiskScore = 0
			}
			if result.RiskScore > 1 {
				result.RiskScore = 1
			}
			return result
		}
		if strings.EqualFold(strings.TrimSpace(match.Reason.Severity), "high") {
			hasHighSeverity = true
		}
	}

	if result.RiskScore < 0 {
		result.RiskScore = 0
	}
	if result.RiskScore > 1 {
		result.RiskScore = 1
	}

	if hasHighSeverity || result.RiskScore >= e.riskThreshold {
		result.Safe = false
	}

	return result
}

func isTerminalCountryBlock(ruleID string) bool {
	return ruleID == "country_blacklist.blocked_country" || ruleID == "country_blacklist.unknown_country"
}
