package safety

import (
	"context"
	"testing"
)

type testRule struct {
	match  Match
	err    error
	onEval func()
}

func (r testRule) ID() string {
	return "test.rule"
}

func (r testRule) Evaluate(_ context.Context, _ Input) (Match, error) {
	if r.onEval != nil {
		r.onEval()
	}
	return r.match, r.err
}

func TestEngineHighSeverityForcesUnsafe(t *testing.T) {
	engine := NewEngine(true, 0.70)
	engine.Register(testRule{match: Match{
		Matched: true,
		Score:   0.20,
		Reason: Reason{
			RuleID:   "test.high",
			Severity: "high",
			Detail:   "high severity indicator",
		},
	}})

	res := engine.Evaluate(context.Background(), Input{Message: "hello"})
	if res.Safe {
		t.Fatalf("expected unsafe result for high severity reason; got %+v", res)
	}
}

func TestEngineKeepsSafeForLowSeverityBelowThreshold(t *testing.T) {
	engine := NewEngine(true, 0.70)
	engine.Register(testRule{match: Match{
		Matched: true,
		Score:   0.20,
		Reason: Reason{
			RuleID:   "test.low",
			Severity: "low",
			Detail:   "low severity indicator",
		},
	}})

	res := engine.Evaluate(context.Background(), Input{Message: "hello"})
	if !res.Safe {
		t.Fatalf("expected safe result for low severity below threshold; got %+v", res)
	}
}

func TestEngineHighSeverityIsCaseInsensitive(t *testing.T) {
	engine := NewEngine(true, 0.70)
	engine.Register(testRule{match: Match{
		Matched: true,
		Score:   0.10,
		Reason: Reason{
			RuleID:   "test.high.upper",
			Severity: "HIGH",
			Detail:   "uppercase severity",
		},
	}})

	res := engine.Evaluate(context.Background(), Input{Message: "hello"})
	if res.Safe {
		t.Fatalf("expected unsafe result for uppercase high severity; got %+v", res)
	}
}

func TestEngineClampsRiskScoreAndThreshold(t *testing.T) {
	engine := NewEngine(true, 2.5)
	engine.Register(testRule{match: Match{
		Matched: true,
		Score:   0.60,
		Reason: Reason{
			RuleID:   "test.one",
			Severity: "medium",
			Detail:   "first signal",
		},
	}})
	engine.Register(testRule{match: Match{
		Matched: true,
		Score:   0.70,
		Reason: Reason{
			RuleID:   "test.two",
			Severity: "low",
			Detail:   "second signal",
		},
	}})

	res := engine.Evaluate(context.Background(), Input{Message: "hello"})
	if res.RiskScore != 1.0 {
		t.Fatalf("expected clamped risk score 1.0, got %f", res.RiskScore)
	}
	if res.Safe {
		t.Fatalf("expected unsafe result with clamped threshold and score; got %+v", res)
	}
}

func TestEngineShortCircuitsOnCountryBlock(t *testing.T) {
	engine := NewEngine(true, 0.70)
	called := 0
	engine.Register(testRule{match: Match{
		Matched: true,
		Score:   1.0,
		Reason: Reason{
			RuleID:   "country_blacklist.blocked_country",
			Severity: "high",
			Detail:   "request country is blacklisted",
		},
	}})
	engine.Register(testRule{onEval: func() { called++ }})

	res := engine.Evaluate(context.Background(), Input{Message: "hello"})
	if res.Safe {
		t.Fatalf("expected unsafe result for country block; got %+v", res)
	}
	if called != 0 {
		t.Fatalf("expected classifier-like rule to be skipped after country block, called=%d", called)
	}
}
