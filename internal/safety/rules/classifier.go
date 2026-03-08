package rules

import (
	"context"
	"fmt"
	"strings"

	"llm_guard/internal/classifier"
	"llm_guard/internal/safety"
)

type ClassifierRule struct {
	model *classifier.Model
}

func NewClassifierRule(model *classifier.Model) safety.Rule {
	return ClassifierRule{model: model}
}

func (r ClassifierRule) ID() string {
	return "classifier.malicious_intent"
}

func (r ClassifierRule) Evaluate(_ context.Context, in safety.Input) (safety.Match, error) {
	if r.model == nil {
		return safety.Match{}, nil
	}

	preds := r.model.Predict(in.Message)
	flagged := make([]string, 0)
	maxScore := 0.0
	for _, pred := range preds {
		if pred.Score > maxScore {
			maxScore = pred.Score
		}
		threshold := r.model.Thresholds[pred.Label]
		if pred.Score >= threshold {
			flagged = append(flagged, fmt.Sprintf("%s=%.3f", pred.Label, pred.Score))
		}
	}

	if len(flagged) == 0 {
		return safety.Match{}, nil
	}

	return safety.Match{
		Matched: true,
		Score:   maxScore,
		Reason: safety.Reason{
			RuleID:   "classifier.malicious_intent",
			Severity: "high",
			Detail:   "classifier flagged labels: " + strings.Join(flagged, ","),
		},
	}, nil
}
