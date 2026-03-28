package rules

import (
	"context"
	"fmt"
	"strings"

	"llm_guard/internal/classifier"
	"llm_guard/internal/safety"
)

// windowWords and strideWords are calibrated to the training data distribution.
// Attack samples sit at p50=43–75 words and p75=76–177 words across all labels.
// A 100-word window matches the p75 of prompt_injection and host_takeover, and
// covers the median exfiltration sample. A 50-word stride (50% overlap) ensures
// any contiguous 50-word span appears fully inside at least one window, so a
// buried attack phrase cannot straddle two window boundaries undetected.
const (
	windowWords = 100
	strideWords = 50
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

// Evaluate runs the ML classifier on user and tool_result messages.
// tool_result is included to catch indirect prompt injection embedded in
// tool outputs (e.g. a fetched webpage containing "ignore all instructions").
// system, assistant, and tool_call messages are skipped.
//
// For messages longer than windowWords, a sliding window is used and the
// maximum score across all windows is returned. This prevents benign context
// surrounding an attack phrase from diluting the classifier score.
func (r ClassifierRule) Evaluate(_ context.Context, in safety.Input) (safety.Match, error) {
	if r.model == nil {
		return safety.Match{}, nil
	}
	if in.MessageType != safety.MessageTypeUser && in.MessageType != safety.MessageTypeToolResult {
		return safety.Match{}, nil
	}

	// Normalize the full text once before windowing. This ensures base64
	// decoding, homoglyph substitution, etc. are applied across the whole
	// message before we slice it into windows.
	text := NormalizeForEvaluation(in.Message)

	words := strings.Fields(text)
	if len(words) == 0 {
		return safety.Match{}, nil
	}

	// Short messages: evaluate in one pass (common case, no overhead).
	if len(words) <= windowWords {
		return r.scoreWindow(words)
	}

	// Long messages: slide a window and return the highest-scoring result.
	var best safety.Match
	for start := 0; start < len(words); start += strideWords {
		end := start + windowWords
		if end > len(words) {
			end = len(words)
		}
		m, err := r.scoreWindow(words[start:end])
		if err != nil {
			return safety.Match{}, err
		}
		if m.Score > best.Score {
			best = m
		}
	}
	return best, nil
}

// scoreWindow runs the classifier on a slice of words and returns a Match if
// any label exceeds its threshold. It calls PredictWords to avoid the
// Join → ToLower → Fields round-trip that Predict would require.
func (r ClassifierRule) scoreWindow(words []string) (safety.Match, error) {
	preds := r.model.PredictWords(words)
	var flagged []string
	maxScore := 0.0
	for _, pred := range preds {
		threshold := r.model.Thresholds[pred.Label]
		if pred.Score >= threshold {
			flagged = append(flagged, fmt.Sprintf("%s=%.3f", pred.Label, pred.Score))
			if pred.Score > maxScore {
				maxScore = pred.Score
			}
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
