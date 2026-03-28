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
//
// earlyExitScore: sliding window stops as soon as a window reaches this score.
// Sigmoid asymptotically approaches 1.0, so 0.99 represents very high confidence
// and there is no meaningful gain from scanning further windows.
const (
	windowWords    = 100
	strideWords    = 50
	earlyExitScore = 0.99
)

type ClassifierRule struct {
	models       []*classifier.Model
	allowedTypes map[safety.MessageType]struct{}
	ruleID       string
	toolName     string // when non-empty, skip unless in.ToolName matches
}

// newClassifierRule is the shared internal constructor. ruleID is the rule
// identifier returned in Match.Reason.RuleID. toolName, when non-empty,
// restricts the rule to fire only when in.ToolName matches exactly.
// Nil models are silently dropped.
func newClassifierRule(ruleID string, toolName string, types []safety.MessageType, models ...*classifier.Model) safety.Rule {
	allowed := make(map[safety.MessageType]struct{}, len(types))
	for _, t := range types {
		allowed[t] = struct{}{}
	}
	ms := make([]*classifier.Model, 0, len(models))
	for _, m := range models {
		if m != nil {
			ms = append(ms, m)
		}
	}
	return ClassifierRule{models: ms, allowedTypes: allowed, ruleID: ruleID, toolName: toolName}
}

// NewClassifierRule accepts one or more models (char n-gram, word n-gram, …)
// and scores them as an ensemble. Nil models are silently dropped.
// Fires on user messages only.
func NewClassifierRule(models ...*classifier.Model) safety.Rule {
	return newClassifierRule("classifier.malicious_intent", "",
		[]safety.MessageType{safety.MessageTypeUser}, models...)
}

// NewToolResultClassifierRule builds a classifier rule that fires only on
// tool_result messages produced by the web_extract tool. It is trained on
// web-page-like benign content with injected attack phrases, so it accurately
// distinguishes indirect prompt injection from ordinary web content.
func NewToolResultClassifierRule(models ...*classifier.Model) safety.Rule {
	return newClassifierRule("classifier.tool_result_injection", "web_extract",
		[]safety.MessageType{safety.MessageTypeToolResult}, models...)
}

func (r ClassifierRule) ID() string {
	return r.ruleID
}

// Evaluate runs the ML classifier ensemble on messages matching the rule's
// allowed message types (and optional tool name filter).
//
// For messages longer than windowWords, a sliding window is used and the
// maximum score across all windows is returned. This prevents benign context
// surrounding an attack phrase from diluting the classifier score.
func (r ClassifierRule) Evaluate(_ context.Context, in safety.Input) (safety.Match, error) {
	if len(r.models) == 0 {
		return safety.Match{}, nil
	}
	if _, ok := r.allowedTypes[in.MessageType]; !ok {
		return safety.Match{}, nil
	}
	if r.toolName != "" && in.ToolName != r.toolName {
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
	// Stop early once we reach earlyExitScore — no further windows can improve
	// the decision and remaining work would be wasted.
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
		if best.Score >= earlyExitScore {
			break
		}
	}
	return best, nil
}

// scoreWindow scores all ensemble models on a slice of words and merges the
// results. The highest score per label is kept (deduplicates when both models
// flag the same label). Calls PredictWords to avoid the Join→ToLower→Fields
// round-trip that Predict would require.
func (r ClassifierRule) scoreWindow(words []string) (safety.Match, error) {
	// bestPerLabel tracks the highest score seen for each flagged label
	// across all ensemble models. Models are scored in order; if one already
	// reaches earlyExitScore we skip the remaining models — the decision is
	// already safe=false at maximum confidence.
	bestPerLabel := make(map[string]float64, 4)
	windowMax := 0.0
	for _, m := range r.models {
		for _, pred := range m.PredictWords(words) {
			threshold := m.Thresholds[pred.Label]
			if pred.Score >= threshold {
				if pred.Score > bestPerLabel[pred.Label] {
					bestPerLabel[pred.Label] = pred.Score
				}
				if pred.Score > windowMax {
					windowMax = pred.Score
				}
			}
		}
		if windowMax >= earlyExitScore {
			break
		}
	}
	if len(bestPerLabel) == 0 {
		return safety.Match{}, nil
	}

	flagged := make([]string, 0, len(bestPerLabel))
	maxScore := 0.0
	for label, score := range bestPerLabel {
		flagged = append(flagged, fmt.Sprintf("%s=%.3f", label, score))
		if score > maxScore {
			maxScore = score
		}
	}
	return safety.Match{
		Matched: true,
		Score:   maxScore,
		Reason: safety.Reason{
			RuleID:   r.ruleID,
			Severity: "high",
			Detail:   "classifier flagged labels: " + strings.Join(flagged, ","),
		},
	}, nil
}
