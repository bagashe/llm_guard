package rules

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"llm_guard/internal/safety"
)

type PIIDetectionRule struct {
	emailRegex     *regexp.Regexp
	ssnRegex       *regexp.Regexp
	cardRegex      *regexp.Regexp
	phoneRegex     *regexp.Regexp
	categoryOrder  []string
	baseScore      float64
	extraScore     float64
	maxCappedScore float64
}

func NewPIIDetectionRule() safety.Rule {
	return &PIIDetectionRule{
		emailRegex:     regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`),
		ssnRegex:       regexp.MustCompile(`\b(\d{3})-(\d{2})-(\d{4})\b`),
		cardRegex:      regexp.MustCompile(`(?:^|[^\d])((?:\d[ -]*){13,19})(?:[^\d]|$)`),
		phoneRegex:     regexp.MustCompile(`(?:^|[^\d])(?:\+?1[ -]?)?\(?[2-9]\d{2}\)?[ -]?[2-9]\d{2}[ -]?\d{4}(?:[^\d]|$)`),
		categoryOrder:  []string{"email", "ssn", "credit_card", "phone"},
		baseScore:      0.25,
		extraScore:     0.10,
		maxCappedScore: 0.50,
	}
}

func (r *PIIDetectionRule) ID() string {
	return "input.pii_detection"
}

func (r *PIIDetectionRule) Evaluate(_ context.Context, in safety.Input) (safety.Match, error) {
	if in.MessageType != safety.MessageTypeUser {
		return safety.Match{}, nil
	}

	found := make(map[string]struct{}, len(r.categoryOrder))
	if r.emailRegex.MatchString(in.Message) {
		found["email"] = struct{}{}
	}
	if containsValidSSN(r.ssnRegex.FindAllStringSubmatch(in.Message, 50)) {
		found["ssn"] = struct{}{}
	}
	if containsLuhnValidCard(r.cardRegex.FindAllStringSubmatch(in.Message, 50)) {
		found["credit_card"] = struct{}{}
	}
	if r.phoneRegex.MatchString(in.Message) {
		found["phone"] = struct{}{}
	}

	if len(found) == 0 {
		return safety.Match{}, nil
	}

	categories := orderedCategories(found, r.categoryOrder)
	count := float64(len(categories))
	score := r.baseScore + r.extraScore*(count-1)
	if score > r.maxCappedScore {
		score = r.maxCappedScore
	}

	return safety.Match{
		Matched: true,
		Score:   score,
		Reason: safety.Reason{
			RuleID:   r.ID(),
			Severity: "medium",
			Detail:   "detected PII categories in input: " + strings.Join(categories, ","),
		},
	}, nil
}

func orderedCategories(found map[string]struct{}, order []string) []string {
	out := make([]string, 0, len(found))
	for _, category := range order {
		if _, ok := found[category]; ok {
			out = append(out, category)
		}
	}
	return out
}

func containsValidSSN(matches [][]string) bool {
	for _, m := range matches {
		if len(m) < 4 {
			continue
		}
		area, _ := strconv.Atoi(m[1])
		group, _ := strconv.Atoi(m[2])
		serial, _ := strconv.Atoi(m[3])
		if area == 0 || area == 666 || area >= 900 {
			continue
		}
		if group == 0 || serial == 0 {
			continue
		}
		return true
	}
	return false
}

func containsLuhnValidCard(matches [][]string) bool {
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		digits := normalizeDigits(match[1])
		if len(digits) < 13 || len(digits) > 19 {
			continue
		}
		if isLuhnValid(digits) {
			return true
		}
	}
	return false
}

func normalizeDigits(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	for _, c := range v {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func isLuhnValid(number string) bool {
	if number == "" {
		return false
	}
	sum := 0
	shouldDouble := false
	for i := len(number) - 1; i >= 0; i-- {
		d := int(number[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if shouldDouble {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		shouldDouble = !shouldDouble
	}
	return sum > 0 && sum%10 == 0
}
