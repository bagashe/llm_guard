package classifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	defaultTokenizerType      = "regex"
	defaultTokenizerPattern   = `[\p{L}\p{N}_]+`
	defaultTokenizerLowercase = true
)

type TokenizerConfig struct {
	Type      string `json:"type"`
	Pattern   string `json:"pattern"`
	Lowercase bool   `json:"lowercase"`
}

type Model struct {
	Version    string               `json:"version"`
	Labels     []string             `json:"labels"`
	Tokenizer  TokenizerConfig      `json:"tokenizer"`
	Vocab      map[string]int       `json:"vocab"`
	Weights    map[string][]float64 `json:"weights"`
	Bias       map[string]float64   `json:"bias"`
	Thresholds map[string]float64   `json:"thresholds"`
	tokenRE    *regexp.Regexp
}

type Prediction struct {
	Label string
	Score float64
}

func Load(path string) (*Model, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var m Model
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if len(m.Labels) == 0 || len(m.Vocab) == 0 {
		return nil, errors.New("invalid model: labels and vocab are required")
	}

	if err := m.initTokenizer(); err != nil {
		return nil, err
	}

	if len(m.Thresholds) == 0 {
		m.Thresholds = make(map[string]float64, len(m.Labels))
		for _, label := range m.Labels {
			m.Thresholds[label] = 0.5
		}
	}
	if m.Bias == nil {
		m.Bias = make(map[string]float64)
	}
	if m.Weights == nil {
		m.Weights = make(map[string][]float64)
	}

	for _, label := range m.Labels {
		if _, ok := m.Bias[label]; !ok {
			m.Bias[label] = 0
		}
		if _, ok := m.Thresholds[label]; !ok {
			m.Thresholds[label] = 0.5
		}
	}

	return &m, nil
}

func (m *Model) initTokenizer() error {
	if m.Tokenizer.Type == "" {
		m.Tokenizer.Type = defaultTokenizerType
	}
	if m.Tokenizer.Pattern == "" {
		m.Tokenizer.Pattern = defaultTokenizerPattern
	}
	if m.Tokenizer.Type != defaultTokenizerType {
		return fmt.Errorf("invalid tokenizer type: %s", m.Tokenizer.Type)
	}
	re, err := regexp.Compile(m.Tokenizer.Pattern)
	if err != nil {
		return fmt.Errorf("invalid tokenizer pattern: %w", err)
	}
	m.tokenRE = re
	if m.Tokenizer.Pattern == defaultTokenizerPattern && !m.Tokenizer.Lowercase {
		m.Tokenizer.Lowercase = defaultTokenizerLowercase
	}
	return nil
}

func (m *Model) Predict(text string) []Prediction {
	if m.tokenRE == nil {
		if err := m.initTokenizer(); err != nil {
			return nil
		}
	}
	features := make(map[int]float64)
	for _, token := range m.tokenize(text) {
		idx, ok := m.Vocab[token]
		if !ok {
			continue
		}
		features[idx] += 1
	}

	out := make([]Prediction, 0, len(m.Labels))
	for _, label := range m.Labels {
		weights := m.Weights[label]
		logit := m.Bias[label]
		for idx, val := range features {
			if idx >= 0 && idx < len(weights) {
				logit += weights[idx] * val
			}
		}
		out = append(out, Prediction{Label: label, Score: sigmoid(logit)})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Score > out[j].Score
	})

	return out
}

func (m *Model) tokenize(text string) []string {
	if m.Tokenizer.Lowercase {
		text = strings.ToLower(text)
	}
	parts := m.tokenRE.FindAllString(text, -1)
	if len(parts) == 0 {
		return nil
	}
	return parts
}

func sigmoid(x float64) float64 {
	if x >= 0 {
		z := math.Exp(-x)
		return 1 / (1 + z)
	}
	z := math.Exp(x)
	return z / (1 + z)
}
