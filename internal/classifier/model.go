package classifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"unicode"
)

const (
	defaultTokenizerType      = "char_ngram_wb"
	defaultTokenizerLowercase = true
	defaultTokenizerNgramMin  = 3
	defaultTokenizerNgramMax  = 5
)

type TokenizerConfig struct {
	Type      string `json:"type"`
	Lowercase bool   `json:"lowercase"`
	NgramMin  int    `json:"ngram_min"`
	NgramMax  int    `json:"ngram_max"`
}

type Model struct {
	Version    string               `json:"version"`
	Labels     []string             `json:"labels"`
	Tokenizer  TokenizerConfig      `json:"tokenizer"`
	Vocab      map[string]int       `json:"vocab"`
	Weights    map[string][]float64 `json:"weights"`
	Bias       map[string]float64   `json:"bias"`
	Thresholds map[string]float64   `json:"thresholds"`
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
	if m.Tokenizer.Type != defaultTokenizerType {
		return fmt.Errorf("invalid tokenizer type: %s", m.Tokenizer.Type)
	}
	if m.Tokenizer.NgramMin == 0 {
		m.Tokenizer.NgramMin = defaultTokenizerNgramMin
	}
	if m.Tokenizer.NgramMax == 0 {
		m.Tokenizer.NgramMax = defaultTokenizerNgramMax
	}
	if m.Tokenizer.NgramMin < 1 {
		return fmt.Errorf("invalid tokenizer ngram_min: %d", m.Tokenizer.NgramMin)
	}
	if m.Tokenizer.NgramMax < m.Tokenizer.NgramMin {
		return fmt.Errorf("invalid tokenizer ngram range: min=%d max=%d", m.Tokenizer.NgramMin, m.Tokenizer.NgramMax)
	}
	return nil
}

var featuresPool = sync.Pool{
	New: func() any {
		m := make(map[int]float64, 256)
		return &m
	},
}

func (m *Model) Predict(text string) []Prediction {
	if m.Tokenizer.Type == "" {
		if err := m.initTokenizer(); err != nil {
			return nil
		}
	}

	fp := featuresPool.Get().(*map[int]float64)
	features := *fp
	clear(features)
	defer featuresPool.Put(fp)

	m.tokenizeInto(text, features)

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

// PredictWords is like Predict but accepts pre-split words, avoiding the
// strings.Join → strings.ToLower → strings.Fields round-trip that Predict
// requires. Lowercasing is applied per-rune via unicode.ToLower, which is
// alloc-free. Use this when the caller already holds a []string word slice
// (e.g. sliding-window evaluation in the classifier rule).
func (m *Model) PredictWords(words []string) []Prediction {
	if m.Tokenizer.Type == "" {
		if err := m.initTokenizer(); err != nil {
			return nil
		}
	}

	fp := featuresPool.Get().(*map[int]float64)
	features := *fp
	clear(features)
	defer featuresPool.Put(fp)

	m.tokenizeWordsInto(words, features)

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

// tokenizeWordsInto is the pre-split companion to tokenizeInto. It accepts
// words that have already been separated by the caller and lowercases each
// rune individually via unicode.ToLower — one int32 transform per rune, no
// intermediate string allocation — rather than calling strings.ToLower on the
// full text.
func (m *Model) tokenizeWordsInto(words []string, features map[int]float64) {
	rp := runePool.Get().(*[]rune)
	runes := *rp

	for _, word := range words {
		runes = runes[:0]
		runes = append(runes, ' ')
		for _, r := range word {
			if m.Tokenizer.Lowercase {
				r = unicode.ToLower(r)
			}
			runes = append(runes, r)
		}
		runes = append(runes, ' ')

		for n := m.Tokenizer.NgramMin; n <= m.Tokenizer.NgramMax; n++ {
			if len(runes) < n {
				continue
			}
			for i := 0; i <= len(runes)-n; i++ {
				if idx, ok := m.Vocab[string(runes[i:i+n])]; ok {
					features[idx]++
				}
			}
		}
	}

	*rp = runes
	runePool.Put(rp)
}

// tokenizeInto counts n-gram occurrences directly into features without
// materialising intermediate strings, eliminating ~150 allocs per call.
func (m *Model) tokenizeInto(text string, features map[int]float64) {
	if m.Tokenizer.Lowercase {
		text = strings.ToLower(text)
	}
	words := strings.Fields(text)

	rp := runePool.Get().(*[]rune)
	runes := *rp

	for _, word := range words {
		runes = runes[:0]
		runes = append(runes, ' ')
		for _, r := range word {
			runes = append(runes, r)
		}
		runes = append(runes, ' ')

		for n := m.Tokenizer.NgramMin; n <= m.Tokenizer.NgramMax; n++ {
			if len(runes) < n {
				continue
			}
			for i := 0; i <= len(runes)-n; i++ {
				if idx, ok := m.Vocab[string(runes[i:i+n])]; ok {
					features[idx]++
				}
			}
		}
	}

	*rp = runes
	runePool.Put(rp)
}

// tokenize materialises n-grams as a string slice. Used only by parity tests.
func (m *Model) tokenize(text string) []string {
	if m.Tokenizer.Lowercase {
		text = strings.ToLower(text)
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}

	out := make([]string, 0, len(words)*12)

	rp := runePool.Get().(*[]rune)
	runes := *rp

	for _, word := range words {
		runes = runes[:0]
		runes = append(runes, ' ')
		for _, r := range word {
			runes = append(runes, r)
		}
		runes = append(runes, ' ')

		for n := m.Tokenizer.NgramMin; n <= m.Tokenizer.NgramMax; n++ {
			if len(runes) < n {
				continue
			}
			for i := 0; i <= len(runes)-n; i++ {
				out = append(out, string(runes[i:i+n]))
			}
		}
	}

	*rp = runes
	runePool.Put(rp)

	if len(out) == 0 {
		return nil
	}
	return out
}

var runePool = sync.Pool{
	New: func() any {
		s := make([]rune, 0, 64)
		return &s
	},
}

func sigmoid(x float64) float64 {
	if x >= 0 {
		z := math.Exp(-x)
		return 1 / (1 + z)
	}
	z := math.Exp(x)
	return z / (1 + z)
}
