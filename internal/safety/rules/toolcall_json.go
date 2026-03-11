package rules

import (
	"encoding/json"
	"strings"
)

// collectStringsFromPayload parses a JSON message and collects all string
// values recursively. If JSON parsing fails, the raw message is returned.
func collectStringsFromPayload(message string) []string {
	message = strings.TrimSpace(message)
	if message == "" {
		return nil
	}

	var payload any
	if err := json.Unmarshal([]byte(message), &payload); err != nil {
		return []string{message}
	}

	var out []string
	collectStringsFromAny(payload, &out)
	return out
}

func collectStringsFromAny(v any, out *[]string) {
	switch typed := v.(type) {
	case map[string]any:
		for _, child := range typed {
			collectStringsFromAny(child, out)
		}
	case []any:
		for _, child := range typed {
			collectStringsFromAny(child, out)
		}
	case string:
		s := strings.TrimSpace(typed)
		if s != "" {
			*out = append(*out, s)
		}
	}
}
