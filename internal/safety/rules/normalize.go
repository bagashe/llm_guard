package rules

import (
	"encoding/base64"
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// base64BlobRegex matches standalone base64 blobs of 20+ chars (padding optional).
// Requires the string to be at a word boundary to reduce false positives.
var base64BlobRegex = regexp.MustCompile(`(?:^|[\s"'=:,(\[{])([A-Za-z0-9+/]{20,}={0,2})(?:$|[\s"',)\]}.])`)

// confusables maps the most commonly abused cross-script homoglyphs to their
// ASCII Latin equivalents. NFKC handles fullwidth/ligature cases; this table
// covers Cyrillic and Greek characters that are visually identical to Latin.
var confusables = strings.NewReplacer(
	// Cyrillic lowercase
	"а", "a", "е", "e", "і", "i", "о", "o", "р", "p", "с", "c", "х", "x", "у", "y",
	// Cyrillic uppercase
	"А", "A", "В", "B", "Е", "E", "Н", "H", "І", "I", "К", "K", "М", "M",
	"О", "O", "Р", "P", "С", "C", "Т", "T", "Х", "X",
	// Greek
	"α", "a", "ο", "o", "ρ", "p",
)

// NormalizeForEvaluation applies a series of normalization passes to a message
// to surface evasion attempts before rule evaluation.
//
// Passes applied:
//  1. Unicode NFKC — collapses fullwidth chars, ligatures, superscripts
//  2. Confusable map — cross-script homoglyphs (Cyrillic/Greek → Latin)
//  3. HTML entity decode — &lt;script&gt; → <script>
//  4. URL decode — %69gnore → ignore
//  5. Base64 decode — any 20+ char base64 blobs are decoded and appended
//
// The original text is preserved; decoded content is appended so both
// the original and decoded forms are evaluated.
//
// ASCII fast-path: if the input is pure ASCII with no '&' or '%' characters,
// passes 1–4 are no-ops and are skipped entirely. Only the base64 scan runs.
func NormalizeForEvaluation(text string) string {
	if isPlainASCII(text) {
		// Passes 1–4 are no-ops for plain ASCII without entity/percent markers.
		return appendBase64Decoded(text)
	}

	// Pass 1: NFKC unicode normalization
	text = norm.NFKC.String(text)

	// Pass 2: confusable homoglyph normalization
	text = confusables.Replace(text)

	// Pass 3: HTML entity decode
	text = html.UnescapeString(text)

	// Pass 4: URL decode (best-effort, ignore errors)
	if decoded, err := url.QueryUnescape(text); err == nil && decoded != text {
		text = text + " " + decoded
	}

	// Pass 5: Decode base64 blobs and append
	text = appendBase64Decoded(text)

	return text
}

// isPlainASCII reports whether s consists entirely of ASCII bytes and contains
// neither '&' (HTML entity marker) nor '%' (URL-encoding marker). When true,
// the NFKC, confusable, HTML, and URL decode passes are all no-ops.
func isPlainASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b > 127 || b == '&' || b == '%' {
			return false
		}
	}
	return true
}

// hasBase64Candidate performs a single O(n) scan to determine whether text
// contains a run of 20+ base64-alphabet characters. This avoids invoking the
// full backtracking regex on inputs that cannot possibly contain a base64 blob,
// which accounts for the vast majority of real-world messages.
func hasBase64Candidate(s string) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
			(b >= '0' && b <= '9') || b == '+' || b == '/' || b == '=' {
			run++
			if run >= 20 {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

func appendBase64Decoded(text string) string {
	if !hasBase64Candidate(text) {
		return text
	}
	matches := base64BlobRegex.FindAllStringSubmatch(text, 20)
	if len(matches) == 0 {
		return text
	}
	var sb strings.Builder
	sb.WriteString(text)
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		blob := m[1]
		if seen[blob] {
			continue
		}
		seen[blob] = true
		// Try standard and URL-safe variants
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			decoded, err := enc.DecodeString(blob)
			if err != nil {
				continue
			}
			if !utf8.Valid(decoded) {
				continue
			}
			s := strings.TrimSpace(string(decoded))
			if len(s) < 8 {
				continue
			}
			sb.WriteByte(' ')
			sb.WriteString(s)
			break
		}
	}
	return sb.String()
}
