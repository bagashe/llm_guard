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
func NormalizeForEvaluation(text string) string {
	// Pass 1: NFKC unicode normalization
	text = norm.NFKC.String(text)

	// Pass 2: confusable homoglyph normalization
	text = confusables.Replace(text)

	// Pass 2: HTML entity decode
	text = html.UnescapeString(text)

	// Pass 3: URL decode (best-effort, ignore errors)
	if decoded, err := url.QueryUnescape(text); err == nil && decoded != text {
		text = text + " " + decoded
	}

	// Pass 4: Decode base64 blobs and append
	text = appendBase64Decoded(text)

	return text
}

func appendBase64Decoded(text string) string {
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
