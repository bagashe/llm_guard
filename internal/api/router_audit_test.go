package api

import (
	"strings"
	"testing"
)

func TestExtractToolCallAuditFields(t *testing.T) {
	longArg := strings.Repeat("abcdefghijklmnopqrstuvwxyz", 24)

	tests := []struct {
		name           string
		message        string
		wantToolName   string
		wantToolArgs   string
		wantArgsSuffix string
		wantArgsMaxLen int
	}{
		{
			name:         "extracts tool and arguments",
			message:      `{"tool":"browser.open","arguments":{"url":"https://example.com"}}`,
			wantToolName: "browser.open",
			wantToolArgs: `{"url":"https://example.com"}`,
		},
		{
			name:         "supports args alias",
			message:      `{"name":"web.fetch","args":{"q":"status"}}`,
			wantToolName: "web.fetch",
			wantToolArgs: `{"q":"status"}`,
		},
		{
			name:         "prefers tool_name over generic name",
			message:      `{"name":"John","tool_name":"browser.open","arguments":{"url":"https://example.com"}}`,
			wantToolName: "browser.open",
			wantToolArgs: `{"url":"https://example.com"}`,
		},
		{
			name:         "returns unparsed for invalid json",
			message:      `not-json`,
			wantToolName: "unparsed",
			wantToolArgs: `not-json`,
		},
		{
			name:         "returns unknown and none when keys absent",
			message:      `{"foo":"bar"}`,
			wantToolName: "unknown",
			wantToolArgs: "none",
		},
		{
			name:           "truncates long tool args",
			message:        `{"tool":"browser.search","arguments":{"query":"` + longArg + `"}}`,
			wantToolName:   "browser.search",
			wantArgsSuffix: "...<truncated>",
			wantArgsMaxLen: maxAuditToolArgsLen,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			toolName, toolArgs := extractToolCallAuditFields(tc.message)
			if toolName != tc.wantToolName {
				t.Fatalf("toolName=%q want=%q", toolName, tc.wantToolName)
			}
			if tc.wantToolArgs != "" && toolArgs != tc.wantToolArgs {
				t.Fatalf("toolArgs=%q want=%q", toolArgs, tc.wantToolArgs)
			}
			if tc.wantArgsSuffix != "" && !strings.HasSuffix(toolArgs, tc.wantArgsSuffix) {
				t.Fatalf("expected toolArgs suffix %q, got %q", tc.wantArgsSuffix, toolArgs)
			}
			if tc.wantArgsMaxLen > 0 && len(toolArgs) > tc.wantArgsMaxLen {
				t.Fatalf("toolArgs length=%d exceeds max=%d", len(toolArgs), tc.wantArgsMaxLen)
			}
		})
	}
}

func TestTruncateForAudit(t *testing.T) {
	if got := truncateForAudit("hello", 5); got != "hello" {
		t.Fatalf("unexpected no-truncation result: %q", got)
	}
	if got := truncateForAudit("hello world", 8); got != "...<trun" {
		t.Fatalf("unexpected short-limit truncation result: %q", got)
	}
}
