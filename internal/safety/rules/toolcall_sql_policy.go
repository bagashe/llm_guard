package rules

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"llm_guard/internal/safety"
)

type ToolCallSQLPolicyRule struct {
	patterns []dangerousSQLPattern
}

type dangerousSQLPattern struct {
	name    string
	pattern *regexp.Regexp
}

func NewToolCallSQLPolicyRule() safety.Rule {
	return ToolCallSQLPolicyRule{
		patterns: []dangerousSQLPattern{
			// Destructive DDL
			{name: "drop_table", pattern: regexp.MustCompile(`(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b`)},
			{name: "truncate", pattern: regexp.MustCompile(`(?i)\bTRUNCATE\s+(TABLE\s+)?\w`)},
			{name: "alter_drop", pattern: regexp.MustCompile(`(?i)\bALTER\s+TABLE\b.*\bDROP\b`)},

			// Bulk destructive DML
			{name: "delete_no_where", pattern: regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+\w+\s*;`)},
			{name: "update_no_where", pattern: regexp.MustCompile(`(?i)\bUPDATE\s+\w+\s+SET\b[^;]*;\s*$`)},

			// Privilege escalation
			{name: "grant", pattern: regexp.MustCompile(`(?i)\bGRANT\b.*\bTO\b`)},
			{name: "revoke", pattern: regexp.MustCompile(`(?i)\bREVOKE\b.*\bFROM\b`)},
			{name: "create_user", pattern: regexp.MustCompile(`(?i)\bCREATE\s+(USER|ROLE)\b`)},
			{name: "alter_user", pattern: regexp.MustCompile(`(?i)\bALTER\s+(USER|ROLE)\b`)},

			// Injection patterns
			{name: "union_select", pattern: regexp.MustCompile(`(?i)\bUNION\s+(ALL\s+)?SELECT\b`)},
			{name: "stacked_query", pattern: regexp.MustCompile(`;\s*(?i)(DROP|DELETE|INSERT|UPDATE|ALTER|GRANT|TRUNCATE|CREATE)\b`)},
			{name: "tautology", pattern: regexp.MustCompile(`(?i)'\s*OR\s+['"]?1['"]?\s*=\s*['"]?1`)},
			{name: "comment_injection", pattern: regexp.MustCompile(`(?i)(--|#)\s*$`)},

			// Data exfiltration
			{name: "into_outfile", pattern: regexp.MustCompile(`(?i)\bINTO\s+(OUT|DUMP)FILE\b`)},
			{name: "load_file", pattern: regexp.MustCompile(`(?i)\bLOAD_FILE\s*\(`)},
			{name: "load_data", pattern: regexp.MustCompile(`(?i)\bLOAD\s+DATA\b`)},

			// System access
			{name: "exec_cmd", pattern: regexp.MustCompile(`(?i)\b(xp_cmdshell|EXEC\s+master|sp_execute_external_script)\b`)},
			{name: "information_schema_dump", pattern: regexp.MustCompile(`(?i)\bSELECT\b.*\bFROM\s+information_schema\.(tables|columns)\b`)},
		},
	}
}

func (r ToolCallSQLPolicyRule) ID() string {
	return "tool_call.sql_policy"
}

func (r ToolCallSQLPolicyRule) Evaluate(_ context.Context, in safety.Input) (safety.Match, error) {
	if in.MessageType != safety.MessageTypeToolCall {
		return safety.Match{}, nil
	}

	values := collectStringsFromPayload(in.Message)
	if len(values) == 0 {
		return safety.Match{}, nil
	}

	matched := make(map[string]struct{})
	for _, s := range values {
		for _, p := range r.patterns {
			if p.pattern.MatchString(s) {
				matched[p.name] = struct{}{}
			}
		}
	}

	if len(matched) == 0 {
		return safety.Match{}, nil
	}

	names := make([]string, 0, len(matched))
	for name := range matched {
		names = append(names, name)
	}
	sort.Strings(names)

	return safety.Match{
		Matched: true,
		Score:   1.0,
		Reason: safety.Reason{
			RuleID:   r.ID(),
			Severity: "high",
			Detail:   fmt.Sprintf("tool call contains dangerous SQL pattern(s): %s", strings.Join(names, ",")),
		},
	}, nil
}
