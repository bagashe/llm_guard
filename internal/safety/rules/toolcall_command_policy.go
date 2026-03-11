package rules

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"llm_guard/internal/safety"
)

type ToolCallCommandPolicyRule struct {
	patterns []dangerousPattern
}

type dangerousPattern struct {
	name    string
	pattern *regexp.Regexp
}

func NewToolCallCommandPolicyRule() safety.Rule {
	return ToolCallCommandPolicyRule{
		patterns: []dangerousPattern{
			// Destructive file operations
			{name: "rm_recursive", pattern: regexp.MustCompile(`\brm\s+.*-[^\s]*[rR][^\s]*\b`)},
			{name: "rm_force", pattern: regexp.MustCompile(`\brm\s+.*-[^\s]*f`)},
			{name: "mkfs", pattern: regexp.MustCompile(`\bmkfs\b`)},
			{name: "dd_of", pattern: regexp.MustCompile(`\bdd\b.*\bof=`)},

			// Privilege escalation / system control
			{name: "chmod_dangerous", pattern: regexp.MustCompile(`\bchmod\s+([0-7]*7[0-7]{2}|[0-7]{0,2}7[0-7]{2}|\+s|u\+s|g\+s|a\+[rwx]*s)`)},
			{name: "chown_root", pattern: regexp.MustCompile(`\bchown\s+root\b`)},
			{name: "sudo", pattern: regexp.MustCompile(`\bsudo\b`)},

			// Remote code execution / download-and-execute
			{name: "curl_pipe_sh", pattern: regexp.MustCompile(`\bcurl\b.*\|\s*(sh|bash|zsh|dash)`)},
			{name: "wget_pipe_sh", pattern: regexp.MustCompile(`\bwget\b.*\|\s*(sh|bash|zsh|dash)`)},
			{name: "eval", pattern: regexp.MustCompile(`\beval\s+`)},

			// Shell injection / chaining
			{name: "backtick_exec", pattern: regexp.MustCompile("`[^`]+`")},
			{name: "command_substitution", pattern: regexp.MustCompile(`\$\([^)]+\)`)},

			// Sensitive file access
			{name: "etc_shadow", pattern: regexp.MustCompile(`/etc/shadow`)},
			{name: "etc_passwd_write", pattern: regexp.MustCompile(`(>|>>)\s*/etc/passwd`)},
			{name: "proc_self", pattern: regexp.MustCompile(`/proc/self/`)},

			// Path traversal
			{name: "path_traversal", pattern: regexp.MustCompile(`\.\./\.\./`)},

			// Network exfiltration
			{name: "nc_listen", pattern: regexp.MustCompile(`\bnc\s+.*-[^\s]*l`)},
			{name: "ncat_exec", pattern: regexp.MustCompile(`\bncat\b.*-[^\s]*e`)},

			// Disk/system destruction
			{name: "dev_write", pattern: regexp.MustCompile(`>\s*/dev/(sd[a-z]|nvme|hd[a-z])`)},
			{name: "shutdown", pattern: regexp.MustCompile(`\b(shutdown|reboot|halt|poweroff)\b`)},
		},
	}
}

func (r ToolCallCommandPolicyRule) ID() string {
	return "tool_call.command_policy"
}

func (r ToolCallCommandPolicyRule) Evaluate(_ context.Context, in safety.Input) (safety.Match, error) {
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
			Detail:   fmt.Sprintf("tool call contains dangerous command pattern(s): %s", strings.Join(names, ",")),
		},
	}, nil
}
