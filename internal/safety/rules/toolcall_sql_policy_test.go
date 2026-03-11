package rules

import (
	"context"
	"strings"
	"testing"

	"llm_guard/internal/safety"
)

func TestToolCallSQLPolicyRule(t *testing.T) {
	rule := NewToolCallSQLPolicyRule()

	tests := []struct {
		name        string
		messageType safety.MessageType
		message     string
		wantMatch   bool
		wantDetail  []string
	}{
		{
			name:        "blocks DROP TABLE",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"DROP TABLE users"}}`,
			wantMatch:   true,
			wantDetail:  []string{"drop_table"},
		},
		{
			name:        "blocks DROP DATABASE",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"DROP DATABASE production"}}`,
			wantMatch:   true,
			wantDetail:  []string{"drop_table"},
		},
		{
			name:        "blocks TRUNCATE",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"TRUNCATE TABLE logs"}}`,
			wantMatch:   true,
			wantDetail:  []string{"truncate"},
		},
		{
			name:        "blocks DELETE without WHERE",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"DELETE FROM users;"}}`,
			wantMatch:   true,
			wantDetail:  []string{"delete_no_where"},
		},
		{
			name:        "blocks UNION SELECT",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"SELECT id FROM users UNION SELECT password FROM credentials"}}`,
			wantMatch:   true,
			wantDetail:  []string{"union_select"},
		},
		{
			name:        "blocks UNION ALL SELECT",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"SELECT 1 UNION ALL SELECT 2"}}`,
			wantMatch:   true,
			wantDetail:  []string{"union_select"},
		},
		{
			name:        "blocks tautology injection",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"SELECT * FROM users WHERE name='' OR '1'='1'"}}`,
			wantMatch:   true,
			wantDetail:  []string{"tautology"},
		},
		{
			name:        "blocks stacked DROP query",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"SELECT 1; DROP TABLE users"}}`,
			wantMatch:   true,
			wantDetail:  []string{"stacked_query"},
		},
		{
			name:        "blocks GRANT",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%'"}}`,
			wantMatch:   true,
			wantDetail:  []string{"grant"},
		},
		{
			name:        "blocks CREATE USER",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"CREATE USER backdoor IDENTIFIED BY 'pass'"}}`,
			wantMatch:   true,
			wantDetail:  []string{"create_user"},
		},
		{
			name:        "blocks INTO OUTFILE",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"SELECT * FROM users INTO OUTFILE '/tmp/dump.csv'"}}`,
			wantMatch:   true,
			wantDetail:  []string{"into_outfile"},
		},
		{
			name:        "blocks xp_cmdshell",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"EXEC xp_cmdshell 'whoami'"}}`,
			wantMatch:   true,
			wantDetail:  []string{"exec_cmd"},
		},
		{
			name:        "blocks information_schema dump",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"SELECT table_name FROM information_schema.tables"}}`,
			wantMatch:   true,
			wantDetail:  []string{"information_schema_dump"},
		},
		{
			name:        "allows safe SELECT",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"SELECT id, name FROM users WHERE active = true"}}`,
			wantMatch:   false,
		},
		{
			name:        "allows INSERT",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"INSERT INTO logs (message) VALUES ('hello')"}}`,
			wantMatch:   false,
		},
		{
			name:        "allows DELETE with WHERE",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"DELETE FROM sessions WHERE expired_at < NOW()"}}`,
			wantMatch:   false,
		},
		{
			name:        "skips non-toolcall messages",
			messageType: safety.MessageTypeUser,
			message:     `{"tool":"db.query","arguments":{"sql":"DROP TABLE users"}}`,
			wantMatch:   false,
		},
		{
			name:        "handles nested args",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"pipeline","arguments":{"steps":[{"query":"DROP TABLE audit_log"}]}}`,
			wantMatch:   true,
			wantDetail:  []string{"drop_table"},
		},
		{
			name:        "case insensitive matching",
			messageType: safety.MessageTypeToolCall,
			message:     `{"tool":"db.query","arguments":{"sql":"drop table Users"}}`,
			wantMatch:   true,
			wantDetail:  []string{"drop_table"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match, err := rule.Evaluate(context.Background(), safety.Input{
				Message:     tc.message,
				MessageType: tc.messageType,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if match.Matched != tc.wantMatch {
				t.Fatalf("matched=%v want=%v", match.Matched, tc.wantMatch)
			}
			if !tc.wantMatch {
				return
			}
			if match.Reason.RuleID != "tool_call.sql_policy" {
				t.Fatalf("unexpected rule id: %s", match.Reason.RuleID)
			}
			if match.Reason.Severity != "high" {
				t.Fatalf("unexpected severity: %s", match.Reason.Severity)
			}
			if match.Score != 1.0 {
				t.Fatalf("unexpected score: %f", match.Score)
			}
			for _, want := range tc.wantDetail {
				if !strings.Contains(match.Reason.Detail, want) {
					t.Fatalf("expected detail to contain %q, got %q", want, match.Reason.Detail)
				}
			}
		})
	}
}
