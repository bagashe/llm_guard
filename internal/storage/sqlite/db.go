package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"llm_guard/internal/quota"
)

func OpenAndInit(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

func initSchema(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS api_keys (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	key_hash TEXT NOT NULL UNIQUE,
	active INTEGER NOT NULL DEFAULT 1,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_used_at DATETIME,
	usage_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS messages_from_agents (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	api_key_hash TEXT    NOT NULL,
	challenge_id TEXT    NOT NULL UNIQUE,
	message      TEXT    NOT NULL,
	created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_messages_from_agents_api_key_hash
	ON messages_from_agents (api_key_hash);

CREATE TABLE IF NOT EXISTS messages_for_agents (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	api_key_hash TEXT    NOT NULL,
	message      TEXT    NOT NULL,
	created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_messages_for_agents_api_key_hash
	ON messages_for_agents (api_key_hash);
`
	if _, err := db.Exec(schema); err != nil {
		return err
	}

	migrations := []string{
		`ALTER TABLE api_keys ADD COLUMN usage_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE api_keys ADD COLUMN daily_limit INTEGER`,
		`ALTER TABLE api_keys ADD COLUMN daily_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE api_keys ADD COLUMN daily_window TEXT`,
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	return nil
}

type APIKeyStore struct {
	db      *sql.DB
	mu      sync.Mutex
	pending map[int64]int64
	done    chan struct{}
}

type APIKeyRecord struct {
	ID          int64
	Name        string
	Active      bool
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	UsageCount  int64
	DailyLimit  *int64
	DailyCount  int64
	DailyWindow string
}

// ErrChallengeAlreadyUsed is returned when a challenge_id has already been
// used to store a message (UNIQUE constraint on messages_from_agents.challenge_id).
var ErrChallengeAlreadyUsed = errors.New("challenge already used for a message")

type AgentMessageRecord struct {
	ID          int64
	APIKeyHash  string
	ChallengeID string
	Message     string
	CreatedAt   time.Time
}

type InboxMessageRecord struct {
	ID         int64
	APIKeyHash string
	Message    string
	CreatedAt  time.Time
}

func NewAPIKeyStore(db *sql.DB) *APIKeyStore {
	s := &APIKeyStore{
		db:      db,
		pending: make(map[int64]int64),
		done:    make(chan struct{}),
	}
	go s.flushLoop()
	return s
}

func (s *APIKeyStore) flushLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = s.flush(context.Background())
		case <-s.done:
			_ = s.flush(context.Background())
			return
		}
	}
}

func (s *APIKeyStore) flush(ctx context.Context) error {
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return nil
	}
	snap := s.pending
	s.pending = make(map[int64]int64, len(snap))
	s.mu.Unlock()

	now := time.Now().UTC()
	today := now.Format("2006-01-02")
	for id, count := range snap {
		const q = `
UPDATE api_keys SET
	last_used_at  = ?,
	usage_count   = usage_count + ?,
	daily_count   = CASE WHEN daily_window = ? THEN daily_count + ? ELSE ? END,
	daily_window  = ?
WHERE id = ?`
		_, _ = s.db.ExecContext(ctx, q, now, count, today, count, count, today, id)
	}
	return nil
}

func (s *APIKeyStore) Close() error {
	close(s.done)
	return nil
}

func (s *APIKeyStore) IsValidAPIKey(ctx context.Context, rawKey string) (bool, error) {
	hash := hashAPIKey(rawKey)
	const q = `SELECT id, daily_limit, daily_count, daily_window FROM api_keys WHERE key_hash = ? AND active = 1 LIMIT 1`
	var id int64
	var dailyLimit sql.NullInt64
	var dailyCount int64
	var dailyWindow sql.NullString
	err := s.db.QueryRowContext(ctx, q, hash).Scan(&id, &dailyLimit, &dailyCount, &dailyWindow)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	if dailyLimit.Valid {
		today := time.Now().UTC().Format("2006-01-02")
		effective := dailyCount
		if !dailyWindow.Valid || dailyWindow.String != today {
			effective = 0
		}
		if effective >= dailyLimit.Int64 {
			return false, quota.ErrDailyQuotaExceeded
		}
	}

	s.mu.Lock()
	s.pending[id]++
	s.mu.Unlock()
	return true, nil
}

func (s *APIKeyStore) BootstrapKeys(ctx context.Context, keys []string) error {
	for i, k := range keys {
		const stmt = `INSERT OR IGNORE INTO api_keys (name, key_hash, active) VALUES (?, ?, 1)`
		name := fmt.Sprintf("bootstrap-%d", i+1)
		if _, err := s.db.ExecContext(ctx, stmt, name, hashAPIKey(k)); err != nil {
			return err
		}
	}
	return nil
}

func (s *APIKeyStore) CreateAPIKey(ctx context.Context, name, rawKey string) error {
	if name == "" || rawKey == "" {
		return errors.New("name and rawKey are required")
	}
	const stmt = `INSERT INTO api_keys (name, key_hash, active) VALUES (?, ?, 1)`
	_, err := s.db.ExecContext(ctx, stmt, name, hashAPIKey(rawKey))
	return err
}

func (s *APIKeyStore) RevokeAPIKeyByID(ctx context.Context, id int64) (bool, error) {
	const stmt = `UPDATE api_keys SET active = 0 WHERE id = ? AND active = 1`
	res, err := s.db.ExecContext(ctx, stmt, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *APIKeyStore) RevokeAPIKeyByName(ctx context.Context, name string) (bool, error) {
	if name == "" {
		return false, errors.New("name is required")
	}
	const stmt = `UPDATE api_keys SET active = 0 WHERE name = ? AND active = 1`
	res, err := s.db.ExecContext(ctx, stmt, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *APIKeyStore) SetDailyQuotaByID(ctx context.Context, id int64, limit int64) error {
	const stmt = `UPDATE api_keys SET daily_limit = ? WHERE id = ?`
	res, err := s.db.ExecContext(ctx, stmt, limit, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("no api key found with that id")
	}
	return nil
}

func (s *APIKeyStore) SetDailyQuotaByName(ctx context.Context, name string, limit int64) error {
	if name == "" {
		return errors.New("name is required")
	}
	const stmt = `UPDATE api_keys SET daily_limit = ? WHERE name = ?`
	res, err := s.db.ExecContext(ctx, stmt, limit, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("no api key found with that name")
	}
	return nil
}

func (s *APIKeyStore) ClearDailyQuotaByID(ctx context.Context, id int64) error {
	const stmt = `UPDATE api_keys SET daily_limit = NULL WHERE id = ?`
	res, err := s.db.ExecContext(ctx, stmt, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("no api key found with that id")
	}
	return nil
}

func (s *APIKeyStore) ClearDailyQuotaByName(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("name is required")
	}
	const stmt = `UPDATE api_keys SET daily_limit = NULL WHERE name = ?`
	res, err := s.db.ExecContext(ctx, stmt, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("no api key found with that name")
	}
	return nil
}

func (s *APIKeyStore) ListAPIKeys(ctx context.Context) ([]APIKeyRecord, error) {
	const q = `
SELECT id, name, active, created_at, last_used_at, usage_count, daily_limit, daily_count, daily_window
FROM api_keys
ORDER BY id ASC
`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]APIKeyRecord, 0)
	for rows.Next() {
		var rec APIKeyRecord
		var activeInt int
		var lastUsed sql.NullTime
		var dailyLimit sql.NullInt64
		var dailyWindow sql.NullString
		if err := rows.Scan(&rec.ID, &rec.Name, &activeInt, &rec.CreatedAt, &lastUsed, &rec.UsageCount, &dailyLimit, &rec.DailyCount, &dailyWindow); err != nil {
			return nil, err
		}
		rec.Active = activeInt == 1
		if lastUsed.Valid {
			v := lastUsed.Time
			rec.LastUsedAt = &v
		}
		if dailyLimit.Valid {
			v := dailyLimit.Int64
			rec.DailyLimit = &v
		}
		if dailyWindow.Valid {
			rec.DailyWindow = dailyWindow.String
		}
		out = append(out, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func (s *APIKeyStore) StoreAgentMessage(ctx context.Context, rawKey, challengeID, message string) (AgentMessageRecord, error) {
	const stmt = `INSERT INTO messages_from_agents (api_key_hash, challenge_id, message) VALUES (?, ?, ?)`
	res, err := s.db.ExecContext(ctx, stmt, hashAPIKey(rawKey), challengeID, message)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: messages_from_agents.challenge_id") {
			return AgentMessageRecord{}, ErrChallengeAlreadyUsed
		}
		return AgentMessageRecord{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return AgentMessageRecord{}, err
	}
	const q = `SELECT id, api_key_hash, challenge_id, message, created_at FROM messages_from_agents WHERE id = ?`
	var rec AgentMessageRecord
	err = s.db.QueryRowContext(ctx, q, id).Scan(&rec.ID, &rec.APIKeyHash, &rec.ChallengeID, &rec.Message, &rec.CreatedAt)
	return rec, err
}

func (s *APIKeyStore) ListAgentMessages(ctx context.Context, rawKey string) ([]AgentMessageRecord, error) {
	const q = `SELECT id, api_key_hash, challenge_id, message, created_at FROM messages_from_agents WHERE api_key_hash = ? ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, q, hashAPIKey(rawKey))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AgentMessageRecord, 0)
	for rows.Next() {
		var rec AgentMessageRecord
		if err := rows.Scan(&rec.ID, &rec.APIKeyHash, &rec.ChallengeID, &rec.Message, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *APIKeyStore) ListInboxMessages(ctx context.Context, rawKey string) ([]InboxMessageRecord, error) {
	const q = `SELECT id, api_key_hash, message, created_at FROM messages_for_agents WHERE api_key_hash = ? ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, q, hashAPIKey(rawKey))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]InboxMessageRecord, 0)
	for rows.Next() {
		var rec InboxMessageRecord
		if err := rows.Scan(&rec.ID, &rec.APIKeyHash, &rec.Message, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// DB returns the underlying *sql.DB. Intended for use in tests that need to
// insert rows directly (e.g. seeding messages_for_agents).
func (s *APIKeyStore) DB() *sql.DB {
	return s.db
}

// HashAPIKey is the exported form of hashAPIKey for use in tests.
func HashAPIKey(key string) string {
	return hashAPIKey(key)
}

func hashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}
