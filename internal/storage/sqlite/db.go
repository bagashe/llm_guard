package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func OpenAndInit(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
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
`
	if _, err := db.Exec(schema); err != nil {
		return err
	}

	const addUsageCount = `ALTER TABLE api_keys ADD COLUMN usage_count INTEGER NOT NULL DEFAULT 0`
	_, err := db.Exec(addUsageCount)
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
}

type APIKeyStore struct {
	db *sql.DB
}

type APIKeyRecord struct {
	ID         int64
	Name       string
	Active     bool
	CreatedAt  time.Time
	LastUsedAt *time.Time
	UsageCount int64
}

func NewAPIKeyStore(db *sql.DB) *APIKeyStore {
	return &APIKeyStore{db: db}
}

func (s *APIKeyStore) IsValidAPIKey(ctx context.Context, rawKey string) (bool, error) {
	hash := hashAPIKey(rawKey)
	const q = `SELECT id FROM api_keys WHERE key_hash = ? AND active = 1 LIMIT 1`
	var id int64
	err := s.db.QueryRowContext(ctx, q, hash).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	const touch = `UPDATE api_keys SET last_used_at = ?, usage_count = usage_count + 1 WHERE id = ?`
	_, _ = s.db.ExecContext(ctx, touch, time.Now().UTC(), id)
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

func (s *APIKeyStore) ListAPIKeys(ctx context.Context) ([]APIKeyRecord, error) {
	const q = `
SELECT id, name, active, created_at, last_used_at, usage_count
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
		if err := rows.Scan(&rec.ID, &rec.Name, &activeInt, &rec.CreatedAt, &lastUsed, &rec.UsageCount); err != nil {
			return nil, err
		}
		rec.Active = activeInt == 1
		if lastUsed.Valid {
			v := lastUsed.Time
			rec.LastUsedAt = &v
		}
		out = append(out, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func hashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}
