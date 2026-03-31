// Package registration implements proof-of-work based self-registration.
//
// Flow:
//
//  1. Client calls IssueChallenge → receives a challenge_id.
//  2. Client searches for a nonce string such that:
//     SHA256(challenge_id + ":" + nonce) has [difficulty] leading zero bits.
//  3. Client calls VerifySolution(challenge_id, nonce) → on success, the
//     caller may create and return an API key.
//
// The expected number of SHA256 operations to find a valid nonce is 2^difficulty.
// At difficulty=25 (~34M hashes), a typical cloud VM takes roughly 2–5 seconds.
package registration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// KeyCreator is satisfied by *sqlite.APIKeyStore. Defined here so the
// registration package does not depend on the storage package.
type KeyCreator interface {
	CreateAPIKey(ctx context.Context, name, rawKey string) error
	SetDailyQuotaByName(ctx context.Context, name string, limit int64) error
}

// Sentinel errors returned by ChallengeStore methods.
var (
	ErrIPRateLimited    = errors.New("ip rate limited")
	ErrChallengeNotFound = errors.New("challenge not found")
	ErrChallengeExpired  = errors.New("challenge expired")
	ErrAlreadySolved     = errors.New("challenge already solved")
	ErrInvalidSolution   = errors.New("invalid proof of work solution")
)

const (
	challengeTTL       = 10 * time.Minute
	ipWindowDuration   = 10 * time.Minute
	ipMaxChallenges    = 5
	maxNonceLen        = 256 // bytes; caps hash-a-giant-input abuse
	cleanupInterval    = time.Minute
)

// Challenge is an issued proof-of-work challenge.
type Challenge struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
	SolvedAt  *time.Time
	ClientIP  string
}

type ipWindow struct {
	count     int
	windowEnd time.Time
}

// ChallengeStore is an in-memory store for issued challenges.
// It is safe for concurrent use.
type ChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]*Challenge
	ipWindows  map[string]*ipWindow
	difficulty int
	nowFn      func() time.Time // injectable for tests
	stop       chan struct{}
	once       sync.Once
}

// NewChallengeStore creates a ChallengeStore with the given PoW difficulty
// (number of leading zero bits required) and starts a background cleanup
// goroutine that evicts expired state every minute.
func NewChallengeStore(difficulty int) *ChallengeStore {
	cs := &ChallengeStore{
		challenges: make(map[string]*Challenge),
		ipWindows:  make(map[string]*ipWindow),
		difficulty: difficulty,
		nowFn:      time.Now,
		stop:       make(chan struct{}),
	}
	go cs.cleanupLoop()
	return cs
}

// Stop shuts down the background cleanup goroutine. Safe to call multiple times.
func (cs *ChallengeStore) Stop() {
	cs.once.Do(func() { close(cs.stop) })
}

// IssueChallenge issues a new challenge for the given client IP.
// Returns ErrIPRateLimited if the IP has exceeded ipMaxChallenges within
// the sliding window.
func (cs *ChallengeStore) IssueChallenge(clientIP string) (*Challenge, error) {
	now := cs.nowFn()

	cs.mu.Lock()
	defer cs.mu.Unlock()

	// IP rate limit check.
	w, ok := cs.ipWindows[clientIP]
	if !ok || now.After(w.windowEnd) {
		// New or expired window — reset.
		cs.ipWindows[clientIP] = &ipWindow{count: 1, windowEnd: now.Add(ipWindowDuration)}
	} else {
		if w.count >= ipMaxChallenges {
			return nil, ErrIPRateLimited
		}
		w.count++
	}

	// Generate challenge ID.
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(b) // 32-char hex

	c := &Challenge{
		ID:        id,
		CreatedAt: now,
		ExpiresAt: now.Add(challengeTTL),
		ClientIP:  clientIP,
	}
	cs.challenges[id] = c
	return c, nil
}

// VerifySolution checks that nonce satisfies the proof of work for challenge id.
// On success the challenge is marked solved and returned. Each challenge may
// only be solved once.
func (cs *ChallengeStore) VerifySolution(id, nonce string) (*Challenge, error) {
	if len(nonce) > maxNonceLen {
		return nil, ErrInvalidSolution
	}

	now := cs.nowFn()

	cs.mu.Lock()
	defer cs.mu.Unlock()

	c, ok := cs.challenges[id]
	if !ok {
		return nil, ErrChallengeNotFound
	}
	if now.After(c.ExpiresAt) {
		return nil, ErrChallengeExpired
	}
	if c.SolvedAt != nil {
		return nil, ErrAlreadySolved
	}
	if !VerifyPoW(id, nonce, cs.difficulty) {
		return nil, ErrInvalidSolution
	}

	t := now
	c.SolvedAt = &t
	return c, nil
}

// VerifyPoW reports whether SHA256(challengeID + ":" + nonce) has bits leading
// zero bits. It is exported so clients can verify their own implementations.
func VerifyPoW(challengeID, nonce string, bits int) bool {
	h := sha256.Sum256([]byte(challengeID + ":" + nonce))
	fullBytes := bits / 8
	for i := range fullBytes {
		if h[i] != 0 {
			return false
		}
	}
	rem := bits % 8
	if rem > 0 {
		mask := byte(0xFF << (8 - rem))
		if h[fullBytes]&mask != 0 {
			return false
		}
	}
	return true
}

// GenerateKey returns a cryptographically random 64-character hex string
// suitable for use as an API key.
func GenerateKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (cs *ChallengeStore) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cs.cleanup()
		case <-cs.stop:
			return
		}
	}
}

func (cs *ChallengeStore) cleanup() {
	now := cs.nowFn()
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for id, c := range cs.challenges {
		if now.After(c.ExpiresAt) {
			delete(cs.challenges, id)
		}
	}
	for ip, w := range cs.ipWindows {
		if now.After(w.windowEnd) {
			delete(cs.ipWindows, ip)
		}
	}
}
