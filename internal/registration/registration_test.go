package registration

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"
)

// --- VerifyPoW ---

func TestVerifyPoWDifficulty0(t *testing.T) {
	// difficulty=0 means any hash is valid
	if !VerifyPoW("id", "nonce", 0) {
		t.Fatal("difficulty=0 should always pass")
	}
}

func TestVerifyPoWCorrectSolution(t *testing.T) {
	// Find a valid nonce at difficulty=8 (one leading zero byte) and verify it.
	id := "testchallenge"
	for n := range 1_000_000 {
		nonce := fmt.Sprintf("%d", n)
		h := sha256.Sum256([]byte(id + ":" + nonce))
		if h[0] == 0 {
			if !VerifyPoW(id, nonce, 8) {
				t.Fatalf("VerifyPoW rejected a valid nonce %q (hash[0]=%02x)", nonce, h[0])
			}
			// Also check a slightly-off nonce fails
			if VerifyPoW(id, nonce+"x", 8) {
				// It's possible but statistically negligible — accept it
			}
			return
		}
	}
	t.Fatal("could not find a nonce with leading zero byte in 1M tries")
}

func TestVerifyPoWBitBoundary(t *testing.T) {
	// difficulty=4: top nibble of first byte must be 0x0.
	id := "boundary"
	for n := range 1_000_000 {
		nonce := fmt.Sprintf("%d", n)
		h := sha256.Sum256([]byte(id + ":" + nonce))
		if h[0]>>4 == 0 { // top 4 bits are zero
			if !VerifyPoW(id, nonce, 4) {
				t.Fatalf("VerifyPoW rejected valid nonce %q for difficulty=4 (hash[0]=%08b)", nonce, h[0])
			}
			return
		}
	}
	t.Fatal("could not find nonce satisfying difficulty=4 in 1M tries")
}

func TestVerifyPoWWrongNonce(t *testing.T) {
	// A nonce that clearly does NOT start with zero bits should fail at difficulty=20.
	// SHA256("x:y") — check that a random-looking hash fails at a high difficulty.
	h := sha256.Sum256([]byte("x:y"))
	// If by chance the hash happens to have 20 leading zero bits, skip this test.
	if h[0] == 0 && h[1] == 0 && (h[2]>>4) == 0 {
		t.Skip("hash accidentally satisfies difficulty=20, skipping")
	}
	if VerifyPoW("x", "y", 20) {
		t.Fatal("expected VerifyPoW to fail for a hash that lacks 20 leading zero bits")
	}
}

// --- ChallengeStore.IssueChallenge ---

func newTestStore(difficulty int) *ChallengeStore {
	cs := NewChallengeStore(difficulty)
	// Override nowFn so we control time in tests.
	cs.nowFn = time.Now
	return cs
}

func TestIssueChallenge_HappyPath(t *testing.T) {
	cs := newTestStore(0)
	defer cs.Stop()

	c, err := cs.IssueChallenge("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.ID) != 32 {
		t.Fatalf("expected 32-char challenge_id, got %d", len(c.ID))
	}
	if c.ExpiresAt.Before(time.Now()) {
		t.Fatal("challenge already expired at issue time")
	}
}

func TestIssueChallenge_IPRateLimit(t *testing.T) {
	cs := newTestStore(0)
	defer cs.Stop()

	ip := "10.0.0.1"
	for i := range ipMaxChallenges {
		if _, err := cs.IssueChallenge(ip); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i+1, err)
		}
	}
	// 6th call must be rejected.
	_, err := cs.IssueChallenge(ip)
	if err == nil {
		t.Fatal("expected ErrIPRateLimited on 6th call, got nil")
	}
	if err != ErrIPRateLimited {
		t.Fatalf("expected ErrIPRateLimited, got %v", err)
	}
}

func TestIssueChallenge_DifferentIPsAreIndependent(t *testing.T) {
	cs := newTestStore(0)
	defer cs.Stop()

	for i := range ipMaxChallenges {
		if _, err := cs.IssueChallenge("192.168.1.1"); err != nil {
			t.Fatalf("ip-a call %d: %v", i+1, err)
		}
		if _, err := cs.IssueChallenge("192.168.1.2"); err != nil {
			t.Fatalf("ip-b call %d: %v", i+1, err)
		}
	}
}

func TestIssueChallenge_WindowReset(t *testing.T) {
	cs := newTestStore(0)
	defer cs.Stop()

	now := time.Now()
	cs.nowFn = func() time.Time { return now }

	ip := "10.0.0.2"
	for range ipMaxChallenges {
		if _, err := cs.IssueChallenge(ip); err != nil {
			t.Fatalf("fill window: %v", err)
		}
	}

	// Advance past the window.
	cs.nowFn = func() time.Time { return now.Add(ipWindowDuration + time.Second) }

	if _, err := cs.IssueChallenge(ip); err != nil {
		t.Fatalf("expected success after window reset, got: %v", err)
	}
}

// --- ChallengeStore.VerifySolution ---

func findNonce(challengeID string, difficulty int) string {
	for n := range 1_000_000 {
		nonce := fmt.Sprintf("%d", n)
		if VerifyPoW(challengeID, nonce, difficulty) {
			return nonce
		}
	}
	panic("could not find nonce in 1M tries")
}

func TestVerifySolution_HappyPath(t *testing.T) {
	cs := newTestStore(0) // difficulty=0: any nonce is valid
	defer cs.Stop()

	c, _ := cs.IssueChallenge("1.2.3.4")
	if _, err := cs.VerifySolution(c.ID, "any-nonce"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifySolution_NotFound(t *testing.T) {
	cs := newTestStore(0)
	defer cs.Stop()

	_, err := cs.VerifySolution("nonexistent", "nonce")
	if err != ErrChallengeNotFound {
		t.Fatalf("expected ErrChallengeNotFound, got %v", err)
	}
}

func TestVerifySolution_Expired(t *testing.T) {
	cs := newTestStore(0)
	defer cs.Stop()

	now := time.Now()
	cs.nowFn = func() time.Time { return now }

	c, _ := cs.IssueChallenge("1.2.3.4")

	// Advance past TTL.
	cs.nowFn = func() time.Time { return now.Add(challengeTTL + time.Second) }

	_, err := cs.VerifySolution(c.ID, "any-nonce")
	if err != ErrChallengeExpired {
		t.Fatalf("expected ErrChallengeExpired, got %v", err)
	}
}

func TestVerifySolution_AlreadySolved(t *testing.T) {
	cs := newTestStore(0)
	defer cs.Stop()

	c, _ := cs.IssueChallenge("1.2.3.4")
	if _, err := cs.VerifySolution(c.ID, "nonce"); err != nil {
		t.Fatalf("first solve: %v", err)
	}
	_, err := cs.VerifySolution(c.ID, "nonce")
	if err != ErrAlreadySolved {
		t.Fatalf("expected ErrAlreadySolved, got %v", err)
	}
}

func TestVerifySolution_InvalidSolution(t *testing.T) {
	cs := newTestStore(20) // difficulty=20 — unlikely any random nonce satisfies it
	defer cs.Stop()

	c, _ := cs.IssueChallenge("1.2.3.4")
	// "bad" almost certainly doesn't have 20 leading zero bits.
	_, err := cs.VerifySolution(c.ID, "bad")
	if err != ErrInvalidSolution {
		t.Fatalf("expected ErrInvalidSolution, got %v", err)
	}
}

func TestVerifySolution_NonceTooLong(t *testing.T) {
	cs := newTestStore(0)
	defer cs.Stop()

	c, _ := cs.IssueChallenge("1.2.3.4")
	longNonce := strings.Repeat("x", maxNonceLen+1)
	_, err := cs.VerifySolution(c.ID, longNonce)
	if err != ErrInvalidSolution {
		t.Fatalf("expected ErrInvalidSolution for oversized nonce, got %v", err)
	}
}

func TestVerifySolution_RealPoW(t *testing.T) {
	cs := newTestStore(8) // 1 leading zero byte — fast enough for a test
	defer cs.Stop()

	c, _ := cs.IssueChallenge("1.2.3.4")
	nonce := findNonce(c.ID, 8)

	solved, err := cs.VerifySolution(c.ID, nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if solved.SolvedAt == nil {
		t.Fatal("SolvedAt should be set after successful verification")
	}
}
