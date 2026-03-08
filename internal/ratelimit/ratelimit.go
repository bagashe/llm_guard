package ratelimit

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"llm_guard/internal/auth"
)

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type KeyLimiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	rps     rate.Limit
	burst   int
	ttl     time.Duration
	stop    chan struct{}
}

func New(rps float64, burst int, cleanupTTL time.Duration) *KeyLimiter {
	kl := &KeyLimiter{
		entries: make(map[string]*entry),
		rps:     rate.Limit(rps),
		burst:   burst,
		ttl:     cleanupTTL,
		stop:    make(chan struct{}),
	}
	go kl.cleanup()
	return kl
}

func (kl *KeyLimiter) Stop() {
	close(kl.stop)
}

func (kl *KeyLimiter) allow(key string) bool {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	e, ok := kl.entries[key]
	if !ok {
		e = &entry{limiter: rate.NewLimiter(kl.rps, kl.burst)}
		kl.entries[key] = e
	}
	e.lastSeen = time.Now()
	return e.limiter.Allow()
}

func (kl *KeyLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-kl.stop:
			return
		case now := <-ticker.C:
			kl.mu.Lock()
			for k, e := range kl.entries {
				if now.Sub(e.lastSeen) > kl.ttl {
					delete(kl.entries, k)
				}
			}
			kl.mu.Unlock()
		}
	}
}

func (kl *KeyLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := auth.APIKeyFromContext(r.Context())
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}
		if !kl.allow(key) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "rate limit exceeded",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
