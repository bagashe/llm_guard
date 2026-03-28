package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"llm_guard/internal/quota"
)

type ctxKey struct{}

// ContextWithKey returns a child context carrying the given API key.
func ContextWithKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, ctxKey{}, key)
}

// APIKeyFromContext returns the validated API key stored by BearerMiddleware.
func APIKeyFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKey{}).(string)
	return v
}

type APIKeyChecker interface {
	IsValidAPIKey(ctx context.Context, rawKey string) (bool, error)
}

const cacheTTL      = 30 * time.Second
const quotaCacheTTL = 5 * time.Second

type cacheEntry struct {
	valid     bool
	err       error // non-nil for special rejections (e.g. quota exceeded)
	expiresAt time.Time
}

type Validator struct {
	checker APIKeyChecker
	mu      sync.RWMutex
	cache   map[string]cacheEntry
}

func NewValidator(checker APIKeyChecker) *Validator {
	return &Validator{
		checker: checker,
		cache:   make(map[string]cacheEntry),
	}
}

func (v *Validator) Validate(ctx context.Context, key string) (bool, error) {
	if key == "" {
		return false, nil
	}

	now := time.Now()

	v.mu.RLock()
	if e, ok := v.cache[key]; ok && now.Before(e.expiresAt) {
		v.mu.RUnlock()
		return e.valid, e.err
	}
	v.mu.RUnlock()

	valid, err := v.checker.IsValidAPIKey(ctx, key)
	if errors.Is(err, quota.ErrDailyQuotaExceeded) {
		v.mu.Lock()
		v.cache[key] = cacheEntry{valid: false, err: quota.ErrDailyQuotaExceeded, expiresAt: now.Add(quotaCacheTTL)}
		v.mu.Unlock()
		return false, quota.ErrDailyQuotaExceeded
	}
	if err != nil {
		return false, err
	}

	v.mu.Lock()
	v.cache[key] = cacheEntry{valid: valid, expiresAt: now.Add(cacheTTL)}
	v.mu.Unlock()

	return valid, nil
}

func BearerMiddleware(v *Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
			if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			key := strings.TrimSpace(authHeader[len("Bearer "):])
			ok, err := v.Validate(r.Context(), key)
			if errors.Is(err, quota.ErrDailyQuotaExceeded) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"quota exceeded","detail":"daily request limit reached"}`))
				return
			}
			if err != nil || !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ctxKey{}, key)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
