package ratelimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"llm_guard/internal/auth"
)

func TestAllowUnderLimit(t *testing.T) {
	kl := New(100, 5, time.Minute)
	defer kl.Stop()

	for i := 0; i < 5; i++ {
		if !kl.allow("key-a") {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
}

func TestAllowOverLimit(t *testing.T) {
	kl := New(1, 2, time.Minute)
	defer kl.Stop()

	kl.allow("key-a") // 1
	kl.allow("key-a") // 2 (exhausts burst)

	if kl.allow("key-a") {
		t.Fatal("request should be rejected after burst exhausted")
	}
}

func TestPerKeyIsolation(t *testing.T) {
	kl := New(1, 1, time.Minute)
	defer kl.Stop()

	kl.allow("key-a") // exhausts key-a burst

	if !kl.allow("key-b") {
		t.Fatal("key-b should not be affected by key-a rate limit")
	}
}

func TestMiddlewareReturns429(t *testing.T) {
	kl := New(1, 1, time.Minute)
	defer kl.Stop()

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := kl.Middleware(next)

	makeReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", nil)
		ctx := auth.ContextWithKey(req.Context(), "test-key")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	rr1 := makeReq()
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request should succeed, got %d", rr1.Code)
	}

	rr2 := makeReq()
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request should be rate limited, got %d", rr2.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rr2.Body).Decode(&body); err != nil {
		t.Fatalf("decode 429 body: %v", err)
	}
	if body["error"] != "rate limit exceeded" {
		t.Fatalf("unexpected error message: %s", body["error"])
	}
}

func TestCleanupEvictsStaleEntries(t *testing.T) {
	kl := New(100, 10, 1*time.Millisecond)
	defer kl.Stop()

	kl.allow("stale-key")

	kl.mu.Lock()
	if _, ok := kl.entries["stale-key"]; !ok {
		kl.mu.Unlock()
		t.Fatal("entry should exist before cleanup")
	}
	kl.mu.Unlock()

	time.Sleep(10 * time.Millisecond)

	// Manually trigger cleanup logic
	kl.mu.Lock()
	now := time.Now()
	for k, e := range kl.entries {
		if now.Sub(e.lastSeen) > kl.ttl {
			delete(kl.entries, k)
		}
	}
	count := len(kl.entries)
	kl.mu.Unlock()

	if count != 0 {
		t.Fatalf("expected stale entry to be evicted, got %d entries", count)
	}
}

func TestMiddlewarePassesThroughWithoutKey(t *testing.T) {
	kl := New(1, 1, time.Minute)
	defer kl.Stop()

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := kl.Middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("handler should be called when no key in context")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}
