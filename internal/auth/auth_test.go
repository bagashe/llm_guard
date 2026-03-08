package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubChecker struct {
	valid bool
	err   error
}

func (s stubChecker) IsValidAPIKey(_ context.Context, _ string) (bool, error) {
	return s.valid, s.err
}

func TestBearerMiddleware(t *testing.T) {
	tests := []struct {
		name         string
		authHeader   string
		checkerValid bool
		checkerErr   error
		wantStatus   int
	}{
		{name: "missing header", wantStatus: http.StatusUnauthorized},
		{name: "wrong scheme", authHeader: "Basic abc", wantStatus: http.StatusUnauthorized},
		{name: "empty bearer key", authHeader: "Bearer    ", wantStatus: http.StatusUnauthorized},
		{name: "checker error", authHeader: "Bearer key", checkerErr: errors.New("db down"), wantStatus: http.StatusUnauthorized},
		{name: "invalid key", authHeader: "Bearer bad", checkerValid: false, wantStatus: http.StatusUnauthorized},
		{name: "valid key", authHeader: "Bearer good", checkerValid: true, wantStatus: http.StatusOK},
		{name: "lowercase bearer prefix", authHeader: "bearer good", checkerValid: true, wantStatus: http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewValidator(stubChecker{valid: tc.checkerValid, err: tc.checkerErr})
			mw := BearerMiddleware(validator)

			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/v1/evaluate", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			rr := httptest.NewRecorder()
			mw(next).ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("status mismatch: got %d want %d", rr.Code, tc.wantStatus)
			}
		})
	}
}
