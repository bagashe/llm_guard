package auth

import (
	"context"
	"net/http"
	"strings"
)

type APIKeyChecker interface {
	IsValidAPIKey(ctx context.Context, rawKey string) (bool, error)
}

type Validator struct {
	checker APIKeyChecker
}

func NewValidator(checker APIKeyChecker) *Validator {
	return &Validator{checker: checker}
}

func (v *Validator) Validate(ctx context.Context, key string) (bool, error) {
	if key == "" {
		return false, nil
	}
	return v.checker.IsValidAPIKey(ctx, key)
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
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
