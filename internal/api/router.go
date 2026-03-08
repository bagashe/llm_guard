package api

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"llm_guard/internal/config"
	"llm_guard/internal/geoip"
	"llm_guard/internal/safety"
)

type Dependencies struct {
	Config              config.Config
	Engine              *safety.Engine
	AuthMiddleware      func(http.Handler) http.Handler
	RateLimitMiddleware func(http.Handler) http.Handler
	CountryResolver     geoip.Resolver
}

type evaluateRequest struct {
	Message     string `json:"message"`
	MessageType string `json:"message_type"`
	Context     struct {
		ClientSignals struct {
			IP        string `json:"ip"`
			UserAgent string `json:"user_agent"`
		} `json:"client_signals"`
	} `json:"context"`
}

func NewRouter(dep Dependencies) http.Handler {
	r := chi.NewRouter()
	r.Use(requestLoggingMiddleware)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Route("/v1", func(v1 chi.Router) {
		v1.Use(dep.AuthMiddleware)
		if dep.RateLimitMiddleware != nil {
			v1.Use(dep.RateLimitMiddleware)
		}
		v1.Post("/evaluate", func(w http.ResponseWriter, r *http.Request) {
			handleEvaluate(w, r, dep)
		})
	})

	return r
}

func handleEvaluate(w http.ResponseWriter, r *http.Request, dep Dependencies) {
	body := http.MaxBytesReader(w, r.Body, dep.Config.MaxBodyBytes)
	defer body.Close()

	var req evaluateRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	if strings.TrimSpace(req.Message) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message is required"})
		return
	}
	if !isValidMessageType(req.MessageType) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message_type must be one of: user, system, tool_call"})
		return
	}
	// Message-type policy notes:
	// - user: run the full safety engine (classifier + policy rules).
	// - system: currently pass-through as safe=true, to be expanded later.
	//   Future checks could include policy leakage markers, unsafe instruction
	//   generation, sensitive data reflection, and response-policy drift.
	// - tool_call: currently pass-through as safe=true, to be expanded later.
	//   Future checks could include strict JSON/schema validation, tool allow/
	//   deny lists, argument risk scanning, and per-tool semantic validators.
	if req.MessageType == string(safety.MessageTypeSystem) || req.MessageType == string(safety.MessageTypeToolCall) {
		writeJSON(w, http.StatusOK, safety.Result{Safe: true, Reasons: []safety.Reason{}, RiskScore: 0})
		return
	}

	ipStr := strings.TrimSpace(req.Context.ClientSignals.IP)
	if ipStr == "" {
		ipStr = extractClientIP(r, dep.Config.TrustProxyHeaders)
	}

	resultInput := safety.Input{Message: req.Message, MessageType: safety.MessageType(req.MessageType), ClientIP: ipStr}
	if ipStr != "" {
		if ip := net.ParseIP(ipStr); ip != nil {
			code, err := dep.CountryResolver.CountryCode(ip)
			if err != nil {
				if dep.Config.FailClosed {
					writeJSON(w, http.StatusOK, safety.Result{
						Safe:      false,
						RiskScore: 1.0,
						Reasons: []safety.Reason{{
							RuleID:   "geoip.lookup_failed",
							Severity: "high",
							Detail:   "failed to resolve country from client ip",
						}},
					})
					return
				}
			} else {
				resultInput.CountryCode = code
			}
		}
	}

	res := dep.Engine.Evaluate(r.Context(), resultInput)
	writeJSON(w, http.StatusOK, res)
}

func isValidMessageType(v string) bool {
	switch safety.MessageType(strings.TrimSpace(v)) {
	case safety.MessageTypeUser, safety.MessageTypeSystem, safety.MessageTypeToolCall:
		return true
	default:
		return false
	}
}

func extractClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
		if xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				candidate := strings.TrimSpace(parts[0])
				if net.ParseIP(candidate) != nil {
					return candidate
				}
			}
		}

		xri := strings.TrimSpace(r.Header.Get("X-Real-IP"))
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && net.ParseIP(host) != nil {
		return host
	}

	if net.ParseIP(r.RemoteAddr) != nil {
		return r.RemoteAddr
	}

	return ""
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func requestLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("level=info method=%s path=%s status=%d duration_ms=%d remote_addr=%s",
			r.Method,
			r.URL.Path,
			rec.status,
			time.Since(start).Milliseconds(),
			r.RemoteAddr,
		)
	})
}
