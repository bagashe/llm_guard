package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"llm_guard/internal/config"
	"llm_guard/internal/geoip"
	"llm_guard/internal/registration"
	"llm_guard/internal/safety"
)

type Dependencies struct {
	Config              config.Config
	Engine              *safety.Engine
	AuthMiddleware      func(http.Handler) http.Handler
	RateLimitMiddleware func(http.Handler) http.Handler
	CountryResolver     geoip.Resolver
	ChallengeStore      *registration.ChallengeStore // nil → registration routes not mounted
	KeyCreator          registration.KeyCreator      // nil → registration routes not mounted
}

type evaluateRequest struct {
	Message     string `json:"message"`
	MessageType string `json:"message_type"`
}

func NewRouter(dep Dependencies) http.Handler {
	r := chi.NewRouter()
	r.Use(requestLoggingMiddleware(dep.Config.TrustProxyHeaders, dep.Config.Debug))

	r.Get("/", serveIndex)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Get("/openapi.json", serveOpenAPISpec)

	r.Route("/v1", func(v1 chi.Router) {
		// Public self-registration endpoints (no auth required).
		// Only mounted when both ChallengeStore and KeyCreator are provided.
		if dep.ChallengeStore != nil && dep.KeyCreator != nil {
			v1.Post("/register/challenge", func(w http.ResponseWriter, r *http.Request) {
				handleRegisterChallenge(w, r, dep)
			})
			v1.Post("/register/solve", func(w http.ResponseWriter, r *http.Request) {
				handleRegisterSolve(w, r, dep)
			})
		}

		// Authenticated and rate-limited routes.
		v1.Group(func(a chi.Router) {
			a.Use(dep.AuthMiddleware)
			if dep.RateLimitMiddleware != nil {
				a.Use(dep.RateLimitMiddleware)
			}
			a.Post("/evaluate", func(w http.ResponseWriter, r *http.Request) {
				handleEvaluate(w, r, dep)
			})
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message_type must be one of: user, system, tool_call, tool_result, assistant"})
		return
	}
	setAuditMessageType(w, req.MessageType)
	if req.MessageType == string(safety.MessageTypeToolCall) {
		setAuditToolCallDetails(w, req.Message)
	}
	// Message-type policy notes:
	// - user: run the full safety engine (classifier + policy rules).
	// - system: currently pass-through as safe=true, to be expanded later.
	//   Future checks could include policy leakage markers, unsafe instruction
	//   generation, sensitive data reflection, and response-policy drift.
	// - tool_call: evaluated by tool-call specific rules.
	if req.MessageType == string(safety.MessageTypeSystem) {
		writeJSON(w, http.StatusOK, safety.Result{Safe: true, Reasons: []safety.Reason{}, RiskScore: 0})
		return
	}

	sourceIP := extractClientIP(r, dep.Config.TrustProxyHeaders)
	isLocal := safety.IsPrivateOrLocalIP(sourceIP)

	resultInput := safety.Input{Message: req.Message, MessageType: safety.MessageType(req.MessageType), ClientIP: sourceIP}
	if sourceIP != "" && !isLocal {
		if ip := net.ParseIP(sourceIP); ip != nil {
			code, err := dep.CountryResolver.CountryCode(ip)
			if err != nil {
				if dep.Config.FailClosed {
					writeJSON(w, http.StatusForbidden, safety.Result{
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
	if res.IsCountryBlocked() {
		writeJSON(w, http.StatusForbidden, res)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

type challengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Difficulty  int    `json:"difficulty"`
	ExpiresAt   string `json:"expires_at"`
}

type solveRequest struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
}

type solveResponse struct {
	APIKey     string `json:"api_key"`
	Name       string `json:"name"`
	DailyLimit int64  `json:"daily_limit"`
}

func handleRegisterChallenge(w http.ResponseWriter, r *http.Request, dep Dependencies) {
	clientIP := extractClientIP(r, dep.Config.TrustProxyHeaders)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	c, err := dep.ChallengeStore.IssueChallenge(clientIP)
	if err != nil {
		if errors.Is(err, registration.ErrIPRateLimited) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error":  "too many registration attempts",
				"detail": "maximum 5 challenges per 10 minutes per IP",
			})
			return
		}
		if dep.Config.Debug {
			log.Printf("level=error msg=\"issue challenge\" err=%v", err)
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, challengeResponse{
		ChallengeID: c.ID,
		Difficulty:  dep.Config.RegistrationDifficulty,
		ExpiresAt:   c.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func handleRegisterSolve(w http.ResponseWriter, r *http.Request, dep Dependencies) {
	body := http.MaxBytesReader(w, r.Body, dep.Config.MaxBodyBytes)
	defer body.Close()

	var req solveRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(req.ChallengeID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge_id is required"})
		return
	}
	if strings.TrimSpace(req.Nonce) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nonce is required"})
		return
	}

	if _, err := dep.ChallengeStore.VerifySolution(req.ChallengeID, req.Nonce); err != nil {
		switch {
		case errors.Is(err, registration.ErrChallengeNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "challenge not found"})
		case errors.Is(err, registration.ErrChallengeExpired):
			writeJSON(w, http.StatusGone, map[string]string{"error": "challenge expired"})
		case errors.Is(err, registration.ErrAlreadySolved):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "challenge already used"})
		case errors.Is(err, registration.ErrInvalidSolution):
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "invalid proof of work solution"})
		default:
			if dep.Config.Debug {
				log.Printf("level=error msg=\"verify solution\" err=%v", err)
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}

	rawKey, err := registration.GenerateKey()
	if err != nil {
		if dep.Config.Debug {
			log.Printf("level=error msg=\"generate key\" err=%v", err)
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	// Random 4-char suffix prevents name collision when two registrations
	// arrive within the same second.
	suffix, err := registration.GenerateKey()
	if err != nil {
		if dep.Config.Debug {
			log.Printf("level=error msg=\"generate key suffix\" err=%v", err)
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	name := fmt.Sprintf("agent-%d-%s", time.Now().Unix(), suffix[:4])

	ctx := context.Background()
	if err := dep.KeyCreator.CreateAPIKey(ctx, name, rawKey); err != nil {
		if dep.Config.Debug {
			log.Printf("level=error msg=\"create api key\" err=%v", err)
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if err := dep.KeyCreator.SetDailyQuotaByName(ctx, name, dep.Config.RegistrationDefaultDailyLimit); err != nil {
		if dep.Config.Debug {
			log.Printf("level=error msg=\"set daily quota\" err=%v", err)
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	// Return the key exactly once. It is never logged.
	writeJSON(w, http.StatusOK, solveResponse{
		APIKey:     rawKey,
		Name:       name,
		DailyLimit: dep.Config.RegistrationDefaultDailyLimit,
	})
}

func isValidMessageType(v string) bool {
	switch safety.MessageType(strings.TrimSpace(v)) {
	case safety.MessageTypeUser, safety.MessageTypeSystem, safety.MessageTypeToolCall, safety.MessageTypeToolResult, safety.MessageTypeAssistant:
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
	status        int
	responseBody  bytes.Buffer
	bodyTruncated bool
	messageType   string
	toolName      string
	toolArgs      string
}

const maxAuditToolArgsLen = 512

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	const maxCaptureBytes = 4096
	if !r.bodyTruncated {
		remaining := maxCaptureBytes - r.responseBody.Len()
		if remaining > 0 {
			if len(p) <= remaining {
				_, _ = r.responseBody.Write(p)
			} else {
				_, _ = r.responseBody.Write(p[:remaining])
				r.bodyTruncated = true
			}
		} else {
			r.bodyTruncated = true
		}
	}
	return r.ResponseWriter.Write(p)
}

func (r *statusRecorder) setAuditMessageType(v string) {
	r.messageType = strings.TrimSpace(v)
}

func (r *statusRecorder) setAuditToolCallDetails(message string) {
	name, args := extractToolCallAuditFields(message)
	r.toolName = name
	r.toolArgs = args
}

func requestLoggingMiddleware(trustProxyHeaders bool, debug bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			clientIP := extractClientIP(r, trustProxyHeaders)
			if clientIP == "" {
				clientIP = r.RemoteAddr
			}

			messageTypeField := "na"
			if rec.messageType != "" {
				messageTypeField = rec.messageType
			}
			toolNameField := "na"
			if rec.toolName != "" {
				toolNameField = rec.toolName
			}

			if !debug {
				log.Printf("level=info method=%s path=%s status=%d duration_ms=%d remote_addr=%s message_type=%s tool_name=%q",
					r.Method,
					r.URL.Path,
					rec.status,
					time.Since(start).Milliseconds(),
					clientIP,
					messageTypeField,
					toolNameField,
				)
				return
			}

			safeField, riskScoreField, reasonIDsField := auditFieldsFromResponse(r.URL.Path, rec.status, rec.responseBody.Bytes())
			toolArgsField := "na"
			if rec.toolArgs != "" {
				toolArgsField = rec.toolArgs
			}
			log.Printf("level=info method=%s path=%s status=%d duration_ms=%d remote_addr=%s message_type=%s tool_name=%q tool_args=%q safe=%s risk_score=%s reason_ids=%s",
				r.Method,
				r.URL.Path,
				rec.status,
				time.Since(start).Milliseconds(),
				clientIP,
				messageTypeField,
				toolNameField,
				toolArgsField,
				safeField,
				riskScoreField,
				reasonIDsField,
			)
		})
	}
}

type auditMessageTypeSetter interface {
	setAuditMessageType(string)
}

type auditToolCallSetter interface {
	setAuditToolCallDetails(string)
}

func setAuditMessageType(w http.ResponseWriter, messageType string) {
	if setter, ok := w.(auditMessageTypeSetter); ok {
		setter.setAuditMessageType(messageType)
	}
}

func setAuditToolCallDetails(w http.ResponseWriter, message string) {
	if setter, ok := w.(auditToolCallSetter); ok {
		setter.setAuditToolCallDetails(message)
	}
}

func extractToolCallAuditFields(message string) (string, string) {
	message = strings.TrimSpace(message)
	if message == "" {
		return "unknown", "none"
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(message), &payload); err != nil {
		return "unparsed", message
	}

	toolName := firstString(payload, "tool", "tool_name", "name")
	if toolName == "" {
		toolName = "unknown"
	}

	toolArgs := firstRawJSON(payload, "arguments", "args")
	if toolArgs == "" {
		toolArgs = "none"
	}
	toolArgs = truncateForAudit(toolArgs, maxAuditToolArgsLen)

	return toolName, toolArgs
}

func truncateForAudit(v string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(v) <= maxLen {
		return v
	}
	const suffix = "...<truncated>"
	if maxLen <= len(suffix) {
		return suffix[:maxLen]
	}
	return v[:maxLen-len(suffix)] + suffix
}

func firstString(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		v, ok := payload[key]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s != "" {
			return s
		}
	}
	return ""
}

func firstRawJSON(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		v, ok := payload[key]
		if !ok {
			continue
		}
		b, err := json.Marshal(v)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(b))
		if s != "" {
			return s
		}
	}
	return ""
}

func auditFieldsFromResponse(path string, status int, body []byte) (string, string, string) {
	if path != "/v1/evaluate" || status != http.StatusOK || len(body) == 0 {
		return "na", "na", "na"
	}

	var result safety.Result
	if err := json.Unmarshal(body, &result); err != nil {
		return "parse_error", "parse_error", "parse_error"
	}

	reasonIDs := make([]string, 0, len(result.Reasons))
	for _, reason := range result.Reasons {
		reasonID := strings.TrimSpace(reason.RuleID)
		if reasonID != "" {
			reasonIDs = append(reasonIDs, reasonID)
		}
	}
	if len(reasonIDs) == 0 {
		reasonIDs = []string{"none"}
	}

	return strconv.FormatBool(result.Safe), floatToAuditString(result.RiskScore), strings.Join(reasonIDs, ",")
}

func floatToAuditString(v float64) string {
	return strconv.FormatFloat(v, 'f', 4, 64)
}
