package api

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
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
	r.Use(requestLoggingMiddleware(dep.Config.TrustProxyHeaders))

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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message_type must be one of: user, system, tool_call, assistant"})
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
	case safety.MessageTypeUser, safety.MessageTypeSystem, safety.MessageTypeToolCall, safety.MessageTypeAssistant:
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

func requestLoggingMiddleware(trustProxyHeaders bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			clientIP := extractClientIP(r, trustProxyHeaders)
			if clientIP == "" {
				clientIP = r.RemoteAddr
			}

			safeField, riskScoreField, reasonIDsField := auditFieldsFromResponse(r.URL.Path, rec.status, rec.responseBody.Bytes())
			messageTypeField := "na"
			if rec.messageType != "" {
				messageTypeField = rec.messageType
			}
			toolNameField := "na"
			toolArgsField := "na"
			if rec.toolName != "" {
				toolNameField = rec.toolName
			}
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
