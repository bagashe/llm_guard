# AGENTS

## Mission

This REST API is a **Sentry** layer that evaluates both untrusted user prompts and LLM responses. Its primary job is to reduce prompt injection, data exfiltration attempts, host-takeover style abuse, system prompt leakage, and secret/credential exposure by making a safe/unsafe decision with explainable reasons.

## Product intent

- Treat inbound prompt content as hostile by default.
- Scan LLM output for leaked system prompts, credentials, and secrets.
- Enforce API key authentication for all protected endpoints.
- Apply per-key rate limiting and usage tracking.
- Apply fail-closed behavior when critical checks fail.
- Return decisions with machine-readable reasons for auditability.
- Keep the system modular so new safeguards can be added quickly.

## Core responsibilities

- **Auth Sentry**: validate Bearer API keys from SQLite-backed key storage.
- **Rate Limiter**: per-key in-memory token bucket rate limiting.
- **Input Sentry**: parse and validate request shape, size, and `message_type` (`user`, `assistant`, `system`, `tool_call`).
- **Geo Sentry**: map client IP to country using GeoLite2 `.mmdb` and enforce country blacklist policy.
- **Classifier Sentry**: ML-based detection of prompt injection, exfiltration intent, and host takeover on user messages.
- **Output Sentry**: detect leaked system prompts and credentials/secrets in assistant responses (regex + Shannon entropy).
- **Policy Sentry**: evaluate safety rules and aggregate risk into final decisions.
- **Decision Output**: return `safe`, `reasons`, and `risk_score` for downstream routing.

## Extensibility contract

New safeguards should be added as independent rules implementing the existing safety rule interface and registered in server bootstrapping.

Examples of planned additions:

- PII detection/redaction on input
- Embedding-based jailbreak similarity
- Multi-turn context tracking
- Tool-use allow/deny controls
- Code execution payload blocking in output
- Per-key usage quotas
- Reputation and threat-intel signals

## Non-goals

- This service is not an LLM orchestration layer.
- This service is not responsible for downstream LLM inference.
- This service should not expose sensitive internals in error responses.

## Operational principles

- Prefer deterministic, explainable checks over opaque behavior.
- Log request outcomes consistently for observability.
- Preserve compatibility of public API response fields.
- Keep secrets out of logs and source control.
- Keep tokenizer parity between training and inference: the Go tokenizer must implement the exact same algorithm/config used during Python training, and parity tests must be updated with any tokenizer changes.
