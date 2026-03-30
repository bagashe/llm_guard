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
- **Input Sentry**: parse and validate request shape, size, and `message_type` (`user`, `assistant`, `system`, `tool_call`, `tool_result`).
- **Geo Sentry**: map client IP to country using GeoLite2 `.mmdb` and enforce country blacklist policy.
- **Classifier Sentry**: ML-based detection of prompt injection, exfiltration intent, and host takeover on user messages.
- **Output Sentry**: detect leaked system prompts and credentials/secrets in assistant responses (regex + Shannon entropy).
- **Policy Sentry**: evaluate safety rules and aggregate risk into final decisions.
- **Decision Output**: return `safe`, `reasons`, and `risk_score` for downstream routing.

## Extensibility contract

New safeguards should be added as independent rules implementing the existing safety rule interface and registered in server bootstrapping.

Shipped safeguards (beyond the core classifier):

- PII detection on user input (flag-only: email, SSN, credit card, phone)
- Tool-call safety rules (domain blacklist, internal network access, redirect resolution, command policy, SQL policy)
- Tool-result secret/credential scanning
- Per-key daily usage quotas
- Self-registration via proof-of-work (agents provision their own API keys)

Examples of planned additions:

- PII redaction/anonymisation on input
- Embedding-based jailbreak similarity
- Multi-turn context tracking
- Tool-use allow/deny controls
- Code execution payload blocking in output
- Reputation and threat-intel signals

## Integration pattern for consuming agents

Agents integrate by calling `POST /v1/evaluate` at four points in the agent loop:

1. **User input received** → `message_type=user` — before the LLM sees it (injection, malicious intent, PII)
2. **LLM emits a tool call** → `message_type=tool_call` — before executing (dangerous commands, blacklisted domains, SQL injection)
3. **Tool returns a result** → `message_type=tool_result` — before passing back to the LLM (secret/credential leakage)
4. **LLM produces output** → `message_type=assistant` — before returning to the caller (system prompt leakage, exposed secrets)

`system` messages are pass-through — no rules apply, skip evaluation.

On `safe=false`: halt at that step. Do not forward the message.

`input.pii_detection` fires at low severity and appears in `reasons` without flipping `safe` to `false` — handle according to your own data policy.

Agents without an API key self-register via the proof-of-work flow (`/v1/register/challenge` → `/v1/register/solve`). The key is returned once.

## Non-goals

- This service is not an LLM orchestration layer.
- This service is not responsible for downstream LLM inference.
- This service should not expose sensitive internals in error responses.

## Operational principles

- Prefer deterministic, explainable checks over opaque behavior.
- Log request outcomes consistently for observability.
- Preserve compatibility of public API response fields.
- Keep secrets out of logs and source control.
- Never log message content, tool arguments, or API keys. Client IP is logged for security auditing; tool arguments are only logged when `DEBUG=true`.
- Keep tokenizer parity between training and inference: the Go tokenizer must implement the exact same algorithm/config used during Python training, and parity tests must be updated with any tokenizer changes.
