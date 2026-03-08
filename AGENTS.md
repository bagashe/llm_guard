# AGENTS

## Mission

This REST API is a **Sentry** layer that evaluates untrusted user prompts before they are sent to downstream LLMs. Its primary job is to reduce prompt injection, data exfiltration attempts, and host-takeover style abuse by making a safe/unsafe decision with explainable reasons.

## Product intent

- Treat inbound prompt content as hostile by default.
- Enforce API key authentication for all protected endpoints.
- Apply fail-closed behavior when critical checks fail.
- Return decisions with machine-readable reasons for auditability.
- Keep the system modular so new safeguards can be added quickly.

## Core responsibilities

- **Auth Sentry**: validate Bearer API keys from SQLite-backed key storage.
- **Input Sentry**: parse and validate request shape and size.
- **Geo Sentry**: map client IP to country using GeoLite2 `.mmdb` and enforce country blacklist policy.
- **Policy Sentry**: evaluate safety rules and aggregate risk into final decisions.
- **Decision Output**: return `safe`, `reasons`, and `risk_score` for downstream routing.

## Extensibility contract

New safeguards should be added as independent rules implementing the existing safety rule interface and registered in server bootstrapping.

Examples of planned additions:

- Country/region/ASN controls
- Bag-of-words and regex filters
- Context-aware policy rules
- Tool-use allow/deny controls
- Reputation and threat-intel signals

## Non-goals

- This service is not an LLM orchestration layer.
- This service is not responsible for model inference.
- This service should not expose sensitive internals in error responses.

## Operational principles

- Prefer deterministic, explainable checks over opaque behavior.
- Log request outcomes consistently for observability.
- Preserve compatibility of public API response fields.
- Keep secrets out of logs and source control.
