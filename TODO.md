# TODO

Planned features and safeguards for evolving llm_guard into a full proxy between users and downstream LLMs.

## Output scanning

- [x] Detect leaked system prompts / internal instructions in LLM responses (regex-based; upgrade to ML classifier for better recall and fewer false positives)
- [x] Flag credentials, API keys, or PII in output (regex + entropy-based; upgrade to ML model for context-aware detection)
- [ ] Block code execution payloads in responses (shell commands, SQL) when not expected

## Input hardening

- [ ] PII detection/redaction before forwarding to the LLM (emails, SSNs, credit cards)
- [ ] Embedding-based similarity to known jailbreak corpora for novel attack detection
- [ ] Multi-turn context tracking to catch slow jailbreaks that build up across turns

## Proxy-layer controls

- [ ] Per-key usage quotas (daily/monthly token or request budgets)
- [ ] Tool/function-call allow/deny lists per API key
- [ ] Model routing rules (different keys get access to different downstream models)
- [ ] Request/response audit log to a durable store for compliance and incident review

## Operational hardening

- [ ] Circuit breaker for downstream LLM (fail fast when slow/down)
- [ ] Response streaming passthrough with incremental safety scanning
- [ ] Webhook/alerting on high-severity detections
