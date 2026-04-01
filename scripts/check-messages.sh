#!/usr/bin/env bash
set -euo pipefail

while true; do
  echo "=== $(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
  kamal app exec --reuse "msgctl messages list -db /app/storage/llm_guard.db"
  sleep 60
done
