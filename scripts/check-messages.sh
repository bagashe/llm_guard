#!/usr/bin/env bash
set -euo pipefail

kamal app exec --reuse "msgctl messages list -db /app/storage/llm_guard.db"
