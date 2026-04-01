#!/usr/bin/env bash
set -euo pipefail

kamal exec --reuse -c "msgctl messages list -db /app/storage/llm_guard.db"
