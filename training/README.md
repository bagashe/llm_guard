# Training Pipeline

This folder contains the classifier training workflow used by `llm_guard`.

## Output locations

- Training code/data: `./training`
- Exported runtime models: `./models`

## Prerequisites

```bash
python3 -m uv sync --project training
```

Default training uses the clean-license dataset profile documented in `training/DATASETS.md`.
This includes external benign rows (OpenAssistant Apache-2.0) and in-repo synthetic benign fallback rows.

## 1) Build unified dataset

This script downloads selected corpora and maps them into a unified multi-label JSONL schema:

```bash
python3 -m uv run --project training python training/prepare_dataset.py --dataset-profile clean --out-dir training/data --oasst-benign-limit 30000 --min-safe-rows 20000
```

Generated files:

- `training/data/train.jsonl`
- `training/data/val.jsonl`

Row schema:

```json
{"text":"...","labels":["prompt_injection","host_takeover_or_jailbreak"]}
```

## 2) Train classifier

```bash
python3 -m uv run --project training python training/train_classifier.py \
  --train training/data/train.jsonl \
  --val training/data/val.jsonl \
  --out models/classifier_v1.json \
  --metrics-out training/artifacts/classifier_v1_metrics.json
```

The output model is consumed by the Go service through `CLASSIFIER_PATH`.
Metrics are saved to `training/artifacts/classifier_v1_metrics.json`.

Tokenizer configuration is exported into the model file and must stay in parity with Go inference. The tokenizer is Unicode-aware (`[\p{L}\p{N}_]+`). Parity fixtures are stored in `training/tokenizer_fixtures.json` and validated by Go tests.

## 3) Run server with model

```bash
export CLASSIFIER_PATH=./models/classifier_v1.json
go run ./cmd/server
```

## Notes

- The classifier runs alongside GeoIP country blacklist checks.
- Server startup is fail-closed: if model load fails, startup fails.
- Review dataset licenses and usage terms before production training.
