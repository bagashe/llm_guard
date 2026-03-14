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
This profile includes Apache-2.0 / MIT / CC-BY-4.0 datasets and keeps synthetic fallback rows only for minimum label floors.

## 1) Build unified dataset

This script downloads selected corpora and maps them into a unified multi-label JSONL schema:

```bash
python3 -m uv run --project training python training/prepare_dataset.py --dataset-profile clean --out-dir training/data --oasst-benign-limit 30000 --min-safe-rows 20000
```

Optional source caps are available for newly integrated datasets:

- `--neuralchemy-limit`
- `--smooth3-limit`
- `--jackhhao-limit`
- `--aegis-unsafe-limit`
- `--aegis-safe-limit`

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

Tokenizer configuration is exported into the model file and must stay in parity with Go inference. The tokenizer is `char_ngram_wb` with lowercase normalization and default range `3..5`. Parity fixtures are stored in `training/tokenizer_fixtures.json` and validated by Go tests.

## 3) Run server with model

```bash
export CLASSIFIER_PATH=./models/classifier_v1.json
go run ./cmd/server
```

## Notes

- The classifier runs alongside GeoIP country blacklist checks.
- Server startup is fail-closed: if model load fails, startup fails.
- Review dataset licenses and usage terms before production training.
