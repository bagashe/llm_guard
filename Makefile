SHELL := /bin/bash

DIST_DIR := dist
SYSTEMS := linux darwin
ARCHES := amd64 arm64
CURRENT_OS := $(shell go env GOOS)
CURRENT_ARCH := $(shell go env GOARCH)

.PHONY: all build release clean train-prepare train-model validate-model smoke

all: build

build:
	@mkdir -p $(DIST_DIR)
	@echo "Building server for $(CURRENT_OS)/$(CURRENT_ARCH)"
	@CGO_ENABLED=0 GOOS=$(CURRENT_OS) GOARCH=$(CURRENT_ARCH) go build -o $(DIST_DIR)/server ./cmd/server
	@echo "Building apikeyctl for $(CURRENT_OS)/$(CURRENT_ARCH)"
	@CGO_ENABLED=0 GOOS=$(CURRENT_OS) GOARCH=$(CURRENT_ARCH) go build -o $(DIST_DIR)/apikeyctl ./cmd/apikeyctl

release:
	@mkdir -p $(DIST_DIR)
	@for os in $(SYSTEMS); do \
		for arch in $(ARCHES); do \
			echo "Building server for $$os/$$arch"; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -o $(DIST_DIR)/server-$$os-$$arch ./cmd/server || exit 1; \
			echo "Building apikeyctl for $$os/$$arch"; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -o $(DIST_DIR)/apikeyctl-$$os-$$arch ./cmd/apikeyctl || exit 1; \
		done; \
	done

clean:
	rm -rf $(DIST_DIR)

train-prepare:
	python3 -m uv run --project training python training/prepare_dataset.py --dataset-profile clean --out-dir training/data --oasst-benign-limit 30000 --min-safe-rows 20000

train-model:
	python3 -m uv run --project training python training/train_classifier.py --train training/data/train.jsonl --val training/data/val.jsonl --out models/classifier_v1.json --metrics-out training/artifacts/classifier_v1_metrics.json

validate-model:
	@test -f models/classifier_v1.json || (echo "missing model: models/classifier_v1.json" && exit 1)
	@go test ./internal/classifier -run TestPredictWithTrainedModel -count=1
	@go test ./internal/safety/rules -run TestClassifierRuleWithTrainedModel -count=1

smoke:
	@test -n "$(API_KEY)" || (echo "set API_KEY before running make smoke" && exit 1)
	@bash scripts/smoke.sh
