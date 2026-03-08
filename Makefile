SHELL := /bin/bash

DIST_DIR := dist
SYSTEMS := linux darwin
ARCHES := amd64 arm64
CURRENT_OS := $(shell go env GOOS)
CURRENT_ARCH := $(shell go env GOARCH)

.PHONY: all build release clean

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
