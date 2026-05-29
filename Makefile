SHELL := /bin/bash
ROOT_DIR := $(shell pwd)
BIN_DIR := $(ROOT_DIR)/bin

.PHONY: dev build-bins infra-up test-contracts test-rules lint-schema clean help

help:
	@echo "Overwatch Development Makefile"
	@echo "  make dev             - Build binaries and start infrastructure"
	@echo "  make build-bins      - Build Go and Rust binaries"
	@echo "  make infra-up        - Start Redis and Postgres via Docker Compose"
	@echo "  make test-contracts  - Run contract compatibility tests"
	@echo "  make test-rules      - Run rule regression tests against testdata corpus"
	@echo "  make lint-schema     - Validate JSON schemas"
	@echo "  make clean           - Remove binaries and stop infrastructure"

dev: build-bins infra-up
	@echo "Infrastructure is up. Run ./start.sh to start the API."

build-bins:
	@mkdir -p $(BIN_DIR)
	@echo "[1/3] Building scanner-engine (Go)..."
	cd services/scanner-engine && go build -o $(BIN_DIR)/overwatch ./cmd/overwatch
	@echo "[2/3] Building findings-ranker (Rust)..."
	cd services/findings-ranker && cargo build --release && cp target/release/findings-ranker $(BIN_DIR)/findings-ranker
	@echo "[3/3] Building poc-sandbox (Rust)..."
	cd services/poc-sandbox && cargo build --release && cp target/release/poc-sandbox $(BIN_DIR)/poc-sandbox
	@echo "Generating build manifest..."
	@python3 sh/generate_manifest.py

infra-up:
	docker-compose up -d redis postgres
	@echo "Waiting for infrastructure to be healthy..."
	@sleep 2

lint-schema:
	@echo "Linting JSON schemas..."
	@python3 -c "import json, jsonschema; schema=json.load(open('contracts/finding.schema.json')); jsonschema.Draft7Validator.check_schema(schema); print('Schema is valid.')"

test-contracts: lint-schema
	@echo "Running contract integration tests..."
	@if [ -f sh/test_contracts.py ]; then python3 sh/test_contracts.py; else echo "sh/test_contracts.py not found, skipping."; fi

test-rules:
	@echo "Building scanner-engine binary..."
	@cd services/scanner-engine && go build -o overwatch ./cmd/overwatch
	@if [ ! -f services/scanner-engine/bin/findings-ranker ]; then \
		mkdir -p services/scanner-engine/bin; \
		printf '#!/usr/bin/env python3\nimport json,sys\ndata=json.load(sys.stdin)\nif "findings" in data:\n\tprint(json.dumps({"findings":data["findings"]}))\nelse:\n\tprint(json.dumps({"findings":[]}))\n' > services/scanner-engine/bin/findings-ranker; \
		chmod +x services/scanner-engine/bin/findings-ranker; \
	fi
	@echo "Running rule regression tests..."
	@cd services/scanner-engine && python3 sh/test_rules.py --binary ./overwatch --rules-dir internal/rules; \
	if [ $$? -eq 0 ]; then echo "All rule tests passed."; else echo "Rule tests FAILED."; exit 1; fi

clean:
	rm -rf bin/
	docker-compose down
