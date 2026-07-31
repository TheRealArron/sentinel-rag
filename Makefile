# Sentinel RAG
#
# `make help` lists everything. `make demo` is the two-second version.

SHELL       := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GO       ?= go
PYTHON   ?= python3
BIN      := ingestor/bin/sentinel-ingestor
SAMPLE   := data/samples/sample_syslog.log
EVENTS   := data/events.jsonl

export PYTHONPATH := $(CURDIR)/engine

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nSentinel RAG — targets\n\n"} \
		/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
	@echo

##@ Quick start

.PHONY: demo
demo: ## End-to-end walkthrough (no Go, no Docker, no API key needed)
	$(PYTHON) -m sentinel demo

.PHONY: serve
serve: ## Run the dashboard on http://127.0.0.1:8000/
	$(PYTHON) -m sentinel serve

.PHONY: install
install: ## Install the Python engine's optional dependencies
	$(PYTHON) -m pip install -r engine/requirements.txt

.PHONY: install-dev
install-dev: ## Install dependencies plus the dev toolchain
	$(PYTHON) -m pip install -r engine/requirements-dev.txt

##@ Go ingestor

.PHONY: build
build: ## Build the ingestor binary
	@mkdir -p ingestor/bin
	cd ingestor && $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" \
		-o bin/sentinel-ingestor ./cmd/sentinel-ingestor
	@echo "built $(BIN) ($(VERSION))"

.PHONY: test-go
test-go: ## Run Go tests with the race detector
	cd ingestor && $(GO) test -race -count=1 ./...

.PHONY: cover-go
cover-go: ## Go tests with a coverage report
	cd ingestor && $(GO) test -race -coverprofile=coverage.out ./... && \
		$(GO) tool cover -func=coverage.out | tail -1

.PHONY: bench
bench: ## Benchmark the ingest pipeline
	cd ingestor && $(GO) test -bench=. -benchmem -run '^$$' ./...

.PHONY: fmt
fmt: ## Format Go sources
	cd ingestor && $(GO) fmt ./...

.PHONY: vet
vet: ## go vet + gofmt check
	cd ingestor && $(GO) vet ./...
	@unformatted=$$(cd ingestor && gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed:"; echo "$$unformatted"; exit 1; \
	fi

##@ Pipeline

.PHONY: ingest
ingest: build ## Parse the sample syslog into data/events.jsonl
	@mkdir -p data
	@rm -f $(EVENTS)
	./$(BIN) -in $(SAMPLE) -out $(EVENTS) -stats
	@echo "wrote $$(wc -l < $(EVENTS)) events to $(EVENTS)"

.PHONY: ingest-host
ingest-host: build ## Follow this host's /var/log/auth.log (Ctrl-C to stop)
	@mkdir -p data
	./$(BIN) -in /var/log/auth.log -out $(EVENTS) -follow -from-start -stats

.PHONY: sample
sample: build ## Regenerate the committed sample fixture from the ingestor
	@# TZ=UTC is required, not cosmetic. RFC 3164 timestamps carry no timezone, so
	@# the ingestor reads them in the host's local zone and normalises to UTC —
	@# meaning this fixture would otherwise differ between a developer in
	@# Asia/Tokyo and a CI runner in UTC, and the drift check would cry wolf on
	@# every machine.
	TZ=UTC ./$(BIN) -in $(SAMPLE) -out - > data/samples/events.sample.jsonl
	@echo "regenerated data/samples/events.sample.jsonl ($$(wc -l < data/samples/events.sample.jsonl) events)"
	@git diff --stat data/samples/events.sample.jsonl 2>/dev/null || true

.PHONY: index
index: ## Build the hierarchical index
	$(PYTHON) -m sentinel index

.PHONY: reindex
reindex: ## Drop and rebuild the index
	$(PYTHON) -m sentinel index --rebuild

.PHONY: analyze
analyze: ## Triage the most severe recent events
	$(PYTHON) -m sentinel analyze --min-score 60

.PHONY: stats
stats: ## Show engine statistics
	$(PYTHON) -m sentinel stats

##@ Python engine

.PHONY: test-py
test-py: ## Run the Python test suite
	cd engine && $(PYTHON) -m pytest tests/ -q

.PHONY: cover-py
cover-py: ## Python tests with a coverage report
	cd engine && $(PYTHON) -m pytest tests/ --cov=sentinel --cov-report=term-missing

.PHONY: lint
lint: ## Lint and type-check the Python engine
	cd engine && $(PYTHON) -m ruff check sentinel tests
	cd engine && $(PYTHON) -m mypy sentinel --ignore-missing-imports || true

.PHONY: format
format: ## Auto-fix Python lint findings
	cd engine && $(PYTHON) -m ruff check --fix sentinel tests
	cd engine && $(PYTHON) -m ruff format sentinel tests

##@ Everything

.PHONY: test
test: test-go test-py ## Run both test suites

.PHONY: check
check: vet lint test ## Full pre-commit check

##@ Docker

.PHONY: up
up: ## Start the stack
	docker compose up --build -d
	@echo "dashboard: http://127.0.0.1:$${SENTINEL_API_PORT:-8000}/"

.PHONY: down
down: ## Stop the stack
	docker compose down

.PHONY: logs
logs: ## Follow container logs
	docker compose logs -f

.PHONY: docker-build
docker-build: ## Build both images without starting them
	docker compose build

##@ Housekeeping

.PHONY: clean
clean: ## Remove build output and generated data (keeps the corpus)
	rm -rf ingestor/bin ingestor/coverage.out
	rm -rf data/index data/chroma data/models
	rm -f data/events.jsonl data/audit.log
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "cleaned"

.PHONY: version
version: ## Print the version string
	@echo $(VERSION)
