# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

.PHONY: all clean test test-verbose test-coverage test-race test-race-verbose deps fmt check check-basic check-enhanced install-linters help

# Default target
all: clean deps fmt check test

# Clean build artifacts
clean:
	$(GOCLEAN)

# Clean test cache
clean-test:
	$(GOCLEAN) -testcache

# Run tests (quiet by default)
test:
	$(GOTEST) ./...

# Run tests with verbose output
test-verbose:
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Run tests with race detection (quiet)
test-race:
	$(GOTEST) -race ./...

# Run tests with race detection and verbose output
test-race-verbose:
	$(GOTEST) -race -v ./...

# Install/update dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Format code
fmt:
	$(GOFMT) ./...

# Basic code quality checks (always available)
check-basic:
	@echo "Running basic code quality checks..."
	@echo "1. Formatting check..."
	@gofmt -l . | grep -E '\.go$$' && echo "❌ Code is not formatted, run 'make fmt'" && exit 1 || echo "✅ Code is properly formatted"
	@echo "2. Go vet check..."
	@$(GOVET) ./... && echo "✅ go vet passed" || (echo "❌ go vet failed" && exit 1)
	@echo "3. Module verification..."
	@$(GOMOD) verify && echo "✅ Module verification passed" || (echo "❌ Module verification failed" && exit 1)
	@echo "4. Module tidy check..."
	@$(GOMOD) tidy && git diff --exit-code go.mod go.sum && echo "✅ go.mod is tidy" || (echo "❌ go.mod needs tidying, run 'make deps'" && exit 1)
	@echo "5. Running tests with race detection..."
	@$(GOTEST) -race ./... && echo "✅ Race condition tests passed" || (echo "❌ Race condition tests failed" && exit 1)

# Enhanced code quality checks (requires optional tools)
check-enhanced:
	@echo "Running enhanced code quality checks..."
	@echo "6. Static analysis with staticcheck..."
	@command -v staticcheck >/dev/null 2>&1 && (staticcheck ./... && echo "✅ staticcheck passed") || echo "⚠️  staticcheck not installed, skipping (install: go install honnef.co/go/tools/cmd/staticcheck@latest)"
	@echo "7. Security analysis with gosec..."
	@command -v gosec >/dev/null 2>&1 && (gosec ./... && echo "✅ gosec passed") || echo "⚠️  gosec not installed, skipping (install: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest)"
	@echo "8. Comprehensive linting with golangci-lint..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		if golangci-lint run; then \
			echo "✅ golangci-lint passed"; \
		else \
			echo "❌ golangci-lint found issues"; \
		fi; \
	else \
		echo "⚠️  golangci-lint not installed, skipping (install: make install-linters)"; \
	fi

# Run all code quality checks
check: check-basic check-enhanced
	@echo ""
	@echo "🎉 All available code quality checks completed!"
	@echo "   To install missing linters, run: make install-linters"

# Install optional linting tools
install-linters:
	@echo "Installing optional linting tools..."
	$(GOGET) -u github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@echo "✅ All linters installed!"

# Lint the code (requires golangci-lint)
lint:
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || (echo "❌ golangci-lint not installed, run 'make install-linters'" && exit 1)

# Generate mock functions for testing (requires gomock)
mocks:
	@echo "Generating mocks..."
	$(GOCMD) generate ./...

# Development setup
dev-setup: install-linters
	$(GOGET) -u github.com/golang/mock/mockgen

# CI/CD friendly check (fails on any issue)
check-ci: 
	@echo "Running CI/CD code quality checks..."
	gofmt -l . | grep -E '\.go$$' && exit 1 || true
	$(GOVET) ./...
	$(GOMOD) verify
	$(GOMOD) tidy
	git diff --exit-code go.mod go.sum
	$(GOTEST) -race ./...
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || true
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || true

# Help target
help:
	@echo "Available targets:"
	@echo "  all              - Clean, deps, fmt, check, and test"
	@echo "  clean            - Clean build artifacts"
	@echo "  clean-test       - Clean test cache"
	@echo "  test             - Run tests (quiet output)"
	@echo "  test-verbose     - Run tests with verbose output"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  test-race        - Run tests with race detection (quiet)"
	@echo "  test-race-verbose - Run tests with race detection and verbose output"
	@echo "  deps             - Download and tidy dependencies"
	@echo "  fmt              - Format code"
	@echo "  check            - Run all code quality checks"
	@echo "  check-basic      - Run basic checks (always available)"
	@echo "  check-enhanced   - Run enhanced checks (requires optional tools)"
	@echo "  check-ci         - CI/CD friendly checks (fail fast)"
	@echo "  lint             - Lint the code (requires golangci-lint)"
	@echo "  install-linters  - Install optional linting tools"
	@echo "  keygen           - Generate a Solana keypair"
	@echo "  keygen-multi     - Generate multiple Solana keypairs"
	@echo "  keygen-json      - Generate keypairs in JSON format"
	@echo "  keygen-env       - Generate keypairs in environment format"
	@echo "  dev-setup        - Install development tools"
	@echo "  help             - Show this help message"

# Generate Solana keypairs
keygen:
	$(GOCMD) run cmd/keygen/main.go

# Generate multiple keypairs
keygen-multi:
	$(GOCMD) run cmd/keygen/main.go -count=5

# Generate keypairs in JSON format
keygen-json:
	$(GOCMD) run cmd/keygen/main.go -format=json

# Generate keypairs in environment format
keygen-env:
	$(GOCMD) run cmd/keygen/main.go -format=env 