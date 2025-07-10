.PHONY: test test-integration test-unit build clean clean-test clean-all help build-cli

# Default target
help:
	@echo "Available commands:"
	@echo "  test          - Run all tests"
	@echo "  test-unit     - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  build         - Build the project"
	@echo "  build-cli     - Build the CLI binary"
	@echo "  clean         - Clean build artifacts"
	@echo "  clean-test    - Clean test artifacts (wallets, coverage)"
	@echo "  clean-all     - Clean all artifacts"
	@echo "  run-example   - Run the example application"

# Run all tests
test: test-unit test-integration

# Run unit tests only
test-unit:
	@echo "Running unit tests..."
	go test -v ./tests -run "TestUnit"

# Run integration tests only
test-integration:
	@echo "Running integration tests..."
	@if [ ! -f test_wallet_0.json ] || [ ! -f test_wallet_1.json ] || [ ! -f test_wallet_2.json ] || [ ! -f test_wallet_3.json ]; then \
		$(MAKE) generate-wallets-multi; \
	fi
	@if [ ! -f bin/p2p-node ]; then \
		$(MAKE) build-cli; \
	fi
	go test -v ./tests -run "TestIntegrationWithMultipleNodes" -timeout 10m

# Generate 4 wallets for integration tests
generate-wallets-multi: build-cli
	@echo "Generating 4 test wallets..."
	@for i in 0 1 2 3; do \
		if [ ! -f test_wallet_$$i.json ]; then \
			./bin/p2p-node -generate-wallet > test_wallet_$$i.json; \
			cat test_wallet_$$i.json; \
		else \
			echo "test_wallet_$$i.json already exists"; \
		fi; \
	 done

# Build the project
build:
	@echo "Building project..."
	go build -o bin/p2p-database .

# Build the CLI binary
build-cli:
	@echo "Building CLI binary..."
	go build -o bin/p2p-node ./cmd/p2p-node

# Build the example
build-example:
	@echo "Building example..."
	go build -o bin/example examples/main.go

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	go clean

# Clean test artifacts (wallets, coverage)
clean-test:
	@echo "Cleaning test artifacts..."
	rm -f test_wallet_*.json
	rm -f coverage.out coverage.html

# Full cleanup (build + test artifacts)
clean-all: clean clean-test
	@echo "All artifacts cleaned"

# Run the example application
run-example: build-example
	@echo "Running example application..."
	@echo "Usage: ./bin/example -pk <private_key>"
	@echo "Example: ./bin/example -pk 5g3euBKXqhdbfzkgbWQ7o1C6HQzbyr1noX6wiqfv2i3x"

# Run the CLI node
run-node: build-cli
	@echo "Running CLI node..."
	@echo "Usage: ./bin/p2p-node -wallet <private_key> -port <port> -http-port <http_port>"
	@echo "Example: ./bin/p2p-node -wallet <private_key> -port 3500 -http-port 8080"

# Generate a new wallet
generate-wallet: build-cli
	@echo "Generating new wallet..."
	./bin/p2p-node -generate-wallet

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod download

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./tests
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html" 