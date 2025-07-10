# Example run
```
go build examples/main.go

./main -pk <privateKey> #error logging mode
./main -pk <privateKey> -v #warning logging mode
./main -pk <privateKey> -vv #info logging mode
./main -pk <privateKey> -vvv #debug logging mode
```

# Usage
```
> debug on #debug mode
> debug on info
> debug on warning
> debug on error
> debug off
> subscribe <event>
> publish <event> <value>
> peers
```

# Using with Custom Loggers

The library uses its own Logger interface but provides utilities to adapt your own logger:


For LiveKit loggers with Debugw, Infow, Warnw, and Errorw methods:

```go
import (
    p2p_database "github.com/dTelecom/p2p-database"
)

// Adapt a LiveKit-style logger
livekitLogger := logger.GetLogger()
adaptedLogger := p2p_database.NewLivekitLoggerAdapter(livekitLogger)

// Use the adapted logger with Connect
db, err := p2p_database.Connect(ctx, config, adaptedLogger)
```

3. To use the built-in console logger:

```go
logger := p2p_database.NewConsoleLogger()
db, err := p2p_database.Connect(ctx, config, logger)
```

The LivekitLogger interface required by NewLivekitLoggerAdapter is:

```go
type LivekitLogger interface {
    Debugw(msg string, keysAndValues ...interface{})
    Infow(msg string, keysAndValues ...interface{})
    Warnw(msg string, err error, keysAndValues ...interface{})
    Errorw(msg string, err error, keysAndValues ...interface{})
}
```

# Testing

## Integration Tests

The project includes integration tests that verify P2P functionality across multiple nodes:

```bash
# Run integration tests
make test-integration

# Run all tests
make test

# Run unit tests only
make test-unit
```

### What the Integration Tests Verify

- **Multi-node Setup**: 4 P2P nodes with different Solana wallets
- **Node Discovery**: Nodes can find and connect to each other
- **Pub/Sub Messaging**: Nodes can subscribe to topics and receive messages
- **Network Communication**: Messages are properly distributed across the P2P network

### Test Artifacts

The integration tests automatically generate:
- `test_wallet_*.json` - Solana wallet files for each test node
- `bin/p2p-node` - CLI binary for running nodes

To clean up test artifacts:
```bash
make clean-test     # Remove test wallets and coverage files
make clean          # Remove build artifacts  
make clean-all      # Remove everything
```

## Manual Testing

You can also run nodes manually for testing:

```bash
# Build the CLI
make build-cli

# Generate a wallet
./bin/p2p-node -generate-wallet

# Run a node
./bin/p2p-node -wallet <private_key> -port 3500 -http-port 8080
```