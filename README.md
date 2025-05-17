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