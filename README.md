# P2P Distributed Pub/Sub System for DePIN

This Go library carries pub/sub messages between dTelecom media nodes over libp2p. The [media server](https://github.com/dTelecom/livekit/blob/dtelecom-db/pkg/routing/localrouter.go) uses the mesh for room and participant routing. Node identity and admission depend on the [Solana registry](https://github.com/dTelecom/registry-program). dTelecom operates the admitted nodes.

For calls in an application, start with the [Cloud quickstart](https://docs.dtelecom.org/quickstart/). For changes to mesh behavior, see [ARCHITECTURE.md](ARCHITECTURE.md) and check the version in the [server module](https://github.com/dTelecom/livekit/blob/dtelecom-db/go.mod).

The earlier [p2p-realtime-database repository](https://github.com/dTelecom/p2p-realtime-database) is archived.

## Features

- **Distributed P2P Architecture**: No central servers, all nodes are equal peers
- **Solana Integration**: Identity and authorization via Solana wallet keypairs
- **Smart Contract Registry**: Node admission through the on-chain registry
- **Multi-Transport Support**: QUIC (primary), TCP (fallback), Circuit Relay (NAT assistance)
- **Real-time Messaging**: Publish/subscribe to arbitrary topics with JSON payloads
- **Namespace Isolation**: Database-based topic namespacing for network segmentation
- **Production Ready**: Structured logging, connection management, and error handling

## Bootstrap Retry & Network Resilience

The system includes robust bootstrap retry mechanisms to ensure network connectivity in dynamic environments:

### **Automatic Bootstrap Retry**
- **Initial Connection**: If bootstrap nodes are unavailable when a node starts, it automatically retries every 5 seconds
- **Network Recovery**: If a node loses all peers, it automatically attempts to reconnect to bootstrap nodes
- **Registry Integration**: Retry mechanism works with dynamic registry-based bootstrap node discovery
- **Graceful Degradation**: Nodes continue operating even when bootstrap nodes are temporarily unavailable

### **Bootstrap Scenarios Handled**
1. **Client Starts Before Bootstrap**: Client nodes can start before bootstrap nodes and automatically connect when they come online
2. **Bootstrap Node Failover**: If a bootstrap node goes down, clients automatically retry and connect to alternative bootstrap nodes
3. **Network Partition Recovery**: Nodes automatically rejoin the network after network partitions
4. **Registry Updates**: Nodes automatically discover new bootstrap nodes as they're added to the registry

### **Readiness State Management**
- **Node Readiness**: Nodes track their readiness state (has at least 1 peer connected)
- **Automatic Retry**: When a node becomes "not ready" (loses all peers), it automatically starts bootstrap retry
- **Retry Termination**: Bootstrap retry automatically stops when the node becomes ready again
- **Resource Cleanup**: All retry operations are properly cleaned up during node shutdown

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │            Go Library Interface                          │ │
│  │           (Subscribe/Publish)                            │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    P2P Pub/Sub Layer                        │
│  ┌─────────────────┐    ┌─────────────────────────────────┐ │
│  │  Topic Manager  │    │      Event Routing              │ │
│  │   (Pub/Sub)     │    │   (Message Distribution)        │ │
│  └─────────────────┘    └─────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Security Layer                           │
│  ┌─────────────────┐    ┌─────────────────────────────────┐ │
│  │Registry Gater   │    │    Solana Identity              │ │
│  │(Smart Contract) │    │  (Ed25519 Keys)                 │ │
│  └─────────────────┘    └─────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    libp2p Networking Layer                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   GossipSub     │  │   Kademlia DHT  │  │ Connection  │ │
│  │   (Pub/Sub)     │  │  (Discovery)    │  │  Manager    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Transport Layer                          │
│  ┌─────────────────┐    ┌─────────────┐    ┌─────────────┐ │
│  │      QUIC       │    │     TCP     │    │   Circuit   │ │
│  │  (Primary)      │    │ (Fallback)  │    │   (Relay)   │ │
│  └─────────────────┘    └─────────────┘    └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Go 1.23 or later
- Solana wallet private key (Base58 encoded)
- Access to Solana RPC endpoint (for registry integration)

### Installation

```bash
git clone https://github.com/dTelecom/p2p-database.git
cd p2p-database
go mod download
```

### Using as a Library

```go
package main

import (
    "context"
    "log/slog"
    "os"
    
    "github.com/dTelecom/p2p-database/common"
    "github.com/dTelecom/p2p-database/pubsub"
    "github.com/gagliardetto/solana-go"
)

func main() {
    // Create logger
    logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelInfo,
    }))
    pubsubLogger := common.NewSlogLogger(logger)
    
    // Configuration
    config := common.Config{
        WalletPrivateKey:     "your_base58_encoded_private_key",
        DatabaseName:         "depin-network",
        GetAuthorizedWallets: getAuthorizedWallets, // Your registry function
        GetBootstrapNodes:    getBootstrapNodes,    // Your bootstrap function
        Logger:               pubsubLogger,
        ListenPorts: common.ListenPorts{
            QUIC: 4001,
            TCP:  4002,
        },
    }
    
    // Connect to network
    ctx := context.Background()
    db, err := pubsub.Connect(ctx, config)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Disconnect(ctx)
    
    // Subscribe to messages
    err = db.Subscribe(ctx, "my-topic", func(event common.Event) {
        log.Printf("Received: %v", event.Message)
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Publish a message
    event, err := db.Publish(ctx, "my-topic", map[string]interface{}{
        "content": "Hello, DePIN!",
        "timestamp": time.Now().Unix(),
    })
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Published message with ID: %s", event.ID)
}
```

## Integration Functions

You need to implement two functions for registry integration:

### GetAuthorizedWallets Function

```go
func getAuthorizedWallets(ctx context.Context) ([]solana.PublicKey, error) {
    // Query your smart contract registry
    // Return list of authorized Solana public keys
    return authorizedWallets, nil
}
```

### GetBootstrapNodes Function

```go
func getBootstrapNodes(ctx context.Context) ([]common.BootstrapNode, error) {
    // Return list of bootstrap nodes
    return []common.BootstrapNode{
        {
            PublicKey: solana.PublicKeyFromBase58("..."),
            IP:        "192.168.1.100",
            QUICPort:  4001,
            TCPPort:   4002,
        },
    }, nil
}
```

## Testing

Run the integration tests with local sockets available. The fixtures supply their own wallets and registry callbacks.

```bash
go test ./test/...
go test -race ./...
```

To select a scenario by name, use the Go test runner's filter. For example, `go test -run TestBootstrapRetry ./test/...` exercises the bootstrap retry cases.

## Configuration

### Environment Variables

- `WALLET_PRIVATE_KEY`: Base58-encoded Solana private key (required)

### Config Structure

```go
type Config struct {
    WalletPrivateKey     string                   // Base58-encoded Solana private key
    DatabaseName         string                   // Namespace for topics
    GetAuthorizedWallets GetAuthorizedWalletsFunc // Function to get authorized wallets
    GetBootstrapNodes    GetBootstrapNodesFunc    // Function to get bootstrap nodes
    Logger               Logger                   // Logger for all internal operations
    ListenPorts          ListenPorts              // Ports for different transports
}
```

## Production Deployment

### **Deployment Architecture**

For production DePIN deployments, consider the following architecture:

#### **Multi-Region Bootstrap Nodes**
```go
// Example: Deploy bootstrap nodes across multiple regions
bootstrapNodes := []common.BootstrapNode{
    // Primary bootstrap nodes
    {PublicKey: solana.MustPublicKeyFromBase58("..."), IP: "us-east-1.example.com", QUICPort: 4001, TCPPort: 4002},
    {PublicKey: solana.MustPublicKeyFromBase58("..."), IP: "us-west-1.example.com", QUICPort: 4001, TCPPort: 4002},
    {PublicKey: solana.MustPublicKeyFromBase58("..."), IP: "eu-west-1.example.com", QUICPort: 4001, TCPPort: 4002},
    
    // Backup bootstrap nodes
    {PublicKey: solana.MustPublicKeyFromBase58("..."), IP: "us-central-1.example.com", QUICPort: 4001, TCPPort: 4002},
    {PublicKey: solana.MustPublicKeyFromBase58("..."), IP: "ap-southeast-1.example.com", QUICPort: 4001, TCPPort: 4002},
}
```

#### **Registry Integration Best Practices**
```go
// Implement robust registry integration with caching and failover
func (node *DePINNode) GetAuthorizedWallets(ctx context.Context) ([]solana.PublicKey, error) {
    // 1. Check local cache first (TTL: 30 seconds)
    if cached := node.cache.Get("authorized_wallets"); cached != nil {
        return cached.([]solana.PublicKey), nil
    }
    
    // 2. Query primary RPC endpoint
    wallets, err := node.queryRegistryPrimary(ctx)
    if err == nil {
        node.cache.Set("authorized_wallets", wallets, 30*time.Second)
        return wallets, nil
    }
    
    // 3. Fallback to secondary RPC endpoint
    wallets, err = node.queryRegistrySecondary(ctx)
    if err == nil {
        node.cache.Set("authorized_wallets", wallets, 30*time.Second)
        return wallets, nil
    }
    
    // 4. Return cached data if available (even if expired)
    if stale := node.cache.GetStale("authorized_wallets"); stale != nil {
        node.logger.Warn("Using stale authorized wallets due to RPC failure")
        return stale.([]solana.PublicKey), nil
    }
    
    return nil, fmt.Errorf("all registry endpoints failed")
}
```

### **Infrastructure Requirements**

#### **Network Configuration**
- **Firewall Rules**: Allow QUIC (UDP) and TCP traffic on configured ports
- **Load Balancers**: Use load balancers for bootstrap node redundancy
- **DNS**: Configure DNS for bootstrap node discovery
- **NAT Traversal**: Ensure QUIC hole punching works through firewalls

#### **Resource Requirements**
- **CPU**: 1-2 cores per node (libp2p is efficient)
- **Memory**: 512MB-2GB depending on message volume
- **Network**: 10-100 Mbps depending on DePIN application
- **Storage**: Minimal (messages are not persisted by default)

#### **Monitoring & Observability**
```go
// Implement comprehensive logging
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
    AddSource: true,
}))

// Monitor key metrics
type NodeMetrics struct {
    ConnectedPeers    int64
    MessagesPublished int64
    MessagesReceived  int64
    BootstrapRetries  int64
    IsReady          bool
}

// Export metrics for monitoring systems (Prometheus, etc.)
func (node *DePINNode) ExportMetrics() map[string]interface{} {
    return map[string]interface{}{
        "connected_peers":     node.metrics.ConnectedPeers,
        "messages_published":  node.metrics.MessagesPublished,
        "messages_received":   node.metrics.MessagesReceived,
        "bootstrap_retries":   node.metrics.BootstrapRetries,
        "is_ready":           node.metrics.IsReady,
        "uptime_seconds":     time.Since(node.startTime).Seconds(),
    }
}
```

### **Security Considerations**

#### **Private Key Management**
- **Environment Variables**: Store private keys securely (not in code)
- **Key Rotation**: Implement key rotation mechanisms
- **Access Control**: Limit access to private keys in production

#### **Network Security**
- **Authorization**: All nodes must be authorized via smart contract
- **Connection Gating**: Unauthorized connections are blocked at transport level
- **Message Validation**: Implement application-level message validation if needed

#### **Registry Security**
- **RPC Endpoint Security**: Use secure RPC endpoints with authentication
- **Cache Security**: Ensure cached authorization data is properly secured
- **Failover Security**: Implement secure failover mechanisms

### **Scaling Considerations**

#### **Horizontal Scaling**
- **Node Distribution**: Distribute nodes across multiple regions
- **Bootstrap Redundancy**: Deploy multiple bootstrap nodes per region
- **Load Distribution**: Use load balancers for bootstrap node traffic

#### **Performance Optimization**
- **Connection Pooling**: libp2p handles connection pooling automatically
- **Message Batching**: Implement application-level message batching if needed
- **Topic Partitioning**: Use different database names for different DePIN networks

#### **Fault Tolerance**
- **Bootstrap Retry**: Automatic retry ensures network resilience
- **Registry Failover**: Implement multiple RPC endpoints for registry queries
- **Graceful Degradation**: Nodes continue operating even with partial connectivity

## Troubleshooting

### **Common Issues and Solutions**

#### **Node Won't Connect to Bootstrap**
```bash
# Symptom: "Failed to connect to bootstrap node"
# Solution: Check bootstrap node is running and accessible

# 1. Verify bootstrap node is running
netstat -an | grep :4001  # Should show QUIC port listening
netstat -an | grep :4002  # Should show TCP port listening

# 2. Check firewall rules
sudo ufw status  # Ensure ports 4001-4002 are allowed

# 3. Test connectivity
nc -v 127.0.0.1 4002  # Test TCP connectivity
# Note: QUIC connectivity requires libp2p client

# 4. Check bootstrap node logs for authorization issues
```

#### **Bootstrap Retry Loop Never Succeeds**
```bash
# Symptom: "Starting bootstrap retry loop (every 5 seconds)" keeps repeating
# Solution: Check registry and bootstrap node availability

# 1. Verify registry function returns valid bootstrap nodes
# 2. Check bootstrap node authorization (wallet in registry)
# 3. Verify network connectivity between nodes
# 4. Check for port conflicts (multiple nodes using same ports)
```

#### **Unauthorized Node Blocked**
```bash
# Symptom: "Rejecting connection from unauthorized peer"
# Solution: Add node's wallet to registry

# 1. Get the node's public key from logs
# 2. Add the public key to your smart contract registry
# 3. Ensure registry function returns the updated list
# 4. Restart the node to pick up registry changes
```

#### **Messages Not Being Received**
```bash
# Symptom: Published messages not received by other nodes
# Solution: Check subscription and network connectivity

# 1. Verify nodes are connected (check peer count)
# 2. Ensure both nodes are subscribed to the same topic
# 3. Check topic name matches exactly (case-sensitive)
# 4. Verify nodes are in the same database namespace
# 5. Check for self-message filtering (nodes don't receive own messages)
```

#### **High Memory Usage**
```bash
# Symptom: Node using excessive memory
# Solution: Check for subscription leaks and message accumulation

# 1. Ensure proper unsubscribe calls
# 2. Check for message handler memory leaks
# 3. Monitor subscription count vs expected count
# 4. Restart node if memory usage is excessive
```

#### **Network Partition Issues**
```bash
# Symptom: Nodes can't communicate despite being authorized
# Solution: Check network topology and bootstrap configuration

# 1. Verify all nodes use the same bootstrap nodes
# 2. Check for NAT/firewall issues
# 3. Ensure QUIC and TCP ports are accessible
# 4. Verify DNS resolution for bootstrap node addresses
```

### **Debug Mode**

Enable debug logging to troubleshoot issues:

```go
// Enable libp2p debug logging
import "github.com/ipfs/go-log/v2"

func init() {
    // Enable debug logging for all libp2p subsystems
    _ = logging.SetLogLevel("*", "DEBUG")
}

// Or enable specific subsystems
_ = logging.SetLogLevel("swarm2", "DEBUG")    // Connection management
_ = logging.SetLogLevel("dht", "DEBUG")       // Peer discovery
_ = logging.SetLogLevel("pubsub", "DEBUG")    // Message routing
```

### **Health Check Implementation**

Implement health checks in your application:

```go
// Health check function for your application
func (node *DePINNode) HealthCheck() map[string]interface{} {
    return map[string]interface{}{
        "status":           "healthy",
        "is_ready":         node.db.IsReady(),
        "connected_peers":  len(node.db.ConnectedPeers()),
        "uptime_seconds":   time.Since(node.startTime).Seconds(),
        "last_activity":    node.lastActivity,
    }
}

// Use with your preferred monitoring system
func (node *DePINNode) ExportMetrics() map[string]interface{} {
    return map[string]interface{}{
        "connected_peers":     len(node.db.ConnectedPeers()),
        "is_ready":           node.db.IsReady(),
        "uptime_seconds":     time.Since(node.startTime).Seconds(),
    }
}
```

### **Performance Monitoring**

Monitor key performance metrics through the library interface:

```go
// Monitor peer connections
peers := db.ConnectedPeers()
fmt.Printf("Connected peers: %d\n", len(peers))

// Check node readiness
isReady := db.IsReady()
fmt.Printf("Node ready: %t\n", isReady)

// Monitor bootstrap retry frequency in logs
// Look for these log messages:
// - "Starting bootstrap retry loop (every 5 seconds)"
// - "Bootstrap retry successful"
// - "Node is ready, stopping bootstrap retry"
```

### **Log Analysis**

Monitor system health through structured logging:

```bash
# Check for bootstrap retry activity
grep "bootstrap retry" node.log | wc -l

# Monitor peer connection changes
grep "Node became ready\|Node no longer ready" node.log

# Check for authorization issues
grep "Rejecting connection from unauthorized peer" node.log

# Monitor message delivery
grep "Published message\|Received message" node.log
```

## API Reference

### **Core Types**

#### **Config Structure**
```go
type Config struct {
    WalletPrivateKey     string                   // Base58-encoded Solana private key
    DatabaseName         string                   // Namespace for topics
    GetAuthorizedWallets GetAuthorizedWalletsFunc // Function to get authorized wallets
    GetBootstrapNodes    GetBootstrapNodesFunc    // Function to get bootstrap nodes
    Logger               Logger                   // Logger for all internal operations
    ListenPorts          ListenPorts              // Ports for different transports
}

type ListenPorts struct {
    QUIC    int     // QUIC listen port (default: 4001)
    TCP     int     // TCP listen port (default: 4002)
}
```

#### **Bootstrap Node Structure**
```go
type BootstrapNode struct {
    PublicKey   solana.PublicKey    // Node's Solana public key
    IP          string              // IP address
    QUICPort    int                 // QUIC port
    TCPPort     int                 // TCP port
}
```

#### **Event Structure**
```go
type Event struct {
    ID         string      // Unique message identifier (UUID)
    FromPeerId string      // Sender's peer ID
    Message    interface{} // Message payload (any JSON-serializable data)
    Timestamp  int64       // Unix timestamp
}
```

### **Core Functions**

#### **Connect to Network**
```go
func Connect(ctx context.Context, config Config) (*DB, error)
```
**Description**: Establishes connection to the P2P network with bootstrap retry support.

**Parameters**:
- `ctx`: Context for cancellation and timeouts
- `config`: Configuration including wallet, registry functions, and ports

**Returns**:
- `*DB`: Database instance for pub/sub operations
- `error`: Connection error if any

**Example**:
```go
db, err := pubsub.Connect(ctx, config)
if err != nil {
    log.Fatal("Failed to connect:", err)
}
defer db.Disconnect(ctx)
```

#### **Subscribe to Topic**
```go
func (db *DB) Subscribe(ctx context.Context, topic string, handler PubSubHandler) error
```
**Description**: Subscribes to a topic and registers a message handler.

**Parameters**:
- `ctx`: Context for cancellation
- `topic`: Topic name (case-sensitive)
- `handler`: Function called when messages are received

**Returns**:
- `error`: Subscription error if any

**Example**:
```go
err := db.Subscribe(ctx, "sensors", func(event common.Event) {
    fmt.Printf("Received: %+v\n", event.Message)
})
```

#### **Publish Message**
```go
func (db *DB) Publish(ctx context.Context, topic string, value interface{}) (Event, error)
```
**Description**: Publishes a message to a topic.

**Parameters**:
- `ctx`: Context for cancellation
- `topic`: Topic name (case-sensitive)
- `value`: Message payload (must be JSON-serializable)

**Returns**:
- `Event`: Published event with ID and metadata
- `error`: Publish error if any

**Example**:
```go
event, err := db.Publish(ctx, "sensors", map[string]interface{}{
    "temperature": 25.5,
    "humidity":    60,
})
```

#### **Get Connected Peers**
```go
func (db *DB) ConnectedPeers() []*peer.AddrInfo
```
**Description**: Returns information about currently connected peers.

**Returns**:
- `[]*peer.AddrInfo`: List of connected peer information

**Example**:
```go
peers := db.ConnectedPeers()
fmt.Printf("Connected to %d peers\n", len(peers))
for _, peer := range peers {
    fmt.Printf("Peer: %s\n", peer.ID.String())
}
```

#### **Check Node Readiness**
```go
func (db *DB) IsReady() bool
```
**Description**: Returns true if the node has at least 1 peer connected.

**Returns**:
- `bool`: True if node is ready (has peers), false otherwise

**Example**:
```go
if db.IsReady() {
    fmt.Println("Node is ready and connected to network")
} else {
    fmt.Println("Node is not ready (no peers connected)")
}
```

#### **Get Host Information**
```go
func (db *DB) GetHost() host.Host
```
**Description**: Returns the underlying libp2p host for advanced operations.

**Returns**:
- `host.Host`: libp2p host instance

**Example**:
```go
host := db.GetHost()
fmt.Printf("Node ID: %s\n", host.ID().String())
```

#### **Disconnect from Network**
```go
func (db *DB) Disconnect(ctx context.Context) error
```
**Description**: Gracefully disconnects from the network and cleans up resources.

**Parameters**:
- `ctx`: Context for cancellation

**Returns**:
- `error`: Disconnect error if any

**Example**:
```go
err := db.Disconnect(ctx)
if err != nil {
    log.Printf("Error during disconnect: %v", err)
}
```

### **Function Types**

#### **Authorization Function**
```go
type GetAuthorizedWalletsFunc func(ctx context.Context) ([]solana.PublicKey, error)
```
**Description**: Function that returns list of authorized Solana wallet public keys.

**Parameters**:
- `ctx`: Context for cancellation and timeouts

**Returns**:
- `[]solana.PublicKey`: List of authorized wallet public keys
- `error`: Error if registry query fails

**Example**:
```go
func getAuthorizedWallets(ctx context.Context) ([]solana.PublicKey, error) {
    // Query your smart contract registry
    // Return list of authorized Solana public keys
    return []solana.PublicKey{
        solana.MustPublicKeyFromBase58("..."),
        solana.MustPublicKeyFromBase58("..."),
    }, nil
}
```

#### **Bootstrap Function**
```go
type GetBootstrapNodesFunc func(ctx context.Context) ([]common.BootstrapNode, error)
```
**Description**: Function that returns list of bootstrap nodes for network discovery.

**Parameters**:
- `ctx`: Context for cancellation and timeouts

**Returns**:
- `[]common.BootstrapNode`: List of bootstrap nodes
- `error`: Error if bootstrap query fails

**Example**:
```go
func getBootstrapNodes(ctx context.Context) ([]common.BootstrapNode, error) {
    return []common.BootstrapNode{
        {
            PublicKey: solana.MustPublicKeyFromBase58("..."),
            IP:        "192.168.1.100",
            QUICPort:  4001,
            TCPPort:   4002,
        },
    }, nil
}
```

#### **Message Handler**
```go
type PubSubHandler func(Event)
```
**Description**: Function called when messages are received on subscribed topics.

**Parameters**:
- `Event`: Received message event with ID, sender, and payload

**Example**:
```go
func messageHandler(event common.Event) {
    fmt.Printf("Received message from %s: %+v\n", event.FromPeerId, event.Message)
}
```

### **Logger Interface**

#### **Logger Methods**
```go
type Logger interface {
    Debug(msg string, keysAndValues ...interface{})
    Info(msg string, keysAndValues ...interface{})
    Warn(msg string, keysAndValues ...interface{})
    Error(msg string, keysAndValues ...interface{})
}
```

#### **Creating a Logger**
```go
import "log/slog"

// Create structured JSON logger
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))

// Create pubsub logger wrapper
pubsubLogger := common.NewSlogLogger(logger)
```

## Network Ports

- **QUIC**: 4001 (default, primary transport)
- **TCP**: 4002 (default, fallback transport)

## Version Information

See the [module versions](https://pkg.go.dev/github.com/dTelecom/p2p-database?tab=versions) for releases and [go.mod](go.mod) for the Go toolchain and dependency versions. The [local integration examples](test/integration_test.go) show how to construct nodes and exchange messages with fixture registry callbacks.

#### **Key Features**
- **Multi-Transport Support**: QUIC (primary), TCP (fallback), Circuit Relay (NAT assistance)
- **Solana Integration**: Wallet-based identity and smart contract authorization
- **Registry-Based Discovery**: Dynamic bootstrap node discovery via smart contracts
- **Namespace Isolation**: Database-based topic namespacing for network segmentation
- **Structured Logging**: JSON logging with configurable levels
- **Resource Management**: Proper cleanup and goroutine lifecycle management

### **Compatibility**

#### **Supported Platforms**
- **Operating Systems**: Linux, macOS, Windows
- **Architectures**: x86_64, ARM64
- **Network**: IPv4, IPv6 support

#### **Dependencies**
- **Network**: QUIC/UDP and TCP support

### **Migration Guide**

#### **From Pre-1.0.0 Versions**
- **Bootstrap Retry**: New automatic retry mechanism (backward compatible)
- **Readiness API**: New `IsReady()` method for monitoring
- **Enhanced Logging**: Improved structured logging with better error messages
- **Resource Cleanup**: Improved shutdown and cleanup procedures

### **Support**

For issues, questions, or contributions:
- **GitHub Issues**: [Create an issue](https://github.com/dTelecom/p2p-database/issues)
- **Documentation**: See `ARCHITECTURE.md` for technical details
- **Examples**: See [the Go integration fixtures](test/integration_test.go).
