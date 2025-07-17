# P2P Distributed Pub/Sub System Architecture for DePIN

## Overview

This system is a **distributed peer-to-peer publish/subscribe network** built on libp2p, designed for secure, decentralized messaging in **DePIN (Decentralized Physical Infrastructure Network) applications**. The system provides **permissionless node participation** through **Solana smart contract registry integration**, where nodes are authorized via on-chain wallet verification.

## Key Characteristics

- **Distributed Pub/Sub**: No central server; all nodes are equal peers
- **DePIN-Optimized**: Designed for decentralized physical infrastructure networks
- **Permissionless Access**: Nodes automatically authorized via Solana smart contract registry
- **Security-First**: Solana wallet-based identity with smart contract gating
- **Bootstrap Discovery**: New nodes join using DHT and registry-based peer discovery  
- **Namespace Isolation**: Single database name acts as namespace for topic keys
- **Real-time Messaging**: Publish and subscribe to arbitrary topics

---

## System Architecture

### Core Components Stack

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

---

## Detailed Component Analysis

### 1. Node Identity & Security

#### Solana-Based Identity
- **Identity Source**: Solana wallet keypairs (Ed25519)
- **Key Conversion**: Solana private key → Ed25519 libp2p key
- **Peer ID Generation**: Deterministic from public key
- **Format**: Base58-encoded private keys for external storage

```go
type Config struct {
    WalletPrivateKey        string                      // Base58-encoded Solana private key
    DatabaseName            string                      // Namespace for topics
    GetAuthorizedWallets    GetAuthorizedWalletsFunc    // Function to get authorized wallets
    GetBootstrapNodes       GetBootstrapNodesFunc       // Function to get bootstrap nodes
    Logger                  Logger                      // Logger for all internal operations
    ListenPorts             ListenPorts                 // Ports for different transports
}

// Function provided by node software to get authorized wallets
type GetAuthorizedWalletsFunc func(ctx context.Context) ([]solana.PublicKey, error)

// Function provided by node software to get bootstrap nodes
type GetBootstrapNodesFunc func(ctx context.Context) ([]BootstrapNode, error)

// Bootstrap node information
type BootstrapNode struct {
    PublicKey   solana.PublicKey    // Node's Solana public key
    IP          string              // IP address
    QUICPort    int                 // QUIC port
    TCPPort     int                 // TCP port
}

// Listen ports for different transports
type ListenPorts struct {
    QUIC    int     // QUIC listen port (default: 4001)
    TCP     int     // TCP listen port (default: 4002)
}
```

#### Registry-Based Connection Gater
```go
type SolanaRegistryGater struct {
    getAuthorizedWallets    GetAuthorizedWalletsFunc  // Function provided by node software
    logger                  Logger                    // Logger instance
    cache                   *AuthorizationCache       // Authorized wallets cache
    refreshInterval         time.Duration            // How often to refresh authorized wallets list
    ctx                     context.Context          // Context for the refresh goroutine
    cancel                  context.CancelFunc       // Cancel function for the refresh goroutine
    wg                      sync.WaitGroup           // Wait group for the refresh goroutine
}

// Authorization cache stores only authorized wallets for performance
type AuthorizationCache struct {
    authorizedWallets       sync.Map                  // solana.PublicKey -> bool (only true values stored)
    mutex                   sync.RWMutex              // Protects cache operations
}
```

**Network-Level Security Functions**:
- `InterceptPeerDial()`: Validates outgoing connections against cache/registry
- `InterceptAddrDial()`: Validates specific address connections  
- `InterceptSecured()`: Post-handshake authorization via cache/registry lookup
- `checkWalletInCache()`: Core validation with cache fallback to registry
- `refreshAuthorizedWallets()`: Background process that refreshes cache every 30 seconds

**Connection Authorization Flow**:
1. **Node Attempts Connection** → Gater checks wallet against cache first
2. **If in Cache** → Connection allowed immediately (performance optimization)
3. **If Not in Cache** → Check registry directly (fallback for new wallets)
4. **If Authorized in Registry** → Add to cache and allow connection
5. **If Unauthorized** → Connection blocked at transport level
6. **Background Refresh** → Cache updated every 30 seconds (configurable)

**Cache Strategy**:
- **Performance**: Cache stores only authorized wallets (no TTL needed)
- **Freshness**: Background refresh every 30 seconds ensures up-to-date authorization
- **Fallback**: Direct registry check for wallets not in cache (handles new additions)
- **Simplicity**: No complex TTL or eviction logic needed

**Registry Integration (Handled by Node Software)**:
```go
// Example: Node software provides this function to pubsub library
func (node *DePINNode) GetAuthorizedWallets(ctx context.Context) ([]solana.PublicKey, error) {
    // Node software handles:
    // - Smart contract RPC calls
    // - Caching and refresh logic
    // - Error handling and retries
    // - Multiple RPC endpoint failover
    
    node.registryMutex.RLock()
    defer node.registryMutex.RUnlock()
    
    // Return cached authorized wallets from node's internal registry
    return node.cachedAuthorizedWallets, nil
}

// Pubsub gater checks cache first, then falls back to registry
func (g *SolanaRegistryGater) checkWalletInCache(ctx context.Context, wallet solana.PublicKey) (bool, error) {
    // Check cache first for performance
    if _, found := g.cache.authorizedWallets.Load(wallet); found {
        return true, nil
    }
    
    // Fallback to registry for new wallets
    authorizedWallets, err := g.getAuthorizedWallets(ctx)
    if err != nil {
        return false, err
    }
    
    // Check if wallet is authorized
    for _, authorized := range authorizedWallets {
        if wallet.Equals(authorized) {
            // Add to cache for future lookups
            g.cache.authorizedWallets.Store(wallet, true)
            return true, nil
        }
    }
    return false, nil
}
```

### 2. Network Layer

#### libp2p Host Configuration
- **Multiple Transports**: QUIC (primary), TCP (fallback), Circuit Relay (NAT assistance)
- **Connection Manager**: Automatic with connection limits and peer tagging
- **Datacenter Optimization**: Connection limits optimized for datacenter infrastructure
- **NAT Traversal**: QUIC hole punching and Circuit Relay

#### Transport Strategy

**Three-Transport Architecture for Universal Connectivity**:

```go
// Transport priority for DePIN nodes (enabled by default)
transports := []string{
    "QUIC",     // Primary: UDP-based, built-in encryption, connection migration
    "TCP",      // Fallback: Reliable for stable connections
    "Circuit",  // NAT assistance: Relay through other nodes when direct connection fails
}
```

**1. QUIC Transport (Primary)**
- **Multiaddr Format**: `/ip4/<ip>/udp/<port>/quic-v1`
- **Benefits for Datacenter DePIN**:
  - Built-in TLS 1.3 encryption
  - Reduced connection setup time
  - No head-of-line blocking
  - NAT hole punching capabilities

**2. TCP Transport (Fallback)**
- **Multiaddr Format**: `/ip4/<ip>/tcp/<port>`
- **Benefits for Datacenter DePIN**:
  - Universal compatibility
  - Reliable for stable connections
  - Excellent for datacenter infrastructure
  - Works through most firewalls

**3. Circuit Relay (NAT Assistance)**
- **Multiaddr Format**: `/ip4/<relay-ip>/tcp/<port>/p2p/<relay-peer-id>/p2p-circuit`
- **Benefits for Datacenter DePIN**:
  - Connects nodes that can't establish direct connections
  - Helps with network bootstrapping
  - Provides connectivity fallback for complex network topologies



#### DePIN-Optimized Peer Discovery
1. **Registry-Based Discovery**: Query smart contract for active nodes
2. **DHT Discovery**: Kademlia-based peer finding with rendezvous
3. **Gossip Discovery**: Peer discovery through topic participation
4. **Bootstrap Redundancy**: Multiple fallback discovery mechanisms

```go
// DePIN discovery process
rendezvous := DiscoveryTag + "_" + db.Name  // "p2p-database-discovery_<dbname>"
routingDiscovery := routing.NewRoutingDiscovery(globalDHT)

// Advertise this node to the network
util.Advertise(ctx, routingDiscovery, rendezvous)

// Find peers through DHT discovery
util.FindPeers(ctx, routingDiscovery, rendezvous)
// Note: Authorization happens at connection time via gater
```

### 3. Pub/Sub Messaging Layer

#### GossipSub Protocol
- **Protocol**: libp2p GossipSub for reliable message propagation  
- **Topic Format**: `<database_name>_<user_topic>`
- **Message Structure**: JSON-encoded Event objects
- **Deduplication**: Built-in message ID tracking
- **DePIN Optimizations**: Bandwidth-aware routing, adaptive mesh overlay

#### Event Structure
```go
type Event struct {
    ID         string      // UUID for deduplication
    FromPeerId string      // Sender's peer ID
    Message    interface{} // Arbitrary message payload
    Timestamp  int64       // Unix timestamp
}
```

#### Topic Management
```go
type TopicSubscription struct {
    subscription *pubsub.Subscription  // libp2p subscription
    topic        *pubsub.Topic         // Topic handle
    handler      PubSubHandler         // User callback function
}
```

**Topic Lifecycle**:
1. **Join**: `pubSub.Join(db.Name + "_" + topic)`
2. **Subscribe**: `topic.Subscribe()` + event listener goroutine
3. **Publish**: JSON marshal + `topic.Publish()`
4. **Leave**: `subscription.Cancel()` + `topic.Close()`

### 4. Shared Infrastructure Management

#### Process-Level Resource Sharing
```go
// Shared libp2p infrastructure managed by process-level manager
type P2PInfrastructure struct {
    host         host.Host                                      // Single libp2p host for all databases
    dht          *dual.DHT                                     // Kademlia DHT
    gossipSub    *pubsub.PubSub                               // GossipSub instance
    connManager  connmgr.ConnManager                          // Connection manager
    
    // Database-specific resources
    databases    map[string]*DatabaseInstance                 // Active database instances
    mutex        sync.RWMutex                                 // Protects databases map
}

// Per-database instance with isolated topics
type DatabaseInstance struct {
    name                string                                 // Database name
    gater              *SolanaRegistryGater                   // Registry-based connection gater
    topics             map[string]*pubsub.Topic               // Joined topics
    subscriptions      map[string]*TopicSubscription          // Active subscriptions
    mutex              sync.RWMutex                           // Protects topics/subscriptions
}
```

#### Initialization Strategy

**Process-Level Initialization (Once)**:
```go
func initializeP2PInfrastructure(config Config) (*P2PInfrastructure, error) {
    // 1. Create libp2p host with all transports
    host, err := libp2p.New(
        libp2p.ListenAddrStrings(
            fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", config.ListenPorts.QUIC),
            fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", config.ListenPorts.TCP),
        ),
        libp2p.Transport(quic.NewTransport),
        libp2p.Transport(tcp.NewTCPTransport),
        libp2p.EnableCircuitRelay(),
        libp2p.ConnectionManager(connManager),
        libp2p.NATPortMap(),
    )
    
    // 2. Initialize DHT for peer discovery
    dht, err := dual.New(ctx, host)
    
    // 3. Initialize GossipSub for pub/sub messaging
    gossipSub, err := pubsub.NewGossipSub(ctx, host)
    
    // 4. Bootstrap connection to network
    return connectToNetwork(host, dht, config.GetBootstrapNodes)
}
```

**Database-Level Initialization (Per Database)**:
```go
func createDatabaseInstance(infra *P2PInfrastructure, config Config) (*DB, error) {
    // 1. Create registry-based connection gater
    gater := &SolanaRegistryGater{
        getAuthorizedWallets: config.GetAuthorizedWallets,
        logger:              config.Logger,
        cache:               newAuthorizationCache(),
    }
    
    // 2. Apply connection gating to host
    infra.host.Network().Notify(gater)
    
    // 3. Create database instance
    dbInstance := &DatabaseInstance{
        name:          config.DatabaseName,
        gater:         gater,
        topics:        make(map[string]*pubsub.Topic),
        subscriptions: make(map[string]*TopicSubscription),
    }
    
    return &DB{infrastructure: infra, instance: dbInstance}, nil
}
```

---

## Message Flow Architecture

### Publishing Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │    │  Topic      │    │  GossipSub  │    │   Network   │
│             │    │  Manager    │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       │ Publish(topic,    │                   │                   │
       │ message)          │                   │                   │
       │──────────────────▶│                   │                   │
       │                   │                   │                   │
       │                   │ Join topic if     │                   │
       │                   │ not exists        │                   │
       │                   │──────────────────▶│                   │
       │                   │                   │                   │
       │                   │ Create Event{     │                   │
       │                   │   ID: uuid,       │                   │
       │                   │   FromPeerId,     │                   │
       │                   │   Message,        │                   │
       │                   │   Timestamp }     │                   │
       │                   │                   │                   │
       │                   │ JSON.Marshal      │                   │
       │                   │ (Event)           │                   │
       │                   │                   │                   │
       │                   │ topic.Publish()   │                   │
       │                   │──────────────────▶│                   │
       │                   │                   │                   │
       │                   │                   │ Gossip to         │
       │                   │                   │ authorized peers  │
       │                   │                   │──────────────────▶│
       │                   │                   │                   │
       │ Return Event{ID}  │                   │                   │
       │◀──────────────────│                   │                   │
```

### Subscription Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │    │  Topic      │    │  Event      │    │  Message    │
│             │    │  Manager    │    │  Listener   │    │  Handler    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       │ Subscribe(topic,  │                   │                   │
       │ handler)          │                   │                   │
       │──────────────────▶│                   │                   │
       │                   │                   │                   │
       │                   │ Join topic        │                   │
       │                   │ topic.Subscribe() │                   │
       │                   │                   │                   │
       │                   │ Start event       │                   │
       │                   │ listener goroutine│                   │
       │                   │──────────────────▶│                   │
       │                   │                   │                   │
       │                   │                   │ Listen loop:      │
       │                   │                   │ subscription.     │
       │                   │                   │ Next()            │
       │                   │                   │                   │
       │                   │                   │ JSON.Unmarshal   │
       │                   │                   │ → Event          │
       │                   │                   │                   │
       │                   │                   │ handler(Event)    │
       │                   │                   │──────────────────▶│
       │                   │                   │                   │
       │ Registration      │                   │                   │
       │ successful        │                   │                   │
       │◀──────────────────│                   │                   │
```

**Note**: Authorization happens at connection time via the connection gater. Once nodes are connected to the network, they can freely subscribe to and publish on any topics.

---

## Security Architecture for DePIN

### Authorization Model

#### Two-Layer Security for DePIN
1. **Smart Contract Level**: On-chain wallet registry provides Sybil resistance
2. **Network Level**: Connection gater blocks unauthorized peers at connection time
3. **Namespace Level**: Database name provides network isolation (different DePIN networks)
4. **Application Level**: Custom message validation (if needed)

**Important**: Once a node passes connection gating (wallet in registry), it can access all topics within that database namespace. Topic-level access control is not implemented at the pub/sub layer.

#### DePIN Threat Model Protection
- **Economic Attacks**: Smart contract registry prevents low-cost identity creation
- **Malicious Hardware**: Wallet-based identity tied to physical device ownership
- **Network Partitioning**: DHT and GossipSub provide resilience
- **Resource Exhaustion**: Connection limits protect against DoS
- **Identity Spoofing**: Cryptographic peer IDs prevent impersonation
- **Infrastructure Attacks**: Network topology monitoring for datacenter infrastructure

#### Smart Contract Registry vs Manual Node Lists
- **Permissionless Operation**: New nodes automatically authorized via smart contract
- **Dynamic Authorization**: Real-time registry updates without node restarts
- **Decentralized Control**: No single point of failure for node authorization
- **Audit Trail**: On-chain record of all authorization changes

### Connection Management for DePIN

#### Connection-Level Authorization
- **Authorization Point**: Connection gater validates wallet during connection handshake
- **One-Time Check**: Once connected, nodes have access to all topics in database namespace
- **No Per-Topic Gating**: Topic subscription/publishing is unrestricted for connected nodes
- **Network Isolation**: Different database names create separate networks with separate authorization

```go
// Connection flow
1. Node A attempts to connect to Node B
2. Connection gater checks Node A's wallet against registry
3. If authorized: Connection established, Node A can use any topics
4. If unauthorized: Connection rejected at transport level
```

#### Resource-Aware Scaling
- **Bandwidth Adaptation**: Message routing based on connection quality
- **Datacenter Distribution**: Latency-based peer prioritization across datacenters

---

## Bootstrap Retry & Network Resilience Architecture

### **Overview**

The system implements robust bootstrap retry mechanisms to ensure network connectivity in dynamic DePIN environments where nodes may start in any order and network conditions may be unstable.

### **Readiness State Management**

#### **Node Readiness Tracking**
```go
type P2PInfrastructure struct {
    // Readiness and bootstrap retry state
    isReady           bool                         // True when node has at least 1 peer connected
    readinessMutex    sync.RWMutex                 // Protects isReady
    getBootstrapNodes common.GetBootstrapNodesFunc // Bootstrap function for retry attempts
    retryCancel       context.CancelFunc           // Cancel function for bootstrap retry goroutine
    retryMutex        sync.Mutex                   // Protects retryCancel
    
    // Shutdown handling
    shutdownCtx    context.Context    // Context that gets cancelled during shutdown
    shutdownCancel context.CancelFunc // Cancel function for shutdown
}
```

#### **Readiness State Transitions**
1. **Initial State**: `isReady = false` (no peers connected)
2. **Peer Connected**: `isReady = true` (at least 1 peer connected)
3. **All Peers Lost**: `isReady = false` → triggers bootstrap retry
4. **Peer Reconnected**: `isReady = true` → stops bootstrap retry

### **Bootstrap Retry Mechanisms**

#### **Initial Bootstrap with Retry**
```go
func bootstrapNetworkWithRetry(ctx context.Context, infra *P2PInfrastructure) error {
    // Check bootstrap nodes availability first
    bootstrapNodes, err := infra.getBootstrapNodes(ctx)
    if err != nil {
        return fmt.Errorf("failed to get bootstrap nodes: %w", err)
    }

    if len(bootstrapNodes) == 0 {
        // No bootstrap nodes available, start retry process
        infra.logger.Info("No bootstrap nodes available, starting retry process")
        infra.startBootstrapRetry(infra.shutdownCtx)
        return nil // Don't return error, we'll retry
    }

    // Bootstrap nodes are available, try normal bootstrap
    err = bootstrapNetwork(ctx, infra.host, infra.dht, infra.getBootstrapNodes, infra.logger)
    if err != nil {
        // Bootstrap failed, start retry process to keep trying
        infra.logger.Warn("Initial bootstrap failed, starting retry process", "error", err.Error())
        infra.startBootstrapRetry(infra.shutdownCtx)
        return nil // Don't return error, we'll retry
    }

    // Bootstrap succeeded
    infra.logger.Info("Initial bootstrap successful")
    return nil
}
```

#### **Automatic Retry Loop**
```go
func (infra *P2PInfrastructure) startBootstrapRetry(parentCtx context.Context) {
    // Check if shutdown is in progress
    select {
    case <-infra.shutdownCtx.Done():
        infra.logger.Debug("Shutdown in progress, not starting bootstrap retry")
        return
    default:
    }

    // Check if retry is already running (with proper synchronization)
    infra.retryMutex.Lock()
    if infra.retryCancel != nil {
        infra.retryMutex.Unlock()
        infra.logger.Debug("Bootstrap retry already running, not starting another")
        return
    }

    // Create cancelable context for the retry goroutine
    retryCtx, cancel := context.WithCancel(parentCtx)
    infra.retryCancel = cancel
    infra.retryMutex.Unlock()

    go func() {
        defer func() {
            cancel()
            // Clear the cancel function when goroutine exits
            infra.retryMutex.Lock()
            infra.retryCancel = nil
            infra.retryMutex.Unlock()
        }()

        ticker := time.NewTicker(5 * time.Second)
        defer ticker.Stop()

        infra.logger.Info("Starting bootstrap retry loop (every 5 seconds)")

        for {
            select {
            case <-retryCtx.Done():
                infra.logger.Debug("Bootstrap retry loop cancelled")
                return
            case <-infra.shutdownCtx.Done():
                infra.logger.Debug("Bootstrap retry loop cancelled due to shutdown")
                return
            case <-ticker.C:
                // Check if node is already ready (has peers)
                if infra.IsReady() {
                    infra.logger.Info("Node is ready, stopping bootstrap retry")
                    return
                }

                // Try to get bootstrap nodes
                bootstrapNodes, err := infra.getBootstrapNodes(retryCtx)
                if err != nil {
                    infra.logger.Warn("Failed to get bootstrap nodes during retry", "error", err.Error())
                    continue
                }

                if len(bootstrapNodes) == 0 {
                    infra.logger.Debug("Still no bootstrap nodes available, will retry")
                    continue
                }

                // Found bootstrap nodes, try to connect
                infra.logger.Info("Found bootstrap nodes during retry", "count", len(bootstrapNodes))
                if err := bootstrapNetwork(retryCtx, infra.host, infra.dht, infra.getBootstrapNodes, infra.logger); err != nil {
                    infra.logger.Warn("Bootstrap retry failed", "error", err.Error())
                    continue
                }

                // Bootstrap succeeded
                infra.logger.Info("Bootstrap retry successful")
                time.Sleep(1 * time.Second) // Give DHT a moment to settle
                return
            }
        }
    }()
}
```

### **Network Recovery Scenarios**

#### **Scenario 1: Client Starts Before Bootstrap**
```
Time 0s:   Client starts, tries to connect to bootstrap → FAILS
Time 0s:   Client starts bootstrap retry loop
Time 5s:   Client retries bootstrap → FAILS (bootstrap not running)
Time 10s:  Bootstrap node starts
Time 15s:  Client retries bootstrap → SUCCESS
Time 15s:  Client becomes ready, stops retry loop
```

#### **Scenario 2: Bootstrap Node Failover**
```
Time 0s:   Node0 (bootstrap) + Node1 start → SUCCESS
Time 30s:  Node0 goes down → Node1 loses all peers
Time 30s:  Node1 becomes not ready, starts bootstrap retry
Time 35s:  Node2 starts as new bootstrap
Time 40s:  Node1 retries, connects to Node2 → SUCCESS
Time 40s:  Node1 becomes ready, stops retry loop
```

#### **Scenario 3: Network Partition Recovery**
```
Time 0s:   All nodes connected and communicating
Time 30s:  Network partition occurs → all nodes lose peers
Time 30s:  All nodes become not ready, start bootstrap retry
Time 35s:  Network partition resolves
Time 40s:  Nodes retry bootstrap → SUCCESS
Time 40s:  All nodes become ready, stop retry loops
```

### **Resource Management**

#### **Goroutine Lifecycle Management**
- **Retry Goroutine**: Started when node becomes not ready
- **Automatic Cleanup**: Goroutine stops when node becomes ready
- **Shutdown Safety**: All retry operations cancelled during shutdown
- **Race Condition Protection**: Mutex-protected retry state management

#### **Context Management**
```go
// Shutdown context for proper cleanup
shutdownCtx, shutdownCancel := context.WithCancel(context.Background())

// Retry context combines parent and shutdown contexts
retryCtx, cancel := context.WithCancel(parentCtx)

// Cleanup on disconnect
func (db *DB) Disconnect(ctx context.Context) error {
    // Cancel shutdown context first to stop all retry operations immediately
    if db.infrastructure.shutdownCancel != nil {
        db.infrastructure.shutdownCancel()
    }
    
    // Stop bootstrap retry
    db.infrastructure.stopBootstrapRetry()
    
    // ... rest of cleanup
}
```

### **Performance Characteristics**

#### **Retry Timing**
- **Initial Retry Delay**: 2 seconds (avoid immediate reconnection attempts)
- **Retry Interval**: 5 seconds (balance between responsiveness and resource usage)
- **Connection Timeout**: 30 seconds per bootstrap attempt
- **DHT Settlement Time**: 1 second after successful bootstrap

#### **Resource Usage**
- **Memory**: Minimal (single goroutine per node)
- **CPU**: Low (5-second intervals)
- **Network**: Only during retry attempts
- **Concurrent Retries**: Prevented (only one retry goroutine per node)

### **Integration with Registry**

#### **Dynamic Bootstrap Discovery**
```go
// Registry can return different bootstrap nodes over time
func (node *DePINNode) GetBootstrapNodes(ctx context.Context) ([]common.BootstrapNode, error) {
    // Query smart contract for current bootstrap nodes
    // This can change as nodes join/leave the network
    return node.registry.GetBootstrapNodes(ctx)
}
```

#### **Failover Support**
```go
// Multiple bootstrap nodes for redundancy
bootstrapNodes := []common.BootstrapNode{
    {PublicKey: node0Key, IP: "primary.example.com", QUICPort: 4001, TCPPort: 4002},
    {PublicKey: node1Key, IP: "backup.example.com", QUICPort: 4001, TCPPort: 4002},
    {PublicKey: node2Key, IP: "secondary.example.com", QUICPort: 4001, TCPPort: 4002},
}
```

### **Monitoring and Observability**

#### **Key Metrics**
- **Node Readiness**: `isReady` boolean state
- **Peer Count**: Number of connected peers
- **Bootstrap Retries**: Count of retry attempts
- **Retry Duration**: Time from not ready to ready
- **Bootstrap Success Rate**: Successful vs failed attempts

#### **Logging Strategy**
```go
// Readiness state changes
infra.logger.Info("Node became ready", "peer_count", peerCount)
infra.logger.Info("Node no longer ready", "peer_count", peerCount)

// Retry operations
infra.logger.Info("Starting bootstrap retry loop (every 5 seconds)")
infra.logger.Info("Found bootstrap nodes during retry", "count", len(bootstrapNodes))
infra.logger.Info("Bootstrap retry successful")
infra.logger.Info("Node is ready, stopping bootstrap retry")
```

---

## Technology Stack

### Core Dependencies (Updated for DePIN)
```go
// go.mod - Go 1.23.11
module github.com/dTelecom/p2p-database

go 1.23.11

require (
    github.com/libp2p/go-libp2p v0.41.1                    // Latest libp2p networking
    github.com/libp2p/go-libp2p-pubsub v0.12.0             // Latest GossipSub
    github.com/libp2p/go-libp2p-kad-dht v0.27.0            // Latest Kademlia DHT
    github.com/libp2p/go-libp2p-quic-transport v0.10.0     // QUIC transport (primary)
    github.com/libp2p/go-libp2p-circuit v0.20.0            // Circuit relay transport
    github.com/gagliardetto/solana-go v1.12.0              // Solana integration
    github.com/multiformats/go-multiaddr v0.12.0           // Multiaddress support
    github.com/google/uuid v1.5.0                          // Event ID generation
)
```

### DePIN-Specific Optimizations
- **Startup Performance**: Fast initialization optimized for DePIN deployment
- **Network Efficiency**: Efficient pub/sub routing with multi-transport optimization

### Logging Interface

The pubsub library uses a simple logging interface to remain logging-library agnostic:

```go
package common

import "log/slog"

// Logger interface for structured logging
type Logger interface {
    Debug(msg string, keysAndValues ...interface{})
    Info(msg string, keysAndValues ...interface{})
    Warn(msg string, keysAndValues ...interface{})
    Error(msg string, keysAndValues ...interface{})
}

// NewSlogLogger creates a logger using Go's standard slog (recommended for Go 1.23.11+)
func NewSlogLogger(logger *slog.Logger) Logger {
    return &slogLogger{logger: logger}
}

type slogLogger struct {
    logger *slog.Logger
}

func (l *slogLogger) Debug(msg string, keysAndValues ...interface{}) {
    l.logger.Debug(msg, keysAndValues...)
}

func (l *slogLogger) Info(msg string, keysAndValues ...interface{}) {
    l.logger.Info(msg, keysAndValues...)
}

func (l *slogLogger) Warn(msg string, keysAndValues ...interface{}) {
    l.logger.Warn(msg, keysAndValues...)
}

func (l *slogLogger) Error(msg string, keysAndValues ...interface{}) {
    l.logger.Error(msg, keysAndValues...)
}
```

#### Usage Example with slog
```go
import (
    "log/slog"
    "os"
)

// Create structured JSON logger
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
    AddSource: true,  // Add source file information
}))

// Create pubsub logger wrapper
pubsubLogger := common.NewSlogLogger(logger)

// Connect with logger in config
config := Config{
    WalletPrivateKey:     "your-wallet-key",
    DatabaseName:         "depin-network",
    GetAuthorizedWallets: node.GetAuthorizedWallets,
    GetBootstrapNodes:    node.GetBootstrapNodes,
    Logger:               pubsubLogger,
    ListenPorts: ListenPorts{
        QUIC: 4001,
        TCP:  4002,
    },
}

db, err := Connect(context.Background(), config)
```

#### Alternative Logger Implementations

The interface can be implemented with other popular logging libraries:

```go
// Using zap
import "go.uber.org/zap"

type ZapLogger struct {
    logger *zap.SugaredLogger
}

func (l *ZapLogger) Info(msg string, keysAndValues ...interface{}) {
    l.logger.Infow(msg, keysAndValues...)
}

// Using logrus  
import "github.com/sirupsen/logrus"

type LogrusLogger struct {
    logger *logrus.Logger
}

func (l *LogrusLogger) Info(msg string, keysAndValues ...interface{}) {
    l.logger.WithFields(logrus.Fields{
        // Convert keysAndValues to fields
    }).Info(msg)
}
```

#### LiveKit Logger Adapter

For projects using LiveKit loggers with methods like `Debugw`, `Infow`, `Warnw`, `Errorw`, use the built-in adapter:

```go
import "github.com/livekit/protocol/logger"

// Assuming you have a LiveKit logger instance
livekitLogger := logger.GetLogger() // or your LiveKit logger instance

// Create adapter
pubsubLogger := common.NewLivekitLoggerAdapter(livekitLogger)

// Use in config
config := Config{
    WalletPrivateKey:     "your-wallet-key",
    DatabaseName:         "depin-network",
    GetAuthorizedWallets: node.GetAuthorizedWallets,
    GetBootstrapNodes:    node.GetBootstrapNodes,
    Logger:               pubsubLogger,
    ListenPorts: ListenPorts{
        QUIC: 4001,
        TCP:  4002,
    },
}
```

The LiveKitLogger interface required by `NewLivekitLoggerAdapter` is:

```go
type LiveKitLogger interface {
    Debugw(msg string, keysAndValues ...interface{})
    Infow(msg string, keysAndValues ...interface{})
    Warnw(msg string, err error, keysAndValues ...interface{})
    Errorw(msg string, err error, keysAndValues ...interface{})
}
```

**Recommendation**: Use Go's standard `slog` package for new projects as it provides excellent performance, structured logging, and is part of the standard library since Go 1.21.

## Error Handling & Resilience for DePIN

**Note**: Smart contract resilience (RPC failover, caching, retry logic) is handled by the node software, not the pubsub library.


### Smart Contract Test Integration
```go
// Test with mock smart contract registry
func TestDePINNetworkWithRegistry(t *testing.T) {
    // Deploy mock registry smart contract
    mockRegistry := NewMockRegistryContract()
    
    // Add test wallets to registry
    testWallets := generateTestWallets(10)
    for _, wallet := range testWallets {
        mockRegistry.AddAuthorizedWallet(wallet)
    }
    
    // Start test nodes with registry integration
    nodes := startTestNodes(testWallets, mockRegistry.RPCEndpoint())
    
    // Test pub/sub functionality
    testPubSubAcrossNodes(nodes)
    
    // Test unauthorized wallet rejection
    testUnauthorizedWalletBlocking(nodes, generateTestWallets(1))
}
```

## Conclusion

This updated P2P distributed pub/sub system is specifically optimized for **DePIN (Decentralized Physical Infrastructure Network)** applications. Key improvements include:

### Major Architectural Changes
1. **Clean Separation of Concerns**: Pubsub library focuses on messaging; node software handles registry and bootstrap management
2. **Function-Based Integration**: Simple function interfaces for authorization and bootstrap discovery without RPC complexity
3. **Three-Transport Architecture**: QUIC (primary), TCP (fallback), and Circuit Relay (NAT assistance) for universal connectivity
4. **Process-Level Resource Sharing**: Efficient infrastructure sharing across multiple database instances
5. **Connection-Level Security**: Registry-based authorization at connection time, not per-topic
6. **Latest Technology Stack**: Go 1.23.11, libp2p v0.41.1, solana-go v1.12.0

### DePIN-Specific Benefits
- **Permissionless Participation**: Nodes automatically authorized via smart contract (handled by node software)
- **Simple Integration**: Pubsub library receives authorization via function call, no RPC complexity
- **Universal Connectivity**: Multi-transport strategy (QUIC + TCP + Circuit Relay) ensures nodes can connect regardless of NAT/firewall restrictions
- **Economic Integration**: Registry tied to DePIN tokenomics and staking mechanisms  
- **Infrastructure Resilience**: Multi-region datacenter support with adaptive transport selection
- **Scalability**: Support for thousands of datacenter nodes with optimized connectivity

### Security & Reliability
- **Sybil Resistance**: Smart contract registry prevents cheap identity creation
- **Datacenter Distribution**: Built-in monitoring and optimization across datacenter infrastructure
- **Economic Security**: Integration with DePIN reward/penalty mechanisms
- **Infrastructure Protection**: Resource limits and reputation-based peer management

This architecture provides a robust foundation for DePIN applications requiring secure, scalable, and economically-integrated peer-to-peer communication infrastructure. The clean separation of concerns ensures the pubsub library remains focused on messaging performance while the node software handles all smart contract complexity, enabling truly permissionless and decentralized operation. 