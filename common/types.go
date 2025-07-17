package common

import (
	"context"
	"time"

	"github.com/gagliardetto/solana-go"
)

// Config represents the configuration for connecting to the P2P pubsub network
type Config struct {
	WalletPrivateKey     string                   // Base58-encoded Solana private key
	DatabaseName         string                   // Namespace for topics
	GetAuthorizedWallets GetAuthorizedWalletsFunc // Function to get authorized wallets
	GetBootstrapNodes    GetBootstrapNodesFunc    // Function to get bootstrap nodes
	Logger               Logger                   // Logger for all internal operations
	ListenPorts          ListenPorts              // Ports for different transports
	RefreshInterval      time.Duration            // How often to refresh authorized wallets cache (default: 30s)
}

// Function provided by node software to get authorized wallets
type GetAuthorizedWalletsFunc func(ctx context.Context) ([]solana.PublicKey, error)

// Function provided by node software to get bootstrap nodes
type GetBootstrapNodesFunc func(ctx context.Context) ([]BootstrapNode, error)

// BootstrapNode represents information about a bootstrap node
type BootstrapNode struct {
	PublicKey solana.PublicKey // Node's Solana public key
	IP        string           // IP address
	QUICPort  int              // QUIC port
	TCPPort   int              // TCP port
}

// ListenPorts represents ports for different transports
type ListenPorts struct {
	QUIC int // QUIC listen port (default: 4001)
	TCP  int // TCP listen port (default: 4002)
}

// Event represents a message in the pub/sub system
type Event struct {
	ID         string      `json:"id"`        // Unique event identifier
	FromPeerId string      `json:"from_peer"` // Peer ID of sender
	Message    interface{} `json:"message"`   // The actual message content
	Timestamp  int64       `json:"timestamp"` // Unix timestamp
	// Note: libp2p handles message signing automatically at the protocol level
}

// PubSubHandler is the callback function for handling received messages
type PubSubHandler func(Event)

// Logger interface for structured logging (library-agnostic)
type Logger interface {
	Debug(msg string, keysAndValues ...interface{})
	Info(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	DebugEnabled() bool // Check if debug logging is enabled
}
