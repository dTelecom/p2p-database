package p2p_database

// GetNodesFunc is a function that returns a map of node keys to their IP addresses
type GetNodesFunc func() map[string]string

type Config struct {
	DisableGater     bool
	PeerListenPort   int
	WalletPrivateKey string
	DatabaseName     string
	GetNodes         GetNodesFunc
}
