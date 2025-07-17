package common

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// SolanaRegistryGater implements connection gating based on Solana wallet registry
type SolanaRegistryGater struct {
	getAuthorizedWallets GetAuthorizedWalletsFunc // Function provided by node software
	logger               Logger                   // Logger instance
	cache                *AuthorizationCache      // Authorized wallets cache
	refreshInterval      time.Duration            // How often to refresh the authorized wallets list
	ctx                  context.Context          // Context for the refresh goroutine
	cancel               context.CancelFunc       // Cancel function for the refresh goroutine
	wg                   sync.WaitGroup           // Wait group for the refresh goroutine
}

// AuthorizationCache provides caching for authorized wallets
type AuthorizationCache struct {
	authorizedWallets sync.Map // solana.PublicKey -> bool (only true values are stored)
	mutex             sync.RWMutex
}

// NewSolanaRegistryGater creates a new connection gater with the provided registry function
func NewSolanaRegistryGater(getAuthorizedWallets GetAuthorizedWalletsFunc, logger Logger, refreshInterval time.Duration) *SolanaRegistryGater {
	ctx, cancel := context.WithCancel(context.Background())

	gater := &SolanaRegistryGater{
		getAuthorizedWallets: getAuthorizedWallets,
		logger:               logger,
		cache:                &AuthorizationCache{},
		refreshInterval:      refreshInterval,
		ctx:                  ctx,
		cancel:               cancel,
	}

	// Start the background refresh process
	gater.wg.Add(1)
	go gater.refreshAuthorizedWallets()

	return gater
}

// refreshAuthorizedWallets runs in a background goroutine and refreshes the authorized wallets list
func (g *SolanaRegistryGater) refreshAuthorizedWallets() {
	defer g.wg.Done()

	// Initial refresh
	g.refreshCache()

	ticker := time.NewTicker(g.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-g.ctx.Done():
			g.logger.Info("Stopping authorized wallets refresh process")
			return
		case <-ticker.C:
			g.refreshCache()
		}
	}
}

// refreshCache fetches the current authorized wallets and updates the cache
func (g *SolanaRegistryGater) refreshCache() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authorizedWallets, err := g.getAuthorizedWallets(ctx)
	if err != nil {
		g.logger.Warn("Failed to refresh authorized wallets cache",
			"error", err.Error())
		return
	}

	// Clear existing cache and populate with new authorized wallets
	g.cache.mutex.Lock()
	g.cache.authorizedWallets = sync.Map{}

	for _, wallet := range authorizedWallets {
		g.cache.authorizedWallets.Store(wallet, true)
	}
	g.cache.mutex.Unlock()

	g.logger.Debug("Refreshed authorized wallets cache",
		"authorized_wallets_count", len(authorizedWallets))
}

// Stop stops the background refresh process
func (g *SolanaRegistryGater) Stop() {
	g.cancel()
	g.wg.Wait()
	g.logger.Info("SolanaRegistryGater stopped")
}

// InterceptPeerDial validates outgoing connections against registry
func (g *SolanaRegistryGater) InterceptPeerDial(p peer.ID) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authorized, err := g.isAuthorizedPeer(ctx, p)
	if err != nil {
		g.logger.Warn("Failed to check peer authorization for outgoing connection",
			"peer_id", p.String(),
			"error", err.Error())
		return false
	}

	if !authorized {
		g.logger.Debug("Blocking outgoing connection to unauthorized peer",
			"peer_id", p.String())
		return false
	}

	g.logger.Debug("Allowing outgoing connection to authorized peer",
		"peer_id", p.String())
	return true
}

// InterceptAddrDial validates specific address connections
func (g *SolanaRegistryGater) InterceptAddrDial(p peer.ID, m multiaddr.Multiaddr) bool {
	// Use the same logic as InterceptPeerDial
	return g.InterceptPeerDial(p)
}

// InterceptAccept validates incoming connections (initial filter)
func (g *SolanaRegistryGater) InterceptAccept(network.ConnMultiaddrs) bool {
	// Allow all incoming connections at address level
	// Authorization happens in InterceptSecured after handshake
	return true
}

// InterceptSecured performs post-handshake authorization via wallet registry lookup
func (g *SolanaRegistryGater) InterceptSecured(direction network.Direction, p peer.ID, connMultiaddr network.ConnMultiaddrs) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authorized, err := g.isAuthorizedPeer(ctx, p)
	if err != nil {
		g.logger.Warn("Failed to check peer authorization after handshake",
			"peer_id", p.String(),
			"direction", direction.String(),
			"error", err.Error())
		return false
	}

	if !authorized {
		g.logger.Info("Blocking connection from unauthorized peer",
			"peer_id", p.String(),
			"direction", direction.String())
		return false
	}

	g.logger.Info("Accepting connection from authorized peer",
		"peer_id", p.String(),
		"direction", direction.String())
	return true
}

// InterceptUpgraded validates connections after protocol upgrade (no additional checks needed)
func (g *SolanaRegistryGater) InterceptUpgraded(network.Conn) (allow bool, reason control.DisconnectReason) {
	// All authorization already done in InterceptSecured
	return true, 0
}

// isAuthorizedPeer checks if a peer is authorized by looking up its wallet in the cache
func (g *SolanaRegistryGater) isAuthorizedPeer(ctx context.Context, peerID peer.ID) (bool, error) {
	// Extract Solana public key from peer ID
	solanaPublicKey, err := PeerIDToSolanaPublicKey(peerID)
	if err != nil {
		g.logger.Debug("Failed to extract Solana public key from peer ID",
			"peer_id", peerID.String(),
			"error", err.Error())
		return false, err
	}

	// Check wallet authorization using the cache
	authorized, err := g.checkWalletInCache(ctx, solanaPublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to check wallet in cache: %w", err)
	}

	g.logger.Debug("Checked peer authorization against cache",
		"peer_id", peerID.String(),
		"wallet", solanaPublicKey.String(),
		"authorized", authorized)

	return authorized, nil
}

// checkWalletInCache checks if a wallet is authorized by looking it up in the cache
func (g *SolanaRegistryGater) checkWalletInCache(ctx context.Context, wallet solana.PublicKey) (bool, error) {
	// Check cache first
	if _, found := g.cache.authorizedWallets.Load(wallet); found {
		g.logger.Debug("Found wallet in authorized cache",
			"wallet", wallet.String())
		return true, nil
	}

	// If not in cache, check registry directly (fallback for new wallets)
	g.logger.Debug("Wallet not found in cache, checking registry",
		"wallet", wallet.String())

	authorizedWallets, err := g.getAuthorizedWallets(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get authorized wallets from registry: %w", err)
	}

	// Check if wallet is in the authorized list
	authorized := false
	for _, authorizedWallet := range authorizedWallets {
		if wallet.Equals(authorizedWallet) {
			authorized = true
			break
		}
	}

	// If authorized, add to cache for future lookups
	if authorized {
		g.cache.authorizedWallets.Store(wallet, true)
		g.logger.Debug("Added wallet to cache after registry check",
			"wallet", wallet.String())
	}

	g.logger.Debug("Checked wallet authorization against registry",
		"wallet", wallet.String(),
		"authorized", authorized,
		"total_authorized_wallets", len(authorizedWallets))

	return authorized, nil
}

// ClearCache clears the authorization cache (useful for testing)
func (g *SolanaRegistryGater) ClearCache() {
	g.cache.mutex.Lock()
	defer g.cache.mutex.Unlock()

	g.cache.authorizedWallets = sync.Map{}
	g.logger.Debug("Cleared authorization cache")
}
