package pubsub

import (
	"context"
	"fmt"
	"time"

	"github.com/dTelecom/p2p-database/common"
	"github.com/libp2p/go-libp2p-kad-dht/dual"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/multiformats/go-multiaddr"
)

// DiscoveryService provides peer discovery functionality
type DiscoveryService struct {
	host      host.Host
	dht       *dual.DHT
	discovery *routing.RoutingDiscovery
	logger    common.Logger
}

// NewDiscoveryService creates a new discovery service
func NewDiscoveryService(host host.Host, dht *dual.DHT, logger common.Logger) *DiscoveryService {
	return &DiscoveryService{
		host:      host,
		dht:       dht,
		discovery: routing.NewRoutingDiscovery(dht),
		logger:    logger,
	}
}

// StartDiscovery starts the discovery process for a database
func (ds *DiscoveryService) StartDiscovery(ctx context.Context, databaseName string) error {
	// Create rendezvous point for this database
	rendezvous := fmt.Sprintf("p2p-database-discovery_%s", databaseName)

	ds.logger.Info("Starting peer discovery",
		"database", databaseName,
		"rendezvous", rendezvous)

	// Start advertising ourselves
	go ds.advertiseLoop(ctx, rendezvous)

	// Start finding peers
	go ds.findPeersLoop(ctx, rendezvous)

	return nil
}

// advertiseLoop periodically advertises this node to the network
func (ds *DiscoveryService) advertiseLoop(ctx context.Context, rendezvous string) {
	// Immediate advertisement on startup
	util.Advertise(ctx, ds.discovery, rendezvous)
	ds.logger.Debug("Initial advertisement on rendezvous", "rendezvous", rendezvous)

	// Continue with periodic advertisements (fast interval for quick connectivity)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Advertise ourselves
			util.Advertise(ctx, ds.discovery, rendezvous)
			ds.logger.Debug("Advertised on rendezvous",
				"rendezvous", rendezvous)
		}
	}
}

// findPeersLoop periodically searches for peers
func (ds *DiscoveryService) findPeersLoop(ctx context.Context, rendezvous string) {
	// Immediate peer discovery on startup
	peers, err := util.FindPeers(ctx, ds.discovery, rendezvous)
	if err != nil {
		ds.logger.Debug("Initial peer discovery failed", "rendezvous", rendezvous, "error", err.Error())
	} else {
		go ds.processPeers(ctx, peers, rendezvous)
	}

	// Continue with periodic peer discovery (fast interval for quick connectivity)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Find peers
			peers, err := util.FindPeers(ctx, ds.discovery, rendezvous)
			if err != nil {
				ds.logger.Warn("Failed to find peers",
					"rendezvous", rendezvous,
					"error", err.Error())
				continue
			}

			// Process found peers
			go ds.processPeers(ctx, peers, rendezvous)
		}
	}
}

// processPeers processes peers found through discovery
func (ds *DiscoveryService) processPeers(ctx context.Context, peers []peer.AddrInfo, rendezvous string) {
	connectedCount := 0

	for _, peerInfo := range peers {
		// Skip if it's ourselves
		if peerInfo.ID == ds.host.ID() {
			continue
		}

		// Skip if already connected
		if ds.host.Network().Connectedness(peerInfo.ID) == network.Connected {
			continue
		}

		// Try to connect
		connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := ds.host.Connect(connectCtx, peerInfo); err != nil {
			ds.logger.Debug("Failed to connect to discovered peer",
				"peer_id", peerInfo.ID.String(),
				"rendezvous", rendezvous,
				"error", err.Error())
			cancel()
			continue
		}
		cancel()

		connectedCount++
		ds.logger.Info("Connected to discovered peer",
			"peer_id", peerInfo.ID.String(),
			"rendezvous", rendezvous,
			"addrs", peerInfo.Addrs)

		// Limit connections per discovery round
		if connectedCount >= 5 {
			break
		}
	}

	if connectedCount > 0 {
		ds.logger.Info("Discovery round completed",
			"rendezvous", rendezvous,
			"new_connections", connectedCount)
	}
}

// GetConnectedPeers returns information about currently connected peers
func (ds *DiscoveryService) GetConnectedPeers() []peer.AddrInfo {
	peers := ds.host.Network().Peers()
	var peerInfos []peer.AddrInfo

	for _, peerID := range peers {
		conns := ds.host.Network().ConnsToPeer(peerID)
		if len(conns) > 0 {
			peerInfo := peer.AddrInfo{
				ID:    peerID,
				Addrs: make([]multiaddr.Multiaddr, 0, len(conns)),
			}
			for _, conn := range conns {
				peerInfo.Addrs = append(peerInfo.Addrs, conn.RemoteMultiaddr())
			}
			peerInfos = append(peerInfos, peerInfo)
		}
	}

	return peerInfos
}

// GetDHTStats returns DHT statistics
func (ds *DiscoveryService) GetDHTStats() map[string]interface{} {
	return map[string]interface{}{
		"connected_peers": len(ds.host.Network().Peers()),
	}
}
