package p2p_database

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/dTelecom/p2p-database/internal/common"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
)

type SolanaConnectionGater struct {
	cache  sync.Map
	logger common.Logger
	cfg    Config
}

func NewSolanaConnectionGater(logger common.Logger, cfg Config) *SolanaConnectionGater {
	g := &SolanaConnectionGater{
		logger: logger,
		cfg:    cfg,
	}
	return g
}

func (e *SolanaConnectionGater) InterceptPeerDial(p peer.ID) (allow bool) {
	return e.checkPeerId(p, "InterceptPeerDial")
}

func (e *SolanaConnectionGater) InterceptAddrDial(id peer.ID, multiaddr multiaddr.Multiaddr) (allow bool) {
	return e.checkPeerId(id, "InterceptAddrDial")
}

func (e *SolanaConnectionGater) InterceptAccept(multiaddrs network.ConnMultiaddrs) (allow bool) {
	return true
}

func (e *SolanaConnectionGater) InterceptSecured(direction network.Direction, id peer.ID, multiaddrs network.ConnMultiaddrs) (allow bool) {
	return e.checkPeerId(id, "InterceptSecured")
}

func (e *SolanaConnectionGater) InterceptUpgraded(conn network.Conn) (allow bool, reason control.DisconnectReason) {
	return true, 0
}

func (e *SolanaConnectionGater) checkPeerId(p peer.ID, method string) bool {
	if e.cfg.DisableGater {
		return true
	}

	cachedRaw, ok := e.cache.Load(p)
	if ok {
		cached, ok := cachedRaw.(bool)
		if ok {
			return cached
		}
	}

	e.logger.Debugf("call method %s with %s", method, p)
	r, err := e.validatePeer(p)

	if err != nil {
		e.logger.Warnf("try validate peer %s with method %s error %s", p, method, err)
		return false
	}

	if !r {
		e.logger.Debugf("try validate peer %s with method %s: invalid", p, method)
	} else {
		e.logger.Debugf("%s peer %s validation success", method, p)
	}

	e.cache.Store(p, r)

	return r
}

func (e *SolanaConnectionGater) GetBoostrapNodes() (res []peer.AddrInfo, err error) {
	for key, ip := range e.cfg.GetNodes() {
		peerId, err := getPeerIdFromPublicKey(key)
		if err != nil {
			e.logger.Errorf(
				"get bootstrap peer id %s ip %s",
				err,
				ip,
			)
			continue
		}

		// Parse IP and port from the value
		var nodeIP string
		var nodePort int = 3500 // Default port

		// Check if the value contains a port (IP:PORT format)
		if strings.Contains(ip, ":") {
			parts := strings.Split(ip, ":")
			if len(parts) == 2 {
				nodeIP = parts[0]
				if port, err := strconv.Atoi(parts[1]); err == nil && port > 0 && port <= 65535 {
					nodePort = port
				} else {
					e.logger.Errorf("invalid port in IP:PORT format: %s", ip)
					continue
				}
			} else {
				e.logger.Errorf("invalid IP:PORT format: %s", ip)
				continue
			}
		} else {
			// Just IP address, use default port
			nodeIP = ip
		}

		// Validate that nodeIP is a valid IPv4 address
		if net.ParseIP(nodeIP) == nil {
			e.logger.Errorf("invalid IPv4 address: %s", nodeIP)
			continue
		}

		e.logger.Infof("Boostrap peer from smart contract /ip4/%s/tcp/%d/p2p/%s\n", nodeIP, nodePort, peerId)

		addr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d/p2p/%s", nodeIP, nodePort, peerId))
		if err != nil {
			e.logger.Errorf(
				"error create multiaddr bootstrap node from contract %s ip %s",
				err,
				ip,
			)
			continue
		}

		peerInfo, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			e.logger.Errorf("error fetch addr info for %s ip %s", err, ip)
			continue
		}

		res = append(res, *peerInfo)
	}

	if len(res) == 0 {
		e.logger.Errorf("empty list bootstrap nodes from smart contract")
	}

	return res, nil
}

func (e *SolanaConnectionGater) validatePeer(p peer.ID) (bool, error) {
	solanaAddr, err := getSolanaAddrFromPeer(p)
	if err != nil {
		return false, errors.Wrap(err, "get solana addr from peer")
	}

	e.logger.Debugf("Validating Solana peer with address %s", solanaAddr)

	nodes := e.cfg.GetNodes()
	_, exists := nodes[solanaAddr]
	return exists, nil
}

func getSolanaAddrFromPeer(p peer.ID) (string, error) {
	pubkey, err := p.ExtractPublicKey()
	if err != nil {
		return "", errors.Wrap(err, "extract pub key")
	}

	// For Ed25519 keys, the public key is directly usable as a Solana address
	dbytes, err := pubkey.Raw()
	if err != nil {
		return "", errors.Wrap(err, "extract raw bytes from public key")
	}

	// Return the Solana base58 encoded public key (address)
	return base58.Encode(dbytes), nil
}

func getPeerIdFromPublicKey(pk string) (string, error) {
	// Decode the base58-encoded Solana public key
	pubKeyBytes, err := base58.Decode(pk)
	if err != nil {
		return "", errors.Wrap(err, "decode base58 solana public key")
	}

	// Unmarshal as Ed25519 public key
	pubKey, err := crypto.UnmarshalEd25519PublicKey(pubKeyBytes)
	if err != nil {
		return "", errors.Wrap(err, "unmarshal Ed25519 public key")
	}

	id, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return "", errors.Wrap(err, "fetch peer_id from pubkey")
	}

	return id.String(), nil
}
