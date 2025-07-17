package common

import (
	"crypto/ed25519"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// CreateIdentityFromSolanaKey converts a Base58-encoded Solana private key to libp2p identity
func CreateIdentityFromSolanaKey(privateKeyBase58 string) (crypto.PrivKey, peer.ID, error) {
	// Parse the Base58-encoded Solana private key
	solanaPrivateKey, err := solana.PrivateKeyFromBase58(privateKeyBase58)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse Solana private key: %w", err)
	}

	// Extract the Ed25519 key bytes (Solana uses Ed25519)
	ed25519PrivateKey := ed25519.PrivateKey(solanaPrivateKey)

	// Create libp2p Ed25519 private key from the bytes
	libp2pPrivateKey, err := crypto.UnmarshalEd25519PrivateKey(ed25519PrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create libp2p private key: %w", err)
	}

	// Generate deterministic peer ID from public key
	peerID, err := peer.IDFromPrivateKey(libp2pPrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate peer ID: %w", err)
	}

	return libp2pPrivateKey, peerID, nil
}

// CreatePeerIDFromSolanaPublicKey creates a libp2p peer ID from a Solana public key
func CreatePeerIDFromSolanaPublicKey(solanaPublicKey solana.PublicKey) (peer.ID, error) {
	// Get the Ed25519 public key bytes
	publicKeyBytes := solanaPublicKey.Bytes()

	// Create libp2p Ed25519 public key from the bytes
	libp2pPublicKey, err := crypto.UnmarshalEd25519PublicKey(publicKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create libp2p public key: %w", err)
	}

	// Generate deterministic peer ID from public key
	peerID, err := peer.IDFromPublicKey(libp2pPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate peer ID: %w", err)
	}

	return peerID, nil
}

// ExtractSolanaPublicKey extracts the Solana public key from a Base58 private key
func ExtractSolanaPublicKey(privateKeyBase58 string) (solana.PublicKey, error) {
	solanaPrivateKey, err := solana.PrivateKeyFromBase58(privateKeyBase58)
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("failed to parse Solana private key: %w", err)
	}

	return solanaPrivateKey.PublicKey(), nil
}

// PeerIDToSolanaPublicKey attempts to extract a Solana public key from a libp2p peer ID
// This only works if the peer uses Ed25519 keys (which our system enforces)
func PeerIDToSolanaPublicKey(peerID peer.ID) (solana.PublicKey, error) {
	// Extract the public key from the peer ID
	publicKey, err := peerID.ExtractPublicKey()
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("failed to extract public key from peer ID: %w", err)
	}

	// Ensure it's an Ed25519 key
	ed25519PublicKey, ok := publicKey.(*crypto.Ed25519PublicKey)
	if !ok {
		return solana.PublicKey{}, fmt.Errorf("peer ID does not use Ed25519 key")
	}

	// Get the raw bytes
	publicKeyBytes, err := ed25519PublicKey.Raw()
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("failed to get raw public key bytes: %w", err)
	}

	// Create Solana public key from the Ed25519 bytes
	return solana.PublicKeyFromBytes(publicKeyBytes), nil
}
