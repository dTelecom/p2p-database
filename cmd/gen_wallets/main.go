package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58"
)

type WalletFile struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Address    string `json:"address"`
}

func main() {
	const walletCount = 3
	wallets := make([]*WalletFile, walletCount)

	for i := 0; i < walletCount; i++ {
		kp := solana.NewWallet()
		// Solana expects the seed (first 32 bytes) as the private key for wallet import
		privSeed := kp.PrivateKey[:32]
		privBase58 := base58.Encode(privSeed)
		pubBase58 := base58.Encode(kp.PublicKey().Bytes())
		address := kp.PublicKey().String()

		wallets[i] = &WalletFile{
			PrivateKey: privBase58,
			PublicKey:  pubBase58,
			Address:    address,
		}

		filename := filepath.Join("testdata", fmt.Sprintf("wallet%d.json", i+1))
		f, err := os.Create(filename)
		if err != nil {
			panic(fmt.Sprintf("Failed to create wallet file: %v", err))
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(wallets[i]); err != nil {
			panic(fmt.Sprintf("Failed to write wallet file: %v", err))
		}
		f.Close()
		fmt.Printf("Generated %s: %s\n", filename, address)
	}

	fmt.Println("All wallets generated in testdata/.")
}
