package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/gagliardetto/solana-go"
)

func main() {
	var (
		count  = flag.Int("count", 1, "Number of keypairs to generate")
		format = flag.String("format", "base58", "Output format: base58, json, env")
		output = flag.String("output", "", "Output file (default: stdout)")
	)
	flag.Parse()

	if *count < 1 {
		log.Fatal("Count must be at least 1")
	}

	var result string

	switch *format {
	case "base58":
		for i := 0; i < *count; i++ {
			account := solana.NewWallet()
			privateKey := account.PrivateKey
			publicKey := account.PublicKey()

			fmt.Printf("# Keypair %d\n", i+1)
			fmt.Printf("Private Key: %s\n", privateKey.String())
			fmt.Printf("Public Key:  %s\n", publicKey.String())
			fmt.Printf("Address:     %s\n\n", publicKey.String())

			if i == 0 {
				result = privateKey.String()
			}
		}

	case "json":
		type Keypair struct {
			PrivateKey string `json:"private_key"`
			PublicKey  string `json:"public_key"`
			Address    string `json:"address"`
		}

		var keypairs []Keypair
		for i := 0; i < *count; i++ {
			account := solana.NewWallet()
			privateKey := account.PrivateKey
			publicKey := account.PublicKey()

			keypairs = append(keypairs, Keypair{
				PrivateKey: privateKey.String(),
				PublicKey:  publicKey.String(),
				Address:    publicKey.String(),
			})
		}

		jsonData, err := json.MarshalIndent(keypairs, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal JSON: %v", err)
		}
		result = string(jsonData)

	case "env":
		for i := 0; i < *count; i++ {
			account := solana.NewWallet()
			privateKey := account.PrivateKey
			publicKey := account.PublicKey()

			suffix := ""
			if *count > 1 {
				suffix = fmt.Sprintf("_%d", i+1)
			}

			fmt.Printf("# Keypair %d\n", i+1)
			fmt.Printf("WALLET_PRIVATE_KEY%s=%s\n", suffix, privateKey.String())
			fmt.Printf("WALLET_PUBLIC_KEY%s=%s\n", suffix, publicKey.String())
			fmt.Printf("WALLET_ADDRESS%s=%s\n\n", suffix, publicKey.String())

			if i == 0 {
				result = privateKey.String()
			}
		}

	default:
		log.Fatalf("Unknown format: %s. Valid formats: base58, json, env", *format)
	}

	// Write to file if specified
	if *output != "" {
		err := os.WriteFile(*output, []byte(result), 0600)
		if err != nil {
			log.Fatalf("Failed to write to file %s: %v", *output, err)
		}
		fmt.Printf("Keys written to %s\n", *output)
	}
}
