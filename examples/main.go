package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	p2p_database "github.com/dTelecom/p2p-database"
	"github.com/dTelecom/p2p-database/internal/common"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

var (
	solanaPrivateKey = flag.String("pk", "", "solana wallet private key")
	db               *p2p_database.DB
	// Map of node keys to their IP addresses
	allNodes = map[string]string{
		"5g3euBKXqhdbfzkgbWQ7o1C6HQzbyr1noX6wiqfv2i3x": "34.175.243.9",
		"644PeDtMTPE1WFSaTC8BSjaNUN697frNRifciWSqiAZz": "35.205.115.103",
		"CiKDiqBjHs9jTaJANgreQkVgA6J4YhVbYx55tU7swKfk": "34.165.46.203",
	}
)

// GetNodes returns the map of node keys to their IP addresses
func GetNodes() map[string]string {
	return allNodes
}

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		log.Fatalf("expected solana wallet private key as first argument: ./main")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	defer cancel()

	logger := new(common.ConsoleLogger)

	cfg := p2p_database.Config{
		DisableGater:     false,
		DatabaseName:     "livekit_global",
		WalletPrivateKey: *solanaPrivateKey,
		PeerListenPort:   3500,
		GetNodes:         GetNodes,
	}

	var err error
	db, err = p2p_database.Connect(ctx, cfg, logger)
	if err != nil {
		panic(err)
	}

	h := db.GetHost()
	fmt.Printf("Peer id %s\n", h.ID().String())

	fmt.Printf("> ")
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		text := scanner.Text()
		fields := strings.Fields(text)
		if len(fields) == 0 {
			fmt.Printf("[db %s] > ", db.Name)
			continue
		}

		switch fields[0] {
		case "subscribe":
			err = db.Subscribe(ctx, fields[1], func(event p2p_database.Event) {
				fmt.Printf("Got subscription event %v", event)
			})
			if err != nil {
				fmt.Printf("error %s\n", err)
			}
		case "publish":
			_, err = db.Publish(ctx, fields[1], fields[2])
			if err != nil {
				fmt.Printf("error %s\n", err)
			}
		case "peers":
			for _, p := range connectedPeers(db.GetHost()) {
				fmt.Printf("Peer [%s] %s\r\n", p.ID, p.Addrs[0].String())
			}
		}
		fmt.Printf("> ")
	}

	shutdownCtx, c := context.WithTimeout(context.Background(), 15*time.Second)
	defer c()

	fmt.Println("Disconnecting...")
	err = db.Disconnect(shutdownCtx)
	if err != nil {
		panic(err)
	}
}

func connectedPeers(h host.Host) []*peer.AddrInfo {
	var pinfos []*peer.AddrInfo
	for _, c := range h.Network().Conns() {
		pinfos = append(pinfos, &peer.AddrInfo{
			ID:    c.RemotePeer(),
			Addrs: []multiaddr.Multiaddr{c.RemoteMultiaddr()},
		})
	}
	return pinfos
}
