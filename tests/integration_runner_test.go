package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type NodeProcess struct {
	Port           int
	HTTPPort       int
	WalletFile     string
	BootstrapNodes string
	cmd            *exec.Cmd
}

func (n *NodeProcess) Start() error {
	// Load wallet private key
	privateKey, err := loadWalletPrivateKey(n.WalletFile)
	if err != nil {
		return fmt.Errorf("failed to load wallet: %v", err)
	}

	// Build the binary first to avoid the 'go run' intermediate process issue
	buildCmd := exec.Command("go", "build", "-o", fmt.Sprintf("test-node-%d", n.Port), "../cmd/p2p-node/main.go")
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("failed to build node binary: %v", err)
	}

	// Run the built binary directly
	binaryPath := fmt.Sprintf("./test-node-%d", n.Port)
	n.cmd = exec.Command(
		binaryPath,
		"-port", fmt.Sprintf("%d", n.Port),
		"-http-port", fmt.Sprintf("%d", n.HTTPPort),
		"-wallet", privateKey,
		"-db", "test_network",
		"-bootstrap", n.BootstrapNodes,
		"-disable-gater", // Disable gater for testing
	)

	// Capture output for debugging - enable to see node logs
	n.cmd.Stdout = os.Stdout
	n.cmd.Stderr = os.Stderr

	// Start the process
	return n.cmd.Start()
}

func (n *NodeProcess) Stop() {
	if n.cmd != nil && n.cmd.Process != nil {
		// Send SIGTERM first for graceful shutdown
		n.cmd.Process.Signal(os.Interrupt)

		// Wait briefly for graceful shutdown
		done := make(chan error, 1)
		go func() {
			done <- n.cmd.Wait()
		}()

		select {
		case <-done:
			// Graceful shutdown completed
		case <-time.After(2 * time.Second):
			// Force kill if graceful shutdown takes too long
			n.cmd.Process.Kill()
			n.cmd.Wait()
		}
	}

	// Clean up the built binary
	binaryPath := fmt.Sprintf("./test-node-%d", n.Port)
	if _, err := os.Stat(binaryPath); err == nil {
		os.Remove(binaryPath)
	}
}

func (n *NodeProcess) IsRunning() bool {
	return n.cmd != nil && n.cmd.Process != nil && n.cmd.ProcessState == nil
}

func (n *NodeProcess) WaitForReady(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for node to be ready")
		case <-ticker.C:
			// Try to connect to HTTP API
			resp, err := http.Get(fmt.Sprintf("http://localhost:%d/health", n.HTTPPort))
			if err == nil && resp.StatusCode == http.StatusOK {
				resp.Body.Close()
				return nil
			}
			if resp != nil {
				resp.Body.Close()
			}
		}
	}
}

func TestIntegrationWithMultipleNodes(t *testing.T) {

	// Ensure we have wallet files
	ensureWalletFiles(t)

	// Create 4 nodes for testing
	numNodes := 4
	nodes := make([]*NodeProcess, numNodes)

	// Cleanup function - define early so it's always available
	cleanup := func() {
		t.Log("Cleaning up nodes...")
		for i, node := range nodes {
			if node != nil {
				t.Logf("Stopping node %d", i)
				node.Stop()
			}
		}
	}
	defer cleanup()

	// Load all wallet public keys first
	walletKeys := make([]string, numNodes)
	for i := 0; i < numNodes; i++ {
		walletFile := fmt.Sprintf("test_wallet_%d.json", i)
		publicKey, err := loadWalletPublicKey(walletFile)
		if err != nil {
			t.Fatalf("Failed to load public key from %s: %v", walletFile, err)
		}
		walletKeys[i] = publicKey
	}

	// Start all nodes
	for i := 0; i < numNodes; i++ {
		port := 3500 + i
		httpPort := 8081 + i

		// Create bootstrap list with public_key:address pairs for 3 other nodes
		var bootstrapList []string
		for j := 0; j < numNodes; j++ {
			if j != i {
				bootstrapList = append(bootstrapList, fmt.Sprintf("%s:127.0.0.1:%d", walletKeys[j], 3500+j))
			}
		}
		bootstrapStr := strings.Join(bootstrapList, ",")

		node := &NodeProcess{
			Port:           port,
			HTTPPort:       httpPort,
			WalletFile:     fmt.Sprintf("test_wallet_%d.json", i),
			BootstrapNodes: bootstrapStr,
		}

		if err := node.Start(); err != nil {
			cleanup() // Clean up any already started nodes
			t.Fatalf("Failed to start node %d: %v", i, err)
		}
		nodes[i] = node
		t.Logf("Node %d started with PID: %d", i, node.cmd.Process.Pid)

		// Wait a bit between starting nodes
		time.Sleep(2 * time.Second)

		// Check if node is still running
		if node.cmd.ProcessState != nil {
			t.Fatalf("Node %d exited early with state: %v", i, node.cmd.ProcessState)
		}
	}

	// Wait for all nodes to be ready
	t.Log("Waiting for all nodes to be ready...")
	for i, node := range nodes {
		if err := node.WaitForReady(30 * time.Second); err != nil {
			cleanup() // Clean up on readiness failure
			t.Fatalf("Node %d failed to become ready: %v", i, err)
		}
		t.Logf("Node %d is ready", i)
	}

	// Test comprehensive pub/sub functionality
	t.Run("TestPubSub", func(t *testing.T) {
		// First verify all nodes are still running
		for i, node := range nodes {
			if node.cmd.ProcessState != nil {
				t.Fatalf("Node %d has exited before pub/sub test: %v", i, node.cmd.ProcessState)
			}
			t.Logf("Node %d (PID: %d) is still running", i, node.cmd.Process.Pid)
		}

		topic := "test_topic"

		// Check all nodes are still running before starting test
		t.Log("Checking node health before subscription...")
		for i, node := range nodes {
			if !node.IsRunning() {
				t.Fatalf("Node %d is not running before subscription test", i)
			}
		}

		// Step 1: All nodes subscribe to test_topic
		t.Log("All nodes subscribing to test_topic...")
		for i, node := range nodes {
			resp, err := http.Post(
				fmt.Sprintf("http://localhost:%d/subscribe", node.HTTPPort),
				"application/json",
				strings.NewReader(fmt.Sprintf(`{"topic":"%s"}`, topic)),
			)
			if err != nil {
				t.Fatalf("Failed to subscribe on node %d: %v", i, err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Subscribe request failed on node %d with status: %d", i, resp.StatusCode)
			}
			t.Logf("Node %d subscribed to %s", i, topic)
		}

		// Wait for subscriptions to propagate
		time.Sleep(3 * time.Second)

		// Debug: Check connected peers for each node using /peers endpoint
		for i, node := range nodes {
			resp, err := http.Get(fmt.Sprintf("http://localhost:%d/peers", node.HTTPPort))
			if err != nil {
				t.Logf("Failed to get peers from node %d: %v", i, err)
				continue
			}

			var peersResponse map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&peersResponse); err != nil {
				resp.Body.Close()
				t.Logf("Failed to decode peers from node %d: %v", i, err)
				continue
			}
			resp.Body.Close()

			count, _ := peersResponse["count"].(float64)
			peers, _ := peersResponse["peers"].([]interface{})

			t.Logf("Node %d has %d connected peers:", i, int(count))
			for j, peer := range peers {
				if peerMap, ok := peer.(map[string]interface{}); ok {
					peerID, _ := peerMap["id"].(string)
					addr, _ := peerMap["addr"].(string)
					t.Logf("  Peer %d: %s at %s", j, peerID, addr)
				}
			}
		}

		// Step 2: Test pub/sub between all nodes (0, 1, 2, 3)
		testNodes := []int{0, 1, 2, 3} // Test all nodes for pub/sub

		for _, publisherNode := range testNodes {
			// Create unique message with timestamp
			timestamp := time.Now().Format("2006-01-02T15:04:05.000Z")
			message := fmt.Sprintf("Message from node %d at %s", publisherNode, timestamp)

			t.Logf("Node %d publishing: %s", publisherNode, message)

			// Publish message
			resp, err := http.Post(
				fmt.Sprintf("http://localhost:%d/publish", nodes[publisherNode].HTTPPort),
				"application/json",
				strings.NewReader(fmt.Sprintf(`{"topic":"%s","message":"%s"}`, topic, message)),
			)
			if err != nil {
				t.Fatalf("Failed to publish from node %d: %v", publisherNode, err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Publish request failed from node %d with status: %d", publisherNode, resp.StatusCode)
			}

			// Wait for message propagation
			time.Sleep(3 * time.Second)

			// Check that OTHER test nodes received the message
			for _, receiverNode := range testNodes {
				if receiverNode == publisherNode {
					continue // Skip self
				}

				// Get messages from receiver node
				resp, err := http.Get(fmt.Sprintf("http://localhost:%d/messages?topic=%s", nodes[receiverNode].HTTPPort, topic))
				if err != nil {
					t.Fatalf("Failed to get messages from node %d: %v", receiverNode, err)
				}

				var response map[string]interface{}
				if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
					resp.Body.Close()
					t.Fatalf("Failed to decode messages from node %d: %v", receiverNode, err)
				}
				resp.Body.Close()

				// Check if the message was received
				var messages []interface{}
				if messagesRaw := response["messages"]; messagesRaw != nil {
					var ok bool
					messages, ok = messagesRaw.([]interface{})
					if !ok {
						// Log the actual response for debugging
						t.Logf("Response from node %d: %+v", receiverNode, response)
						t.Fatalf("Invalid messages format from node %d - expected []interface{}, got %T", receiverNode, response["messages"])
					}
				} else {
					// Handle nil case by treating it as empty array
					messages = make([]interface{}, 0)
					t.Logf("Node %d returned nil messages, treating as empty array", receiverNode)
				}

				// Look for our specific message
				found := false
				for _, msg := range messages {
					msgMap, ok := msg.(map[string]interface{})
					if !ok {
						continue
					}
					if msgContent, ok := msgMap["message"].(string); ok && msgContent == message {
						found = true
						t.Logf("✓ Node %d received message from node %d: %s", receiverNode, publisherNode, message)
						break
					}
				}

				if !found {
					t.Errorf("✗ Node %d did NOT receive message from node %d: %s", receiverNode, publisherNode, message)
					t.Logf("Node %d has %d total messages", receiverNode, len(messages))
				}
			}
		}

		t.Log("Comprehensive pub/sub test completed successfully!")
	})
}

func ensureWalletFiles(t *testing.T) {
	for i := 0; i < 4; i++ {
		filename := fmt.Sprintf("../test_wallet_%d.json", i)
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			t.Fatalf("Wallet file %s not found. Run 'make generate-wallets' first.", filename)
		}
	}
}

func loadWalletPrivateKey(filename string) (string, error) {
	// Prepend ../ to look in project root directory
	fullPath := fmt.Sprintf("../%s", filename)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return "", err
	}

	var wallet struct {
		PrivateKey string `json:"private_key"`
	}

	if err := json.Unmarshal(data, &wallet); err != nil {
		return "", err
	}

	return wallet.PrivateKey, nil
}

func loadWalletPublicKey(filename string) (string, error) {
	// Prepend ../ to look in project root directory
	fullPath := fmt.Sprintf("../%s", filename)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return "", err
	}

	var wallet struct {
		PublicKey string `json:"public_key"`
	}

	if err := json.Unmarshal(data, &wallet); err != nil {
		return "", err
	}

	return wallet.PublicKey, nil
}
