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
	KnownNodes     string
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
		"-known-nodes", n.KnownNodes, // Use known nodes for gater
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

	// Create 5 nodes for testing - node 4 will be excluded from known-nodes
	numNodes := 5
	authorizedNodes := 4 // Only nodes 0,1,2,3 are authorized
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

		// Create bootstrap list with public_key:address pairs for other nodes
		// EXCLUDE node 4 from bootstrap lists since it's unauthorized
		var bootstrapList []string
		for j := 0; j < authorizedNodes; j++ { // Only include authorized nodes (0,1,2,3)
			if j != i {
				bootstrapList = append(bootstrapList, fmt.Sprintf("%s:127.0.0.1:%d", walletKeys[j], 3500+j))
			}
		}
		bootstrapStr := strings.Join(bootstrapList, ",")

		// Create known nodes list for gater - ONLY include nodes 0,1,2,3 (exclude node 4)
		var knownNodesList []string
		for j := 0; j < authorizedNodes; j++ {
			knownNodesList = append(knownNodesList, fmt.Sprintf("%s:127.0.0.1:%d", walletKeys[j], 3500+j))
		}
		knownNodesStr := strings.Join(knownNodesList, ",")

		node := &NodeProcess{
			Port:           port,
			HTTPPort:       httpPort,
			WalletFile:     fmt.Sprintf("test_wallet_%d.json", i),
			BootstrapNodes: bootstrapStr,
			KnownNodes:     knownNodesStr,
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

	// Test comprehensive pub/sub functionality with gater isolation
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

		// Step 2: Test pub/sub between authorized nodes (0,1,2,3) - they should communicate
		t.Log("=== Testing authorized nodes communication (0,1,2,3) ===")
		authorizedNodes := []int{0, 1, 2, 3}

		for _, publisherNode := range authorizedNodes {
			// Create unique message with timestamp
			timestamp := time.Now().Format("2006-01-02T15:04:05.000Z")
			message := fmt.Sprintf("Authorized message from node %d at %s", publisherNode, timestamp)

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

			// Check that OTHER authorized nodes received the message
			for _, receiverNode := range authorizedNodes {
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
						t.Fatalf("Invalid messages format from node %d - expected []interface{}, got %T", receiverNode, response["messages"])
					}
				} else {
					messages = make([]interface{}, 0)
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
				}
			}

			// Check that UNAUTHORIZED node 4 did NOT receive the message
			resp4, err4 := http.Get(fmt.Sprintf("http://localhost:%d/messages?topic=%s", nodes[4].HTTPPort, topic))
			if err4 != nil {
				t.Fatalf("Failed to get messages from node 4: %v", err4)
			}

			var response4 map[string]interface{}
			if err := json.NewDecoder(resp4.Body).Decode(&response4); err != nil {
				resp4.Body.Close()
				t.Fatalf("Failed to decode messages from node 4: %v", err)
			}
			resp4.Body.Close()

			var messages4 []interface{}
			if messagesRaw := response4["messages"]; messagesRaw != nil {
				var ok bool
				messages4, ok = messagesRaw.([]interface{})
				if !ok {
					messages4 = make([]interface{}, 0)
				}
			} else {
				messages4 = make([]interface{}, 0)
			}

			// Look for the message - it should NOT be there
			found4 := false
			for _, msg := range messages4 {
				msgMap, ok := msg.(map[string]interface{})
				if !ok {
					continue
				}
				if msgContent, ok := msgMap["message"].(string); ok && msgContent == message {
					found4 = true
					break
				}
			}

			if found4 {
				t.Errorf("✗ SECURITY BREACH: Node 4 (unauthorized) received message from node %d: %s", publisherNode, message)
			} else {
				t.Logf("✓ Node 4 (unauthorized) correctly did NOT receive message from node %d", publisherNode)
			}
		}

		// Step 3: Test that messages from unauthorized node 4 are not visible to authorized nodes
		t.Log("=== Testing unauthorized node 4 isolation ===")

		timestamp := time.Now().Format("2006-01-02T15:04:05.000Z")
		unauthorizedMessage := fmt.Sprintf("UNAUTHORIZED message from node 4 at %s", timestamp)

		t.Logf("Node 4 (unauthorized) publishing: %s", unauthorizedMessage)

		// Node 4 publishes message
		respPub, errPub := http.Post(
			fmt.Sprintf("http://localhost:%d/publish", nodes[4].HTTPPort),
			"application/json",
			strings.NewReader(fmt.Sprintf(`{"topic":"%s","message":"%s"}`, topic, unauthorizedMessage)),
		)
		if errPub != nil {
			t.Fatalf("Failed to publish from node 4: %v", errPub)
		}
		respPub.Body.Close()

		if respPub.StatusCode != http.StatusOK {
			t.Fatalf("Publish request failed from node 4 with status: %d", respPub.StatusCode)
		}

		// Wait for potential message propagation
		time.Sleep(3 * time.Second)

		// Check that authorized nodes did NOT receive the unauthorized message
		for _, receiverNode := range authorizedNodes {
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

			var messages []interface{}
			if messagesRaw := response["messages"]; messagesRaw != nil {
				var ok bool
				messages, ok = messagesRaw.([]interface{})
				if !ok {
					messages = make([]interface{}, 0)
				}
			} else {
				messages = make([]interface{}, 0)
			}

			// Look for the unauthorized message - it should NOT be there
			found := false
			for _, msg := range messages {
				msgMap, ok := msg.(map[string]interface{})
				if !ok {
					continue
				}
				if msgContent, ok := msgMap["message"].(string); ok && msgContent == unauthorizedMessage {
					found = true
					break
				}
			}

			if found {
				t.Errorf("✗ SECURITY BREACH: Node %d (authorized) received message from unauthorized node 4: %s", receiverNode, unauthorizedMessage)
			} else {
				t.Logf("✓ Node %d (authorized) correctly did NOT receive message from unauthorized node 4", receiverNode)
			}
		}

		t.Log("✓ Gater security test completed successfully!")
		t.Log("✓ Authorized nodes (0,1,2,3) can communicate with each other")
		t.Log("✓ Unauthorized node 4 is properly isolated from the network")
	})
}

func ensureWalletFiles(t *testing.T) {
	for i := 0; i < 5; i++ {
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
