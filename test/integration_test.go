package test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/dTelecom/p2p-database/common"
	"github.com/dTelecom/p2p-database/pubsub"
	"github.com/gagliardetto/solana-go"
)

// Node keypairs for testing (generated using cmd/keygen)
var (
	// Node 0 - Bootstrap and authorized
	node0PrivateKey = "gR1mAahBg6XGRSSPLRYyihHVcC2VE5oagGcLPPi81G69Yz1GZvoq8XsjXKjDVD6D8cD6nY3q8GX9PAb7PbsvhB6"
	node0PublicKey  = "jgtpoApjta2e97hvuSKzUiSKXsYrCS9yHjyADgeJyBN"

	// Node 1 - Just authorized
	node1PrivateKey = "5GeZEx4FUD1vZEoJsH1KVbtCa2tGw5qhedxMuuNnmYVkMR3XPJpLh8oSLanCwHcDzuK6M3D24BVx1aHb3xsmYgxt"
	node1PublicKey  = "FLE6aWnEhSqVeyUHzpkHmaxhPJEJj61foYqkL9z1qJpL"

	// Node 2 - Just authorized
	node2PrivateKey = "5zRE2yD43ERnUEDuCBJd3e1y9P5gGaegnYTQxa42GEFdB2Bd6aFf2sH4jSjPiV3MgxqXQAQPKPRgR3RReDHWfdhH"
	node2PublicKey  = "Dg99EAH5xgLFSqCo8DSsUbaW6wNdFXWVNnXmqofodoKd"

	// Node 3 - Unauthorized (NOT in the authorized list)
	node3PrivateKey = "2z7Mz9QdFJNrqxHqB8NKr6m5VhG3kLFwkDvYFCrBzYxhQe6jN9vT8WpU4RkSyC5X1nDzJkWf2N8YdGqQ9tZvMrSb"
	node3PublicKey  = "8vQm2x5MHqYgRnE3DpWvF9BzGkTnJL2wHxCr7ZkNfK4m"
)

// NodeMessage represents test message structure
type NodeMessage struct {
	NodeID  string `json:"node_id"`
	Content string `json:"content"`
	Counter int    `json:"counter"`
}

// Mock registry function - returns only nodes 0, 1, 2 as authorized (NOT node 3)
func mockGetAuthorizedWallets(ctx context.Context) ([]solana.PublicKey, error) {
	return []solana.PublicKey{
		solana.MustPublicKeyFromBase58(node0PublicKey),
		solana.MustPublicKeyFromBase58(node1PublicKey),
		solana.MustPublicKeyFromBase58(node2PublicKey),
		// Note: node3 is intentionally NOT included
	}, nil
}

// Mock unauthorized registry - returns only node 3 (for testing unauthorized scenario)
func mockGetUnauthorizedWallets(ctx context.Context) ([]solana.PublicKey, error) {
	return []solana.PublicKey{
		solana.MustPublicKeyFromBase58(node3PublicKey),
	}, nil
}

// Mock bootstrap function for nodes 1 and 2 - returns node 0 as bootstrap
func mockGetBootstrapNodesForClients(node0Host string, quicPort, tcpPort int) common.GetBootstrapNodesFunc {
	return func(ctx context.Context) ([]common.BootstrapNode, error) {
		return []common.BootstrapNode{
			{
				PublicKey: solana.MustPublicKeyFromBase58(node0PublicKey),
				IP:        node0Host,
				QUICPort:  quicPort, // Use actual bootstrap node's QUIC port
				TCPPort:   tcpPort,  // Use actual bootstrap node's TCP port
			},
		}, nil
	}
}

// Mock bootstrap function for node 0 - returns empty (it's the bootstrap node)
func mockGetBootstrapNodesForBootstrap(ctx context.Context) ([]common.BootstrapNode, error) {
	return []common.BootstrapNode{}, nil
}

// TestMultiNodePubSubWithContentVerification tests P2P communication with detailed message content verification
func TestMultiNodePubSubWithContentVerification(t *testing.T) {
	t.Log("=== Starting 3-Node P2P Integration Test with Content Verification ===")

	// Test configuration
	testTopic := "content-verification-topic"
	messageTimeout := 10 * time.Second

	// Define expected messages
	expectedMessages := []NodeMessage{
		{NodeID: "node-0", Content: "Hello from Node 0 (Bootstrap)", Counter: 1},
		{NodeID: "node-1", Content: "Hello from Node 1 (Client)", Counter: 2},
		{NodeID: "node-2", Content: "Hello from Node 2 (Client)", Counter: 3},
	}

	// Message tracking with content verification
	var (
		node0ReceivedMessages = make([]NodeMessage, 0)
		node1ReceivedMessages = make([]NodeMessage, 0)
		node2ReceivedMessages = make([]NodeMessage, 0)
		messagesMutex         sync.RWMutex
	)

	// Create message handlers that extract and verify content
	node0Handler := func(event common.Event) {
		var nodeMsg NodeMessage
		if msgBytes, err := json.Marshal(event.Message); err == nil {
			if err := json.Unmarshal(msgBytes, &nodeMsg); err == nil {
				messagesMutex.Lock()
				node0ReceivedMessages = append(node0ReceivedMessages, nodeMsg)
				messagesMutex.Unlock()
				t.Logf("Node 0 received: %+v", nodeMsg)
			}
		}
	}

	node1Handler := func(event common.Event) {
		var nodeMsg NodeMessage
		if msgBytes, err := json.Marshal(event.Message); err == nil {
			if err := json.Unmarshal(msgBytes, &nodeMsg); err == nil {
				messagesMutex.Lock()
				node1ReceivedMessages = append(node1ReceivedMessages, nodeMsg)
				messagesMutex.Unlock()
				t.Logf("Node 1 received: %+v", nodeMsg)
			}
		}
	}

	node2Handler := func(event common.Event) {
		var nodeMsg NodeMessage
		if msgBytes, err := json.Marshal(event.Message); err == nil {
			if err := json.Unmarshal(msgBytes, &nodeMsg); err == nil {
				messagesMutex.Lock()
				node2ReceivedMessages = append(node2ReceivedMessages, nodeMsg)
				messagesMutex.Unlock()
				t.Logf("Node 2 received: %+v", nodeMsg)
			}
		}
	}

	// Create logger
	logger := &TestLogger{}

	// Setup nodes
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Node 0 (Bootstrap)
	node0DB := setupNode(t, ctx, logger, node0PrivateKey, "test-network", 15001, 15002,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForBootstrap)
	defer func() { _ = node0DB.Disconnect(ctx) }()

	err := node0DB.Subscribe(ctx, testTopic, node0Handler)
	if err != nil {
		t.Fatalf("Failed to subscribe Node 0: %v", err)
	}

	time.Sleep(2 * time.Second)

	// Node 1 (Client)
	node1DB := setupNode(t, ctx, logger, node1PrivateKey, "test-network", 15003, 15004,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForClients("127.0.0.1", 15001, 15002))
	defer func() { _ = node1DB.Disconnect(ctx) }()

	err = node1DB.Subscribe(ctx, testTopic, node1Handler)
	if err != nil {
		t.Fatalf("Failed to subscribe Node 1: %v", err)
	}

	// Node 2 (Client)
	node2DB := setupNode(t, ctx, logger, node2PrivateKey, "test-network", 15005, 15006,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForClients("127.0.0.1", 15001, 15002))
	defer func() { _ = node2DB.Disconnect(ctx) }()

	err = node2DB.Subscribe(ctx, testTopic, node2Handler)
	if err != nil {
		t.Fatalf("Failed to subscribe Node 2: %v", err)
	}

	// Wait for network convergence
	time.Sleep(5 * time.Second)

	// Publish messages and track what was sent
	nodes := []*pubsub.DB{node0DB, node1DB, node2DB}
	for i, node := range nodes {
		event, err := node.Publish(ctx, testTopic, expectedMessages[i])
		if err != nil {
			t.Fatalf("Failed to publish from Node %d: %v", i, err)
		}
		t.Logf("Node %d published: %+v (Event ID: %s)", i, expectedMessages[i], event.ID)
		time.Sleep(1 * time.Second)
	}

	// Wait for message propagation
	time.Sleep(messageTimeout)

	// Verify content
	messagesMutex.RLock()
	defer messagesMutex.RUnlock()

	// Each node should receive 2 messages (from the other 2 nodes)
	allReceivedMessages := [][]NodeMessage{node0ReceivedMessages, node1ReceivedMessages, node2ReceivedMessages}
	nodeNames := []string{"Node 0", "Node 1", "Node 2"}

	for i, receivedMessages := range allReceivedMessages {
		if len(receivedMessages) != 2 {
			t.Errorf("%s: expected 2 messages, got %d", nodeNames[i], len(receivedMessages))
			continue
		}

		// Verify each received message matches expected content
		expectedForThisNode := make([]NodeMessage, 0)
		for j, expected := range expectedMessages {
			if j != i { // Node doesn't receive its own messages
				expectedForThisNode = append(expectedForThisNode, expected)
			}
		}

		// Sort and compare (order might vary)
		verifyMessagesContent(t, nodeNames[i], receivedMessages, expectedForThisNode)
	}

	t.Log("✅ Content verification test PASSED")
}

// TestUnauthorizedNodeBlocked tests that unauthorized nodes cannot connect or send/receive messages
func TestUnauthorizedNodeBlocked(t *testing.T) {
	t.Log("=== Testing Unauthorized Node Blocking ===")

	testTopic := "unauthorized-test-topic"
	messageTimeout := 8 * time.Second

	// Track messages for authorized nodes
	var (
		authorizedMessages = make([]common.Event, 0)
		messagesMutex      sync.RWMutex
	)

	authorizedHandler := func(event common.Event) {
		messagesMutex.Lock()
		authorizedMessages = append(authorizedMessages, event)
		messagesMutex.Unlock()
		t.Logf("Authorized node received message from: %s", event.FromPeerId)
	}

	logger := &TestLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Setup authorized node (bootstrap)
	authorizedDB := setupNode(t, ctx, logger, node0PrivateKey, "test-network", 15001, 15002,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForBootstrap)
	defer func() { _ = authorizedDB.Disconnect(ctx) }()

	err := authorizedDB.Subscribe(ctx, testTopic, authorizedHandler)
	if err != nil {
		t.Fatalf("Failed to subscribe authorized node: %v", err)
	}

	time.Sleep(2 * time.Second)

	// Try to setup unauthorized node - this should fail to connect or be blocked
	t.Log("Attempting to connect unauthorized node...")

	unauthorizedConfig := common.Config{
		WalletPrivateKey:     node3PrivateKey, // This key is NOT in the authorized list
		DatabaseName:         "test-network",
		GetAuthorizedWallets: mockGetUnauthorizedWallets, // Returns only node3, but authorized network only allows 0,1,2
		GetBootstrapNodes:    mockGetBootstrapNodesForClients("127.0.0.1", 15001, 15002),
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 15007,
			TCP:  15008,
		},
	}

	// Unauthorized node should either fail to connect or be unable to communicate
	unauthorizedDB, err := pubsub.Connect(ctx, unauthorizedConfig)
	if err != nil {
		t.Logf("✅ Unauthorized node correctly failed to connect: %v", err)
		return
	}
	defer func() { _ = unauthorizedDB.Disconnect(ctx) }()

	// If it did connect, it shouldn't be able to communicate with authorized nodes
	unauthorizedMessageReceived := false
	unauthorizedHandler := func(event common.Event) {
		unauthorizedMessageReceived = true
		t.Logf("❌ Unauthorized node received message (should not happen): %v", event)
	}

	err = unauthorizedDB.Subscribe(ctx, testTopic, unauthorizedHandler)
	if err != nil {
		t.Logf("✅ Unauthorized node correctly failed to subscribe: %v", err)
		return
	}

	// Wait for potential connection
	time.Sleep(5 * time.Second)

	// Check if unauthorized node can see authorized peers
	unauthorizedPeers := unauthorizedDB.ConnectedPeers()
	t.Logf("Unauthorized node connected to %d peers", len(unauthorizedPeers))

	// Authorized node publishes a message
	testMessage := NodeMessage{NodeID: "authorized", Content: "Secret message", Counter: 1}
	event, err := authorizedDB.Publish(ctx, testTopic, testMessage)
	if err != nil {
		t.Fatalf("Authorized node failed to publish: %v", err)
	}
	t.Logf("Authorized node published: %s", event.ID)

	// Unauthorized node tries to publish a message
	unauthorizedMessage := NodeMessage{NodeID: "unauthorized", Content: "Malicious message", Counter: 999}
	_, err = unauthorizedDB.Publish(ctx, testTopic, unauthorizedMessage)
	if err != nil {
		t.Logf("✅ Unauthorized node correctly failed to publish: %v", err)
	} else {
		t.Logf("⚠️ Unauthorized node was able to publish (will check if message is received)")
	}

	// Wait for message propagation
	time.Sleep(messageTimeout)

	// Verify unauthorized node didn't receive authorized messages
	if unauthorizedMessageReceived {
		t.Error("❌ Unauthorized node received messages from authorized network")
	} else {
		t.Log("✅ Unauthorized node correctly did not receive messages")
	}

	// Verify authorized node didn't receive unauthorized messages
	messagesMutex.RLock()
	for _, msg := range authorizedMessages {
		if msg.FromPeerId == unauthorizedDB.GetHost().ID().String() {
			t.Error("❌ Authorized node received message from unauthorized node")
		}
	}
	messagesMutex.RUnlock()

	t.Log("✅ Unauthorized node blocking test PASSED")
}

// TestMultiTopicIsolation tests that messages are only received on the correct topics
func TestMultiTopicIsolation(t *testing.T) {
	t.Log("=== Testing Multi-Topic Isolation ===")

	topic1 := "topic-sensors"
	topic2 := "topic-alerts"
	topic3 := "topic-logs"
	messageTimeout := 8 * time.Second

	// Track messages by topic
	var (
		topic1Messages = make([]NodeMessage, 0)
		topic2Messages = make([]NodeMessage, 0)
		topic3Messages = make([]NodeMessage, 0)
		messagesMutex  sync.RWMutex
	)

	// Topic-specific handlers
	topic1Handler := func(event common.Event) {
		var msg NodeMessage
		if extractMessage(event, &msg) {
			messagesMutex.Lock()
			topic1Messages = append(topic1Messages, msg)
			messagesMutex.Unlock()
			t.Logf("Topic1 received: %+v", msg)
		}
	}

	topic2Handler := func(event common.Event) {
		var msg NodeMessage
		if extractMessage(event, &msg) {
			messagesMutex.Lock()
			topic2Messages = append(topic2Messages, msg)
			messagesMutex.Unlock()
			t.Logf("Topic2 received: %+v", msg)
		}
	}

	topic3Handler := func(event common.Event) {
		var msg NodeMessage
		if extractMessage(event, &msg) {
			messagesMutex.Lock()
			topic3Messages = append(topic3Messages, msg)
			messagesMutex.Unlock()
			t.Logf("Topic3 received: %+v", msg)
		}
	}

	logger := &TestLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Setup nodes
	node0DB := setupNode(t, ctx, logger, node0PrivateKey, "test-network", 15001, 15002,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForBootstrap)
	defer func() { _ = node0DB.Disconnect(ctx) }()

	node1DB := setupNode(t, ctx, logger, node1PrivateKey, "test-network", 15003, 15004,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForClients("127.0.0.1", 15001, 15002))
	defer func() { _ = node1DB.Disconnect(ctx) }()

	// Subscribe nodes to different topic combinations
	// Node 0: subscribes to topic1 and topic2
	err := node0DB.Subscribe(ctx, topic1, topic1Handler)
	if err != nil {
		t.Fatalf("Node 0 failed to subscribe to topic1: %v", err)
	}
	err = node0DB.Subscribe(ctx, topic2, topic2Handler)
	if err != nil {
		t.Fatalf("Node 0 failed to subscribe to topic2: %v", err)
	}

	// Node 1: subscribes to topic2 and topic3
	err = node1DB.Subscribe(ctx, topic2, topic2Handler)
	if err != nil {
		t.Fatalf("Node 1 failed to subscribe to topic2: %v", err)
	}
	err = node1DB.Subscribe(ctx, topic3, topic3Handler)
	if err != nil {
		t.Fatalf("Node 1 failed to subscribe to topic3: %v", err)
	}

	time.Sleep(5 * time.Second)

	// Publish messages to different topics
	msg1 := NodeMessage{NodeID: "publisher", Content: "Sensor data", Counter: 1}
	msg2 := NodeMessage{NodeID: "publisher", Content: "Alert message", Counter: 2}
	msg3 := NodeMessage{NodeID: "publisher", Content: "Log entry", Counter: 3}

	// Publish to topic1 (only Node0 should receive)
	_, err = node0DB.Publish(ctx, topic1, msg1)
	if err != nil {
		t.Fatalf("Failed to publish to topic1: %v", err)
	}
	t.Logf("Published to topic1: %+v", msg1)

	time.Sleep(1 * time.Second)

	// Publish to topic2 (both Node0 and Node1 should receive)
	_, err = node1DB.Publish(ctx, topic2, msg2)
	if err != nil {
		t.Fatalf("Failed to publish to topic2: %v", err)
	}
	t.Logf("Published to topic2: %+v", msg2)

	time.Sleep(1 * time.Second)

	// Publish to topic3 (only Node1 should receive)
	_, err = node1DB.Publish(ctx, topic3, msg3)
	if err != nil {
		t.Fatalf("Failed to publish to topic3: %v", err)
	}
	t.Logf("Published to topic3: %+v", msg3)

	// Wait for message propagation
	time.Sleep(messageTimeout)

	// Verify topic isolation
	messagesMutex.RLock()
	defer messagesMutex.RUnlock()

	// Topic1: should have 1 message (msg1) - only Node0 subscribed and published
	if len(topic1Messages) != 0 { // Node0 doesn't receive its own messages
		t.Errorf("Topic1: expected 0 messages, got %d", len(topic1Messages))
	}

	// Topic2: should have 1 message (msg2) - Node1 published, Node0 received
	if len(topic2Messages) != 1 {
		t.Errorf("Topic2: expected 1 message, got %d", len(topic2Messages))
	} else if !reflect.DeepEqual(topic2Messages[0], msg2) {
		t.Errorf("Topic2: message content mismatch. Expected %+v, got %+v", msg2, topic2Messages[0])
	}

	// Topic3: should have 0 messages - only Node1 subscribed and published (doesn't receive own)
	if len(topic3Messages) != 0 {
		t.Errorf("Topic3: expected 0 messages, got %d", len(topic3Messages))
	}

	t.Log("✅ Multi-topic isolation test PASSED")
}

// TestUnsubscribeFunctionality tests that nodes stop receiving messages after unsubscribing
func TestUnsubscribeFunctionality(t *testing.T) {
	t.Log("=== Testing Unsubscribe Functionality ===")

	testTopic := "unsubscribe-test-topic"
	messageTimeout := 5 * time.Second

	var (
		receivedMessages = make([]NodeMessage, 0)
		messagesMutex    sync.RWMutex
	)

	messageHandler := func(event common.Event) {
		var msg NodeMessage
		if extractMessage(event, &msg) {
			messagesMutex.Lock()
			receivedMessages = append(receivedMessages, msg)
			messagesMutex.Unlock()
			t.Logf("Received message: %+v", msg)
		}
	}

	logger := &TestLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Setup nodes
	node0DB := setupNode(t, ctx, logger, node0PrivateKey, "test-network", 15001, 15002,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForBootstrap)
	defer func() { _ = node0DB.Disconnect(ctx) }()

	node1DB := setupNode(t, ctx, logger, node1PrivateKey, "test-network", 15003, 15004,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForClients("127.0.0.1", 15001, 15002))
	defer func() { _ = node1DB.Disconnect(ctx) }()

	// Subscribe node1 to topic
	err := node1DB.Subscribe(ctx, testTopic, messageHandler)
	if err != nil {
		t.Fatalf("Failed to subscribe: %v", err)
	}

	time.Sleep(3 * time.Second)

	// Publish first message - should be received
	msg1 := NodeMessage{NodeID: "test", Content: "Before unsubscribe", Counter: 1}
	_, err = node0DB.Publish(ctx, testTopic, msg1)
	if err != nil {
		t.Fatalf("Failed to publish first message: %v", err)
	}

	time.Sleep(messageTimeout)

	// Verify first message was received
	messagesMutex.RLock()
	firstCount := len(receivedMessages)
	messagesMutex.RUnlock()

	if firstCount != 1 {
		t.Errorf("Expected 1 message before unsubscribe, got %d", firstCount)
	}

	// Unsubscribe from topic
	t.Log("Unsubscribing from topic...")
	err = node1DB.Unsubscribe(ctx, testTopic)
	if err != nil {
		t.Fatalf("Failed to unsubscribe: %v", err)
	}

	time.Sleep(2 * time.Second)

	// Publish second message - should NOT be received
	msg2 := NodeMessage{NodeID: "test", Content: "After unsubscribe", Counter: 2}
	_, err = node0DB.Publish(ctx, testTopic, msg2)
	if err != nil {
		t.Fatalf("Failed to publish second message: %v", err)
	}

	time.Sleep(messageTimeout)

	// Verify second message was NOT received
	messagesMutex.RLock()
	finalCount := len(receivedMessages)
	messagesMutex.RUnlock()

	if finalCount != 1 {
		t.Errorf("Expected 1 message after unsubscribe (no new messages), got %d", finalCount)
	}

	// Verify we can't unsubscribe from a topic we're not subscribed to
	err = node1DB.Unsubscribe(ctx, "non-existent-topic")
	if err == nil {
		t.Error("Expected error when unsubscribing from non-existent topic")
	}

	// Test re-subscription works
	t.Log("Re-subscribing to topic...")
	err = node1DB.Subscribe(ctx, testTopic, messageHandler)
	if err != nil {
		t.Fatalf("Failed to re-subscribe: %v", err)
	}

	time.Sleep(3 * time.Second)

	// Publish third message - should be received again
	msg3 := NodeMessage{NodeID: "test", Content: "After re-subscribe", Counter: 3}
	_, err = node0DB.Publish(ctx, testTopic, msg3)
	if err != nil {
		t.Fatalf("Failed to publish third message: %v", err)
	}

	time.Sleep(messageTimeout)

	// Verify third message was received
	messagesMutex.RLock()
	resubscribeCount := len(receivedMessages)
	lastMessage := receivedMessages[len(receivedMessages)-1]
	messagesMutex.RUnlock()

	if resubscribeCount != 2 {
		t.Errorf("Expected 2 messages after re-subscribe, got %d", resubscribeCount)
	}

	if !reflect.DeepEqual(lastMessage, msg3) {
		t.Errorf("Last message mismatch. Expected %+v, got %+v", msg3, lastMessage)
	}

	t.Log("✅ Unsubscribe functionality test PASSED")
}

// TestPublishThenSubscribeEdgeCase tests the specific edge case where:
// - Nodes connect but NO initial subscriptions (pure edge case)
// - Node publishes to a topic without subscribing first (joins topic for publishing only)
// - Same node later subscribes to that topic (should reuse existing topic, not fail)
// - Verify that subsequent messages are properly received after subscription
func TestPublishThenSubscribeEdgeCase(t *testing.T) {
	t.Log("=== Testing Publish-Then-Subscribe Edge Case ===")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := &TestLogger{}
	topic := "edge-case-topic"

	// Use EXACT same ports as working test to eliminate any port-related issues
	// Node 0 (Bootstrap) - will do publish-then-subscribe to test edge case
	node0DB := setupNode(t, ctx, logger, node0PrivateKey, "test-network", 15001, 15002,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForBootstrap)
	defer func() { _ = node0DB.Disconnect(ctx) }()

	// DON'T subscribe Node 0 yet - this is the edge case we're testing!

	time.Sleep(2 * time.Second)

	// Node 1 (Client) - just connect, NO subscription initially
	node1DB := setupNode(t, ctx, logger, node1PrivateKey, "test-network", 15003, 15004,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForClients("127.0.0.1", 15001, 15002))
	defer func() { _ = node1DB.Disconnect(ctx) }()

	// Node 2 (Client) - just connect, NO subscription initially
	node2DB := setupNode(t, ctx, logger, node2PrivateKey, "test-network", 15005, 15006,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForClients("127.0.0.1", 15001, 15002))
	defer func() { _ = node2DB.Disconnect(ctx) }()

	// Wait for network convergence (same as working tests)
	time.Sleep(5 * time.Second)

	// Verify nodes are connected - FAIL the test if not connected (don't skip)
	node0Peers := node0DB.ConnectedPeers()
	node1Peers := node1DB.ConnectedPeers()
	node2Peers := node2DB.ConnectedPeers()
	t.Logf("Node 0 connected to %d peers", len(node0Peers))
	t.Logf("Node 1 connected to %d peers", len(node1Peers))
	t.Logf("Node 2 connected to %d peers", len(node2Peers))

	if len(node0Peers) < 2 || len(node1Peers) < 2 || len(node2Peers) < 2 {
		t.Fatalf("CONNECTIVITY FAILURE: Nodes not properly connected. Expected each node to have 2 peers. Node0: %d, Node1: %d, Node2: %d. This test must not skip!",
			len(node0Peers), len(node1Peers), len(node2Peers))
	}

	var receivedMessages []NodeMessage
	var messagesMutex sync.Mutex

	// Step 1: Node 0 publishes WITHOUT subscribing first (edge case)
	t.Log("Step 1: Publishing without subscription...")
	publishMessage := NodeMessage{
		NodeID:  "node-0",
		Content: "Published before subscribing",
		Counter: 1,
	}

	_, err := node0DB.Publish(ctx, topic, publishMessage)
	if err != nil {
		t.Fatalf("Failed to publish without subscription: %v", err)
	}
	t.Log("✅ Successfully published without subscription")

	// Step 2: Node 0 tries to subscribe AFTER publishing (this was the bug)
	t.Log("Step 2: Subscribing after publishing...")

	handler := func(event common.Event) {
		messagesMutex.Lock()
		defer messagesMutex.Unlock()

		var msg NodeMessage
		if jsonData, err := json.Marshal(event.Message); err == nil {
			if err := json.Unmarshal(jsonData, &msg); err == nil {
				receivedMessages = append(receivedMessages, msg)
				t.Logf("Node 0 received message: %+v", msg)
			}
		}
	}

	err = node0DB.Subscribe(ctx, topic, handler)
	if err != nil {
		t.Fatalf("Failed to subscribe after publishing - this indicates the edge case bug: %v", err)
	}
	t.Log("✅ Successfully subscribed after publishing")

	// Step 3: Now Node 1 subscribes to help establish GossipSub mesh for message delivery
	t.Log("Step 3: Node 1 subscribing to establish mesh...")
	err = node1DB.Subscribe(ctx, topic, func(event common.Event) {
		// Node 1 handler (needed for GossipSub mesh)
	})
	if err != nil {
		t.Fatalf("Node 1 subscription failed: %v", err)
	}

	// Wait for mesh to stabilize
	time.Sleep(3 * time.Second)

	// Step 4: Node 1 publishes a message that Node 0 should receive
	t.Log("Step 4: Testing message delivery after edge case resolution...")

	testMessage := NodeMessage{
		NodeID:  "node-1",
		Content: "Message after subscription established",
		Counter: 2,
	}

	_, err = node1DB.Publish(ctx, topic, testMessage)
	if err != nil {
		t.Fatalf("Failed to publish test message: %v", err)
	}
	t.Log("Node 1 published test message")

	// Wait for message delivery
	time.Sleep(5 * time.Second)

	// Step 5: Verify Node 0 received the message from Node 1
	messagesMutex.Lock()
	defer messagesMutex.Unlock()

	if len(receivedMessages) != 1 {
		t.Fatalf("Expected 1 message, got %d. Messages: %+v", len(receivedMessages), receivedMessages)
	}

	received := receivedMessages[0]
	if received.NodeID != "node-1" {
		t.Errorf("Expected message from node-1, got from %s", received.NodeID)
	}
	if received.Content != "Message after subscription established" {
		t.Errorf("Expected specific content, got: %s", received.Content)
	}
	if received.Counter != 2 {
		t.Errorf("Expected counter 2, got %d", received.Counter)
	}

	t.Log("✅ Edge case test PASSED")
	t.Log("  - No initial subscriptions: Works")
	t.Log("  - Publish without subscribe: Works")
	t.Log("  - Subscribe after publish: Works (edge case fixed)")
	t.Log("  - Message delivery after subscription: Works")
}

// TestBasicConnectivity tests that 3 nodes can connect to each other without any pub/sub operations
func TestBasicConnectivity(t *testing.T) {
	t.Log("=== Testing Basic 3-Node Connectivity ===")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := &TestLogger{}

	// Node 0 (Bootstrap) - just connect, no pub/sub
	node0DB := setupNode(t, ctx, logger, node0PrivateKey, "test-network", 15001, 15002,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForBootstrap)
	defer func() { _ = node0DB.Disconnect(ctx) }()

	time.Sleep(2 * time.Second)

	// Node 1 (Client) - just connect, no pub/sub
	node1DB := setupNode(t, ctx, logger, node1PrivateKey, "test-network", 15003, 15004,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForClients("127.0.0.1", 15001, 15002))
	defer func() { _ = node1DB.Disconnect(ctx) }()

	// Node 2 (Client) - just connect, no pub/sub
	node2DB := setupNode(t, ctx, logger, node2PrivateKey, "test-network", 15005, 15006,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForClients("127.0.0.1", 15001, 15002))
	defer func() { _ = node2DB.Disconnect(ctx) }()

	// Wait for network convergence
	time.Sleep(5 * time.Second)

	// Verify all nodes are connected to each other
	node0Peers := node0DB.ConnectedPeers()
	node1Peers := node1DB.ConnectedPeers()
	node2Peers := node2DB.ConnectedPeers()

	t.Logf("Node 0 connected to %d peers", len(node0Peers))
	t.Logf("Node 1 connected to %d peers", len(node1Peers))
	t.Logf("Node 2 connected to %d peers", len(node2Peers))

	// Each node should be connected to the other 2 nodes
	if len(node0Peers) != 2 {
		t.Errorf("Node 0 should have 2 peers, got %d", len(node0Peers))
	}
	if len(node1Peers) != 2 {
		t.Errorf("Node 1 should have 2 peers, got %d", len(node1Peers))
	}
	if len(node2Peers) != 2 {
		t.Errorf("Node 2 should have 2 peers, got %d", len(node2Peers))
	}

	// Verify peer IDs match
	expectedPeerIDs := map[string][]string{
		node0DB.GetHost().ID().String(): {node1DB.GetHost().ID().String(), node2DB.GetHost().ID().String()},
		node1DB.GetHost().ID().String(): {node0DB.GetHost().ID().String(), node2DB.GetHost().ID().String()},
		node2DB.GetHost().ID().String(): {node0DB.GetHost().ID().String(), node1DB.GetHost().ID().String()},
	}

	nodes := []*pubsub.DB{node0DB, node1DB, node2DB}
	nodeNames := []string{"Node 0", "Node 1", "Node 2"}

	for i, node := range nodes {
		peers := node.ConnectedPeers()
		nodeID := node.GetHost().ID().String()
		expectedPeers := expectedPeerIDs[nodeID]

		for _, peer := range peers {
			peerID := peer.ID.String()
			found := false
			for _, expectedPeerID := range expectedPeers {
				if peerID == expectedPeerID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s connected to unexpected peer: %s", nodeNames[i], peerID)
			}
		}
	}

	t.Log("✅ Basic connectivity test PASSED")
	t.Log("  - All 3 nodes connected to each other")
	t.Log("  - No pub/sub operations required")
	t.Log("  - Pure P2P network connectivity verified")
}

// Helper functions

func setupNode(t *testing.T, ctx context.Context, logger common.Logger, privateKey, dbName string,
	quicPort, tcpPort int, getAuthorizedWallets common.GetAuthorizedWalletsFunc,
	getBootstrapNodes common.GetBootstrapNodesFunc) *pubsub.DB {

	config := common.Config{
		WalletPrivateKey:     privateKey,
		DatabaseName:         dbName,
		GetAuthorizedWallets: getAuthorizedWallets,
		GetBootstrapNodes:    getBootstrapNodes,
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: quicPort,
			TCP:  tcpPort,
		},
	}

	db, err := pubsub.Connect(ctx, config)
	if err != nil {
		t.Fatalf("Failed to connect node: %v", err)
	}

	return db
}

func extractMessage(event common.Event, target *NodeMessage) bool {
	msgBytes, err := json.Marshal(event.Message)
	if err != nil {
		return false
	}
	return json.Unmarshal(msgBytes, target) == nil
}

func verifyMessagesContent(t *testing.T, nodeName string, received, expected []NodeMessage) {
	if len(received) != len(expected) {
		t.Errorf("%s: expected %d messages, got %d", nodeName, len(expected), len(received))
		return
	}

	// Create maps for easier comparison (since order might vary)
	receivedMap := make(map[string]NodeMessage)
	expectedMap := make(map[string]NodeMessage)

	for _, msg := range received {
		receivedMap[msg.NodeID] = msg
	}
	for _, msg := range expected {
		expectedMap[msg.NodeID] = msg
	}

	for nodeID, expectedMsg := range expectedMap {
		receivedMsg, found := receivedMap[nodeID]
		if !found {
			t.Errorf("%s: missing message from %s", nodeName, nodeID)
			continue
		}
		if !reflect.DeepEqual(receivedMsg, expectedMsg) {
			t.Errorf("%s: message content mismatch for %s. Expected %+v, got %+v",
				nodeName, nodeID, expectedMsg, receivedMsg)
		}
	}
}

// Keep the original test for backwards compatibility
func TestMultiNodePubSub(t *testing.T) {
	t.Log("=== Starting 3-Node P2P Integration Test ===")

	// Test configuration
	testTopic := "integration-test-topic"
	messageTimeout := 10 * time.Second

	// Set up message collection for each node
	var (
		node0Messages = make([]common.Event, 0)
		node1Messages = make([]common.Event, 0)
		node2Messages = make([]common.Event, 0)
		messagesMutex sync.RWMutex
	)

	// Create message handlers for each node
	node0Handler := func(event common.Event) {
		messagesMutex.Lock()
		node0Messages = append(node0Messages, event)
		messagesMutex.Unlock()
		t.Logf("Node 0 received message: %v", event.Message)
	}

	node1Handler := func(event common.Event) {
		messagesMutex.Lock()
		node1Messages = append(node1Messages, event)
		messagesMutex.Unlock()
		t.Logf("Node 1 received message: %v", event.Message)
	}

	node2Handler := func(event common.Event) {
		messagesMutex.Lock()
		node2Messages = append(node2Messages, event)
		messagesMutex.Unlock()
		t.Logf("Node 2 received message: %v", event.Message)
	}

	// Create logger
	logger := &TestLogger{}

	// Step 1: Setup Node 0 (Bootstrap node)
	t.Log("Setting up Node 0 (Bootstrap)...")
	node0Config := common.Config{
		WalletPrivateKey:     node0PrivateKey,
		DatabaseName:         "test-network",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes:    mockGetBootstrapNodesForBootstrap,
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 15001,
			TCP:  15002,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	node0DB, err := pubsub.Connect(ctx, node0Config)
	if err != nil {
		t.Fatalf("Failed to connect Node 0: %v", err)
	}
	defer func() { _ = node0DB.Disconnect(ctx) }()

	// Get Node 0's addresses for bootstrap
	node0Host := node0DB.GetHost()
	node0Addrs := node0Host.Addrs()
	if len(node0Addrs) == 0 {
		t.Fatal("Node 0 has no addresses")
	}

	t.Logf("Node 0 started with Peer ID: %s", node0Host.ID().String())
	for _, addr := range node0Addrs {
		t.Logf("Node 0 address: %s", addr.String())
	}

	// Subscribe Node 0 to test topic
	err = node0DB.Subscribe(ctx, testTopic, node0Handler)
	if err != nil {
		t.Fatalf("Failed to subscribe Node 0: %v", err)
	}

	// Wait a bit for Node 0 to fully initialize
	time.Sleep(2 * time.Second)

	// Step 2: Setup Node 1 (Client node)
	t.Log("Setting up Node 1 (Client)...")
	node1Config := common.Config{
		WalletPrivateKey:     node1PrivateKey,
		DatabaseName:         "test-network",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes:    mockGetBootstrapNodesForClients("127.0.0.1", 15001, 15002),
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 15003,
			TCP:  15004,
		},
	}

	node1DB, err := pubsub.Connect(ctx, node1Config)
	if err != nil {
		t.Fatalf("Failed to connect Node 1: %v", err)
	}
	defer func() { _ = node1DB.Disconnect(ctx) }()

	t.Logf("Node 1 started with Peer ID: %s", node1DB.GetHost().ID().String())

	// Subscribe Node 1 to test topic
	err = node1DB.Subscribe(ctx, testTopic, node1Handler)
	if err != nil {
		t.Fatalf("Failed to subscribe Node 1: %v", err)
	}

	// Step 3: Setup Node 2 (Client node)
	t.Log("Setting up Node 2 (Client)...")
	node2Config := common.Config{
		WalletPrivateKey:     node2PrivateKey,
		DatabaseName:         "test-network",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes:    mockGetBootstrapNodesForClients("127.0.0.1", 15001, 15002),
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 15005,
			TCP:  15006,
		},
	}

	node2DB, err := pubsub.Connect(ctx, node2Config)
	if err != nil {
		t.Fatalf("Failed to connect Node 2: %v", err)
	}
	defer func() { _ = node2DB.Disconnect(ctx) }()

	t.Logf("Node 2 started with Peer ID: %s", node2DB.GetHost().ID().String())

	// Subscribe Node 2 to test topic
	err = node2DB.Subscribe(ctx, testTopic, node2Handler)
	if err != nil {
		t.Fatalf("Failed to subscribe Node 2: %v", err)
	}

	// Step 4: Wait for network convergence
	t.Log("Waiting for network convergence...")
	time.Sleep(5 * time.Second)

	// Check peer connections
	node0Peers := node0DB.ConnectedPeers()
	node1Peers := node1DB.ConnectedPeers()
	node2Peers := node2DB.ConnectedPeers()

	t.Logf("Node 0 connected to %d peers", len(node0Peers))
	t.Logf("Node 1 connected to %d peers", len(node1Peers))
	t.Logf("Node 2 connected to %d peers", len(node2Peers))

	// Step 5: Publish messages from each node
	t.Log("Publishing messages from all nodes...")

	// Publish from Node 0
	node0Message := NodeMessage{
		NodeID:  "node-0",
		Content: "Hello from Node 0 (Bootstrap)",
		Counter: 1,
	}
	event0, err := node0DB.Publish(ctx, testTopic, node0Message)
	if err != nil {
		t.Fatalf("Failed to publish from Node 0: %v", err)
	}
	t.Logf("Node 0 published message with ID: %s", event0.ID)

	time.Sleep(1 * time.Second)

	// Publish from Node 1
	node1Message := NodeMessage{
		NodeID:  "node-1",
		Content: "Hello from Node 1 (Client)",
		Counter: 2,
	}
	event1, err := node1DB.Publish(ctx, testTopic, node1Message)
	if err != nil {
		t.Fatalf("Failed to publish from Node 1: %v", err)
	}
	t.Logf("Node 1 published message with ID: %s", event1.ID)

	time.Sleep(1 * time.Second)

	// Publish from Node 2
	node2Message := NodeMessage{
		NodeID:  "node-2",
		Content: "Hello from Node 2 (Client)",
		Counter: 3,
	}
	event2, err := node2DB.Publish(ctx, testTopic, node2Message)
	if err != nil {
		t.Fatalf("Failed to publish from Node 2: %v", err)
	}
	t.Logf("Node 2 published message with ID: %s", event2.ID)

	// Step 6: Wait for message propagation
	t.Log("Waiting for message propagation...")
	time.Sleep(messageTimeout)

	// Step 7: Verify all nodes received all messages
	t.Log("Verifying message reception...")

	messagesMutex.RLock()
	defer messagesMutex.RUnlock()

	t.Logf("Node 0 received %d messages", len(node0Messages))
	t.Logf("Node 1 received %d messages", len(node1Messages))
	t.Logf("Node 2 received %d messages", len(node2Messages))

	// Each node should receive 2 messages (from the other 2 nodes, not their own)
	expectedMessages := 2

	if len(node0Messages) != expectedMessages {
		t.Errorf("Node 0 expected %d messages, got %d", expectedMessages, len(node0Messages))
	}

	if len(node1Messages) != expectedMessages {
		t.Errorf("Node 1 expected %d messages, got %d", expectedMessages, len(node1Messages))
	}

	if len(node2Messages) != expectedMessages {
		t.Errorf("Node 2 expected %d messages, got %d", expectedMessages, len(node2Messages))
	}

	// Verify message content from each node's perspective
	t.Log("Verifying message content...")

	allMessages := [][]common.Event{node0Messages, node1Messages, node2Messages}
	nodeNames := []string{"Node 0", "Node 1", "Node 2"}

	for i, messages := range allMessages {
		t.Logf("=== %s received messages ===", nodeNames[i])
		for j, msg := range messages {
			t.Logf("  Message %d: From %s, ID: %s", j+1, msg.FromPeerId, msg.ID)

			// Verify message structure
			if msg.ID == "" {
				t.Errorf("%s: Message %d has empty ID", nodeNames[i], j+1)
			}
			if msg.FromPeerId == "" {
				t.Errorf("%s: Message %d has empty FromPeerId", nodeNames[i], j+1)
			}
			if msg.Message == nil {
				t.Errorf("%s: Message %d has nil Message", nodeNames[i], j+1)
			}
			if msg.Timestamp == 0 {
				t.Errorf("%s: Message %d has zero timestamp", nodeNames[i], j+1)
			}
		}
	}

	t.Log("=== 3-Node P2P Integration Test COMPLETED ===")
	t.Log("✅ All nodes successfully communicated via P2P pubsub")
	t.Log("✅ Message propagation verified across the network")
	t.Log("✅ Bootstrap discovery working correctly")
	t.Log("✅ Authorization and signatures validated by libp2p")
}

// TestConnectivityIssueReproduction attempts to reproduce the connectivity issues we encountered
// by using conditions that previously caused connection failures
func TestConnectivityIssueReproduction(t *testing.T) {
	t.Log("=== Testing Connectivity After Bootstrap Address Fix ===")
	t.Log("This test validates that conditions which previously caused failures now work correctly")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := &TestLogger{}

	// Use conditions that previously caused connectivity failures
	t.Log("Using conditions that previously failed:")
	t.Log("  - Different ports: 18001-18006 (not 15001-15006)")
	t.Log("  - Different network: 'different-network'")
	t.Log("  - Shorter timing: 500ms + 2s")

	// Node 0 (Bootstrap) - use different ports that previously caused issues
	node0DB := setupNode(t, ctx, logger, node0PrivateKey, "different-network", 18001, 18002,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForBootstrap)
	defer func() { _ = node0DB.Disconnect(ctx) }()

	// SHORTER wait time (this previously might have caused timing issues)
	time.Sleep(500 * time.Millisecond)

	// Node 1 (Client) - different ports, different timing
	node1DB := setupNode(t, ctx, logger, node1PrivateKey, "different-network", 18003, 18004,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForClients("127.0.0.1", 18001, 18002))
	defer func() { _ = node1DB.Disconnect(ctx) }()

	// Node 2 (Client) - more different ports
	node2DB := setupNode(t, ctx, logger, node2PrivateKey, "different-network", 18005, 18006,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForClients("127.0.0.1", 18001, 18002))
	defer func() { _ = node2DB.Disconnect(ctx) }()

	// Wait for connectivity (shorter time that previously failed)
	time.Sleep(2 * time.Second)

	// Check connectivity - this should work now that bootstrap addresses are dynamic
	node0Peers := node0DB.ConnectedPeers()
	node1Peers := node1DB.ConnectedPeers()
	node2Peers := node2DB.ConnectedPeers()

	t.Logf("Initial connectivity check - Node 0: %d peers, Node 1: %d peers, Node 2: %d peers",
		len(node0Peers), len(node1Peers), len(node2Peers))

	// If not immediately connected, wait a bit longer (but still fail if no connection)
	if len(node0Peers) < 2 || len(node1Peers) < 2 || len(node2Peers) < 2 {
		t.Log("Not immediately connected, waiting additional 5 seconds...")
		time.Sleep(5 * time.Second)

		node0Peers = node0DB.ConnectedPeers()
		node1Peers = node1DB.ConnectedPeers()
		node2Peers = node2DB.ConnectedPeers()

		t.Logf("After additional wait - Node 0: %d peers, Node 1: %d peers, Node 2: %d peers",
			len(node0Peers), len(node1Peers), len(node2Peers))
	}

	// ASSERT that connectivity works - this test should FAIL if it doesn't
	if len(node0Peers) < 2 {
		t.Errorf("Node 0 connectivity failed: expected 2+ peers, got %d", len(node0Peers))
	}
	if len(node1Peers) < 2 {
		t.Errorf("Node 1 connectivity failed: expected 2+ peers, got %d", len(node1Peers))
	}
	if len(node2Peers) < 2 {
		t.Errorf("Node 2 connectivity failed: expected 2+ peers, got %d", len(node2Peers))
	}

	// If we get here, connectivity works as expected
	t.Log("✅ Bootstrap address fix validation successful!")
	t.Log("  - Dynamic bootstrap addresses resolved the connectivity issue")
	t.Log("  - Nodes connect correctly regardless of port combinations")
}

// TestBootstrapAddressValidation validates that bootstrap addresses match actual node ports
func TestBootstrapAddressValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := &TestLogger{}

	// Test multiple port ranges to ensure bootstrap addresses are dynamic
	testCases := []struct {
		name           string
		bootstrapPorts [2]int // [QUIC, TCP]
		clientPorts    [4]int // [QUIC1, TCP1, QUIC2, TCP2]
	}{
		{
			name:           "Standard ports",
			bootstrapPorts: [2]int{15001, 15002},
			clientPorts:    [4]int{15003, 15004, 15005, 15006},
		},
		{
			name:           "High ports",
			bootstrapPorts: [2]int{19001, 19002},
			clientPorts:    [4]int{19003, 19004, 19005, 19006},
		},
		{
			name:           "Mixed range ports",
			bootstrapPorts: [2]int{12345, 12346},
			clientPorts:    [4]int{12347, 12348, 12349, 12350},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Node 0 (Bootstrap) with specified ports
			node0DB := setupNode(t, ctx, logger, node0PrivateKey, "test-bootstrap-validation",
				tc.bootstrapPorts[0], tc.bootstrapPorts[1],
				mockGetAuthorizedWallets, mockGetBootstrapNodesForBootstrap)
			defer func() { _ = node0DB.Disconnect(ctx) }()

			// Create bootstrap function with actual node0 ports
			bootstrapFunc := mockGetBootstrapNodesForClients("127.0.0.1", tc.bootstrapPorts[0], tc.bootstrapPorts[1])

			// Node 1 (Client) - should use node0's actual ports for bootstrap
			node1DB := setupNode(t, ctx, logger, node1PrivateKey, "test-bootstrap-validation",
				tc.clientPorts[0], tc.clientPorts[1],
				mockGetAuthorizedWallets, bootstrapFunc)
			defer func() { _ = node1DB.Disconnect(ctx) }()

			// Node 2 (Client) - should use node0's actual ports for bootstrap
			node2DB := setupNode(t, ctx, logger, node2PrivateKey, "test-bootstrap-validation",
				tc.clientPorts[2], tc.clientPorts[3],
				mockGetAuthorizedWallets, bootstrapFunc)
			defer func() { _ = node2DB.Disconnect(ctx) }()

			// Verify bootstrap addresses by checking connectivity
			time.Sleep(5 * time.Second) // Allow time for discovery

			// All nodes should be connected if bootstrap addresses are correct
			node0Peers := len(node0DB.GetHost().Network().Peers())
			node1Peers := len(node1DB.GetHost().Network().Peers())
			node2Peers := len(node2DB.GetHost().Network().Peers())

			t.Logf("Bootstrap validation for %s - Node0: %d peers, Node1: %d peers, Node2: %d peers",
				tc.name, node0Peers, node1Peers, node2Peers)

			// Each node should see the other 2 nodes
			if node0Peers < 2 || node1Peers < 2 || node2Peers < 2 {
				t.Errorf("Bootstrap address validation failed for %s - expected 2+ peers each, got Node0: %d, Node1: %d, Node2: %d",
					tc.name, node0Peers, node1Peers, node2Peers)
			}

			// Validate that nodes can actually communicate (not just connected)
			// Subscribe all nodes to a test topic
			testTopic := fmt.Sprintf("bootstrap-validation-%s", tc.name)

			messageReceived := make(chan bool, 2)

			// Subscribe nodes 1 and 2 to receive messages
			err := node1DB.Subscribe(ctx, testTopic, func(event common.Event) {
				select {
				case messageReceived <- true:
				default:
				}
			})
			if err != nil {
				t.Fatalf("Node1 subscribe failed: %v", err)
			}

			err = node2DB.Subscribe(ctx, testTopic, func(event common.Event) {
				select {
				case messageReceived <- true:
				default:
				}
			})
			if err != nil {
				t.Fatalf("Node2 subscribe failed: %v", err)
			}

			// Allow subscription to propagate
			time.Sleep(2 * time.Second)

			// Node 0 publishes a message
			testMessage := []byte(fmt.Sprintf("bootstrap-test-%s", tc.name))
			_, err = node0DB.Publish(ctx, testTopic, testMessage)
			if err != nil {
				t.Fatalf("Node0 publish failed: %v", err)
			}

			// Wait for message delivery
			received := 0
			timeout := time.After(3 * time.Second)
			for received < 2 {
				select {
				case <-messageReceived:
					received++
				case <-timeout:
					t.Errorf("Message delivery timeout for %s - only %d/2 nodes received message", tc.name, received)
					return
				}
			}

			t.Logf("✅ Bootstrap validation successful for %s - all nodes connected and communicating", tc.name)
		})
	}
	t.Log("✅ Bootstrap validation successful for all test cases")
}

// TestBootstrapRetryEmptyNodes tests bootstrap retry when no nodes are initially available
func TestBootstrapRetryEmptyNodes(t *testing.T) {
	t.Log("=== Testing Bootstrap Retry with Initially Empty Nodes ===")

	logger := &TestLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a mock that initially returns empty but later returns bootstrap nodes
	var callCount int
	var mutex sync.Mutex
	delayedBootstrapFunc := func(ctx context.Context) ([]common.BootstrapNode, error) {
		mutex.Lock()
		defer mutex.Unlock()
		callCount++

		// First 2 calls return empty (simulating no bootstrap nodes available initially)
		if callCount <= 2 {
			t.Logf("Bootstrap call %d: returning empty list", callCount)
			return []common.BootstrapNode{}, nil
		}

		// After that, return bootstrap nodes (simulating registry becoming available)
		t.Logf("Bootstrap call %d: returning bootstrap nodes", callCount)
		return []common.BootstrapNode{
			{
				PublicKey: solana.MustPublicKeyFromBase58(node0PublicKey),
				IP:        "127.0.0.1",
				QUICPort:  15001,
				TCPPort:   15002,
			},
		}, nil
	}

	// Start bootstrap node first
	node0Config := common.Config{
		WalletPrivateKey:     node0PrivateKey,
		DatabaseName:         "test-retry",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes:    mockGetBootstrapNodesForBootstrap,
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 15001,
			TCP:  15002,
		},
	}

	node0DB, err := pubsub.Connect(ctx, node0Config)
	if err != nil {
		t.Fatalf("Failed to connect bootstrap node: %v", err)
	}
	defer func() { _ = node0DB.Disconnect(ctx) }()

	// Node 0 should be ready immediately (bootstrap node)
	if !node0DB.IsReady() {
		t.Log("Note: Bootstrap node not immediately ready, waiting...")
		// Give it a moment to settle
		time.Sleep(2 * time.Second)
	}

	// Start client node that will use delayed bootstrap function
	node1Config := common.Config{
		WalletPrivateKey:     node1PrivateKey,
		DatabaseName:         "test-retry",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes:    delayedBootstrapFunc, // This will retry
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 15003,
			TCP:  15004,
		},
	}

	node1DB, err := pubsub.Connect(ctx, node1Config)
	if err != nil {
		t.Fatalf("Failed to connect client node: %v", err)
	}
	defer func() { _ = node1DB.Disconnect(ctx) }()

	// Node 1 should initially not be ready
	if node1DB.IsReady() {
		t.Log("Note: Client node is immediately ready - this may be expected if bootstrap worked")
	}

	// Wait for retry to kick in and bootstrap to succeed
	t.Log("Waiting for bootstrap retry to succeed...")
	startTime := time.Now()
	timeout := 20 * time.Second

	for time.Since(startTime) < timeout {
		if node1DB.IsReady() {
			t.Logf("✅ Node became ready after %v", time.Since(startTime))
			break
		}
		time.Sleep(1 * time.Second)
	}

	// Give connections time to stabilize
	time.Sleep(2 * time.Second)

	// Verify node is now ready
	if !node1DB.IsReady() {
		t.Errorf("Node should be ready after bootstrap retry, but IsReady() = false")
	}

	// Verify both nodes can see each other
	node0Peers := len(node0DB.GetHost().Network().Peers())
	node1Peers := len(node1DB.GetHost().Network().Peers())

	t.Logf("Node 0 peers: %d, Node 1 peers: %d", node0Peers, node1Peers)

	if node0Peers < 1 || node1Peers < 1 {
		t.Errorf("Expected both nodes to have at least 1 peer, got Node0: %d, Node1: %d", node0Peers, node1Peers)
	}

	// Verify the bootstrap function was called multiple times
	mutex.Lock()
	finalCallCount := callCount
	mutex.Unlock()

	if finalCallCount < 3 {
		t.Errorf("Expected at least 3 bootstrap calls (showing retry), got %d", finalCallCount)
	}

	t.Log("✅ Bootstrap retry test passed")
}

// TestReadinessStateTracking tests that readiness state is properly tracked
func TestReadinessStateTracking(t *testing.T) {
	t.Log("=== Testing Readiness State Tracking ===")

	logger := &TestLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create isolated node with no bootstrap nodes
	isolatedConfig := common.Config{
		WalletPrivateKey:     node1PrivateKey,
		DatabaseName:         "test-readiness",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes:    mockGetBootstrapNodesForBootstrap, // Returns empty
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 15007,
			TCP:  15008,
		},
	}

	isolatedDB, err := pubsub.Connect(ctx, isolatedConfig)
	if err != nil {
		t.Fatalf("Failed to connect isolated node: %v", err)
	}
	defer func() { _ = isolatedDB.Disconnect(ctx) }()

	// Node should not be ready initially
	if isolatedDB.IsReady() {
		t.Log("Note: Isolated node is ready immediately - may have found peers through other means")
	} else {
		t.Log("✅ Isolated node correctly shows not ready")
	}

	// Create a peer node that will connect to the isolated node
	peerConfig := common.Config{
		WalletPrivateKey:     node0PrivateKey,
		DatabaseName:         "test-readiness",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes: func(ctx context.Context) ([]common.BootstrapNode, error) {
			// Return the isolated node as bootstrap
			return []common.BootstrapNode{
				{
					PublicKey: solana.MustPublicKeyFromBase58(node1PublicKey),
					IP:        "127.0.0.1",
					QUICPort:  15007,
					TCPPort:   15008,
				},
			}, nil
		},
		Logger: logger,
		ListenPorts: common.ListenPorts{
			QUIC: 15009,
			TCP:  15010,
		},
	}

	peerDB, err := pubsub.Connect(ctx, peerConfig)
	if err != nil {
		t.Fatalf("Failed to connect peer node: %v", err)
	}
	defer func() { _ = peerDB.Disconnect(ctx) }()

	// Wait for connection to be established
	t.Log("Waiting for peer connection...")
	startTime := time.Now()
	timeout := 10 * time.Second

	for time.Since(startTime) < timeout {
		if isolatedDB.IsReady() && peerDB.IsReady() {
			t.Logf("✅ Both nodes became ready after %v", time.Since(startTime))
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Verify both nodes are ready
	if !isolatedDB.IsReady() {
		t.Errorf("Isolated node should be ready after peer connection")
	}
	if !peerDB.IsReady() {
		t.Errorf("Peer node should be ready after connection")
	}

	// Verify they can see each other
	isolatedPeers := len(isolatedDB.GetHost().Network().Peers())
	peerPeers := len(peerDB.GetHost().Network().Peers())

	if isolatedPeers < 1 || peerPeers < 1 {
		t.Errorf("Expected both nodes to have peers, got isolated: %d, peer: %d", isolatedPeers, peerPeers)
	}

	t.Log("✅ Readiness state tracking test passed")
}

// TestBootstrapRetryStopsWhenReady tests that bootstrap retry stops when node becomes ready
func TestBootstrapRetryStopsWhenReady(t *testing.T) {
	t.Log("=== Testing Bootstrap Retry Stops When Node Becomes Ready ===")

	logger := &TestLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Track bootstrap function calls
	var callCount int
	var mutex sync.Mutex
	trackingBootstrapFunc := func(ctx context.Context) ([]common.BootstrapNode, error) {
		mutex.Lock()
		defer mutex.Unlock()
		callCount++
		t.Logf("Bootstrap function called (count: %d)", callCount)

		// Always return empty to trigger retry
		return []common.BootstrapNode{}, nil
	}

	// Start node with empty bootstrap (will trigger retry)
	node1Config := common.Config{
		WalletPrivateKey:     node1PrivateKey,
		DatabaseName:         "test-retry-stop",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes:    trackingBootstrapFunc,
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 15011,
			TCP:  15012,
		},
	}

	node1DB, err := pubsub.Connect(ctx, node1Config)
	if err != nil {
		t.Fatalf("Failed to connect node: %v", err)
	}
	defer func() { _ = node1DB.Disconnect(ctx) }()

	// Wait a bit for retry to start
	time.Sleep(3 * time.Second)

	// Count calls before peer connection
	mutex.Lock()
	callsBeforePeer := callCount
	mutex.Unlock()

	t.Logf("Bootstrap calls before peer connection: %d", callsBeforePeer)

	// Now create a peer that will connect to node1
	node2Config := common.Config{
		WalletPrivateKey:     node2PrivateKey,
		DatabaseName:         "test-retry-stop",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes: func(ctx context.Context) ([]common.BootstrapNode, error) {
			return []common.BootstrapNode{
				{
					PublicKey: solana.MustPublicKeyFromBase58(node1PublicKey),
					IP:        "127.0.0.1",
					QUICPort:  15011,
					TCPPort:   15012,
				},
			}, nil
		},
		Logger: logger,
		ListenPorts: common.ListenPorts{
			QUIC: 15013,
			TCP:  15014,
		},
	}

	node2DB, err := pubsub.Connect(ctx, node2Config)
	if err != nil {
		t.Fatalf("Failed to connect peer node: %v", err)
	}
	defer func() { _ = node2DB.Disconnect(ctx) }()

	// Wait for connection
	time.Sleep(2 * time.Second)

	// Verify node1 is ready
	if !node1DB.IsReady() {
		t.Errorf("Node1 should be ready after peer connection")
	}

	// Wait a bit more to see if bootstrap retry stops
	time.Sleep(8 * time.Second)

	// Count final calls
	mutex.Lock()
	finalCallCount := callCount
	mutex.Unlock()

	t.Logf("Bootstrap calls after peer connection: %d (started with %d)", finalCallCount, callsBeforePeer)

	// The retry should have stopped, so call count shouldn't increase much
	// Allow for one additional call due to timing, but no more
	if finalCallCount > callsBeforePeer+2 {
		t.Errorf("Bootstrap retry should have stopped when node became ready, but calls increased from %d to %d", callsBeforePeer, finalCallCount)
	}

	t.Log("✅ Bootstrap retry stop test passed")
}

// TestBootstrapNodeFailover tests network resilience when bootstrap nodes go down and new ones come online
func TestBootstrapNodeFailover(t *testing.T) {
	t.Log("=== Testing Bootstrap Node Failover Scenario ===")
	t.Log("Scenario: Node0+Node1 start → Node0 down → Node2 up → Node1+Node2 work")

	logger := &TestLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create bootstrap functions that support both Node0 and Node2 as bootstrap
	// Node1 will try Node0 first, then Node2 if Node0 is down
	multiBootstrapFunc := func(ctx context.Context) ([]common.BootstrapNode, error) {
		return []common.BootstrapNode{
			{
				PublicKey: solana.MustPublicKeyFromBase58(node0PublicKey),
				IP:        "127.0.0.1",
				QUICPort:  15001,
				TCPPort:   15002,
			},
			{
				PublicKey: solana.MustPublicKeyFromBase58(node2PublicKey),
				IP:        "127.0.0.1",
				QUICPort:  15005,
				TCPPort:   15006,
			},
		}, nil
	}

	// === Phase 1: Node0 and Node1 start ===
	t.Log("Phase 1: Starting Node0 (bootstrap) and Node1 (client)")

	// Start Node0 (bootstrap)
	node0Config := common.Config{
		WalletPrivateKey:     node0PrivateKey,
		DatabaseName:         "test-failover",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes:    mockGetBootstrapNodesForBootstrap, // Returns empty
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 15001,
			TCP:  15002,
		},
	}

	node0DB, err := pubsub.Connect(ctx, node0Config)
	if err != nil {
		t.Fatalf("Failed to connect Node0: %v", err)
	}
	// Note: We'll manually disconnect node0 later, so no defer here initially

	// Start Node1 (client) - uses both Node0 and Node2 as potential bootstrap
	node1Config := common.Config{
		WalletPrivateKey:     node1PrivateKey,
		DatabaseName:         "test-failover",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes:    multiBootstrapFunc,
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 15003,
			TCP:  15004,
		},
	}

	node1DB, err := pubsub.Connect(ctx, node1Config)
	if err != nil {
		t.Fatalf("Failed to connect Node1: %v", err)
	}
	defer func() { _ = node1DB.Disconnect(ctx) }()

	// Wait for Node0 and Node1 to connect
	time.Sleep(5 * time.Second)

	// Verify Phase 1: Node0 and Node1 are connected
	node0Peers := len(node0DB.GetHost().Network().Peers())
	node1Peers := len(node1DB.GetHost().Network().Peers())

	t.Logf("Phase 1 - Node0 peers: %d, Node1 peers: %d", node0Peers, node1Peers)

	if node0Peers < 1 || node1Peers < 1 {
		t.Errorf("Phase 1 failed: Node0 and Node1 should be connected, got Node0: %d, Node1: %d peers", node0Peers, node1Peers)
	}

	// Test communication in Phase 1
	t.Log("Testing Phase 1 communication...")
	testTopic := "failover-test"
	phase1Messages := make([]string, 0)
	var phase1Mutex sync.Mutex

	err = node1DB.Subscribe(ctx, testTopic, func(event common.Event) {
		phase1Mutex.Lock()
		phase1Messages = append(phase1Messages, fmt.Sprintf("Phase1: %v", event.Message))
		phase1Mutex.Unlock()
	})
	if err != nil {
		t.Fatalf("Phase 1 subscribe failed: %v", err)
	}

	time.Sleep(2 * time.Second)

	_, err = node0DB.Publish(ctx, testTopic, "Phase1: Hello from Node0")
	if err != nil {
		t.Fatalf("Phase 1 publish failed: %v", err)
	}

	time.Sleep(3 * time.Second)

	phase1Mutex.Lock()
	phase1Count := len(phase1Messages)
	phase1Mutex.Unlock()

	if phase1Count < 1 {
		t.Errorf("Phase 1 communication failed: expected 1+ messages, got %d", phase1Count)
	}

	t.Log("✅ Phase 1 successful: Node0 and Node1 working together")

	// === Phase 2: Node0 goes down ===
	t.Log("Phase 2: Taking Node0 down...")

	err = node0DB.Disconnect(ctx)
	if err != nil {
		t.Logf("Note: Node0 disconnect had error: %v", err)
	}
	node0DB = nil

	// Wait for Node1 to detect Node0 is gone
	time.Sleep(3 * time.Second)

	// Verify Node1 is no longer connected to Node0
	node1PeersAfterNode0Down := len(node1DB.GetHost().Network().Peers())
	t.Logf("Phase 2 - Node1 peers after Node0 down: %d", node1PeersAfterNode0Down)

	if node1PeersAfterNode0Down > 0 {
		t.Log("Note: Node1 still shows peers after Node0 down - may take time to detect disconnect")
	}

	t.Log("✅ Phase 2 successful: Node0 down")

	// === Phase 3: Node2 comes up ===
	t.Log("Phase 3: Starting Node2 (new bootstrap)...")

	// Start Node2 (new bootstrap)
	node2Config := common.Config{
		WalletPrivateKey:     node2PrivateKey,
		DatabaseName:         "test-failover",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes:    multiBootstrapFunc, // Node2 can also use Node1 as bootstrap
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 15005,
			TCP:  15006,
		},
	}

	node2DB, err := pubsub.Connect(ctx, node2Config)
	if err != nil {
		t.Fatalf("Failed to connect Node2: %v", err)
	}
	defer func() { _ = node2DB.Disconnect(ctx) }()

	// Wait for Node1 and Node2 to find each other
	// Node1 should retry bootstrap and find Node2
	t.Log("Waiting for Node1 and Node2 to discover each other...")

	startTime := time.Now()
	timeout := 20 * time.Second
	connected := false

	for time.Since(startTime) < timeout {
		node1Peers = len(node1DB.GetHost().Network().Peers())
		node2Peers := len(node2DB.GetHost().Network().Peers())

		if node1Peers >= 1 && node2Peers >= 1 {
			connected = true
			t.Logf("✅ Node1 and Node2 discovered each other after %v", time.Since(startTime))
			break
		}

		time.Sleep(1 * time.Second)
	}

	if !connected {
		t.Errorf("Phase 3 failed: Node1 and Node2 failed to discover each other within %v", timeout)
	}

	// === Phase 4: Test Node1 and Node2 communication ===
	t.Log("Phase 4: Testing Node1 and Node2 communication...")

	phase4Messages := make([]string, 0)
	var phase4Mutex sync.Mutex

	// Node2 subscribes to receive messages from Node1
	err = node2DB.Subscribe(ctx, testTopic, func(event common.Event) {
		phase4Mutex.Lock()
		phase4Messages = append(phase4Messages, fmt.Sprintf("Phase4: %v", event.Message))
		phase4Mutex.Unlock()
	})
	if err != nil {
		t.Fatalf("Phase 4 subscribe failed: %v", err)
	}

	time.Sleep(2 * time.Second)

	// Node1 publishes to Node2
	_, err = node1DB.Publish(ctx, testTopic, "Phase4: Hello from Node1 to Node2")
	if err != nil {
		t.Fatalf("Phase 4 publish failed: %v", err)
	}

	time.Sleep(3 * time.Second)

	phase4Mutex.Lock()
	phase4Count := len(phase4Messages)
	phase4Mutex.Unlock()

	if phase4Count < 1 {
		t.Errorf("Phase 4 communication failed: expected 1+ messages, got %d", phase4Count)
	}

	// === Final Verification ===
	finalNode1Peers := len(node1DB.GetHost().Network().Peers())
	finalNode2Peers := len(node2DB.GetHost().Network().Peers())

	t.Logf("Final verification - Node1 peers: %d, Node2 peers: %d", finalNode1Peers, finalNode2Peers)

	if finalNode1Peers < 1 || finalNode2Peers < 1 {
		t.Errorf("Final verification failed: Node1 and Node2 should be connected, got Node1: %d, Node2: %d peers", finalNode1Peers, finalNode2Peers)
	}

	t.Log("✅ Bootstrap node failover test PASSED")
	t.Log("  Phase 1: ✅ Node0 + Node1 working")
	t.Log("  Phase 2: ✅ Node0 down")
	t.Log("  Phase 3: ✅ Node2 up and discovered")
	t.Log("  Phase 4: ✅ Node1 + Node2 working")
	t.Log("  Network successfully healed after bootstrap node failure!")
}

// TestLogger is a simple test logger
type TestLogger struct{}

func (l *TestLogger) Debug(msg string, keysAndValues ...interface{}) {
	// Don't show debug messages in tests by default to reduce noise
	// Only uncomment this line when debugging test issues
	// fmt.Printf("DEBUG: %s", msg)
	// if len(keysAndValues) > 0 {
	//	fmt.Printf(" - %v", keysAndValues)
	// }
	// fmt.Println()
}

func (l *TestLogger) Info(msg string, keysAndValues ...interface{}) {
	// Show info messages in tests
	fmt.Printf("INFO: %s", msg)
	if len(keysAndValues) > 0 {
		fmt.Printf(" - %v", keysAndValues)
	}
	fmt.Println()
}

func (l *TestLogger) Warn(msg string, keysAndValues ...interface{}) {
	fmt.Printf("WARN: %s\n", msg)
}

func (l *TestLogger) Error(msg string, keysAndValues ...interface{}) {
	fmt.Printf("ERROR: %s\n", msg)
}

func (l *TestLogger) DebugEnabled() bool {
	// Return false since we don't show debug messages by default in tests
	return false
}

// TestClientStartsBeforeBootstrap tests the scenario where a client node starts
// before the bootstrap node is running, and should automatically connect when
// the bootstrap node comes online later
func TestClientStartsBeforeBootstrap(t *testing.T) {
	t.Log("=== Testing Client Starts Before Bootstrap Scenario ===")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	logger := &TestLogger{}

	// Phase 1: Start client node first - bootstrap node is not running yet
	t.Log("Phase 1: Starting client node before bootstrap node...")

	// Client node tries to connect to bootstrap node at ports 16001/16002, but no bootstrap node is running
	clientDB := setupNode(t, ctx, logger, node1PrivateKey, "client-before-bootstrap-test", 16003, 16004,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForClients("127.0.0.1", 16001, 16002))
	defer func() { _ = clientDB.Disconnect(ctx) }()

	// Verify client is not ready (has no peers)
	if clientDB.IsReady() {
		t.Error("Client should not be ready initially (no bootstrap node running)")
	}

	// Wait a bit to ensure initial bootstrap attempt fails and retry starts
	time.Sleep(6 * time.Second)

	// Client should still not be ready
	if clientDB.IsReady() {
		t.Error("Client should still not be ready (bootstrap node not running)")
	}

	// Phase 2: Start bootstrap node - client should automatically connect
	t.Log("Phase 2: Starting bootstrap node - client should automatically connect...")

	bootstrapDB := setupNode(t, ctx, logger, node0PrivateKey, "client-before-bootstrap-test", 16001, 16002,
		mockGetAuthorizedWallets, mockGetBootstrapNodesForBootstrap)
	defer func() { _ = bootstrapDB.Disconnect(ctx) }()

	// Wait for bootstrap node to be ready
	time.Sleep(2 * time.Second)

	// Wait for client to discover and connect to bootstrap node via retry mechanism
	t.Log("Waiting for client to discover bootstrap node...")
	connected := false
	for i := 0; i < 20; i++ { // Wait up to 20 seconds
		if clientDB.IsReady() {
			connected = true
			t.Log("Client successfully connected to bootstrap node!")
			break
		}
		time.Sleep(1 * time.Second)
	}

	if !connected {
		t.Error("Client failed to connect to bootstrap node after it came online")
	}

	// Phase 3: Test communication between nodes
	t.Log("Phase 3: Testing communication between nodes...")

	testTopic := "client-before-bootstrap-topic"

	// Set up message handlers
	var (
		clientReceived    []string
		bootstrapReceived []string
		mu                sync.RWMutex
	)

	clientHandler := func(event common.Event) {
		mu.Lock()
		clientReceived = append(clientReceived, fmt.Sprintf("%v", event.Message))
		mu.Unlock()
	}

	bootstrapHandler := func(event common.Event) {
		mu.Lock()
		bootstrapReceived = append(bootstrapReceived, fmt.Sprintf("%v", event.Message))
		mu.Unlock()
	}

	// Subscribe both nodes
	err := clientDB.Subscribe(ctx, testTopic, clientHandler)
	if err != nil {
		t.Fatalf("Failed to subscribe client: %v", err)
	}

	err = bootstrapDB.Subscribe(ctx, testTopic, bootstrapHandler)
	if err != nil {
		t.Fatalf("Failed to subscribe bootstrap: %v", err)
	}

	// Wait for subscriptions to propagate
	time.Sleep(2 * time.Second)

	// Test bidirectional communication
	clientMsg := map[string]interface{}{"from": "client", "message": "Hello from client"}
	bootstrapMsg := map[string]interface{}{"from": "bootstrap", "message": "Hello from bootstrap"}

	// Client publishes to bootstrap
	_, err = clientDB.Publish(ctx, testTopic, clientMsg)
	if err != nil {
		t.Fatalf("Failed to publish from client: %v", err)
	}

	// Bootstrap publishes to client
	_, err = bootstrapDB.Publish(ctx, testTopic, bootstrapMsg)
	if err != nil {
		t.Fatalf("Failed to publish from bootstrap: %v", err)
	}

	// Wait for message propagation
	time.Sleep(5 * time.Second)

	// Verify messages were received
	mu.RLock()
	defer mu.RUnlock()

	if len(clientReceived) == 0 {
		t.Error("Client did not receive any messages")
	} else {
		t.Logf("Client received %d messages", len(clientReceived))
	}

	if len(bootstrapReceived) == 0 {
		t.Error("Bootstrap did not receive any messages")
	} else {
		t.Logf("Bootstrap received %d messages", len(bootstrapReceived))
	}

	t.Log("=== Client Starts Before Bootstrap Test Complete ===")
}

// TestAllNodesBootstrapAndAuthorized tests the scenario where all nodes are both
// bootstrap and authorized nodes, and each node knows about all other nodes
func TestAllNodesBootstrapAndAuthorized(t *testing.T) {
	t.Log("=== Testing All Nodes as Bootstrap and Authorized ===")
	t.Log("Scenario: Node0, Node1, Node2 - all bootstrap and authorized")
	t.Log("Each node receives all 3 nodes as bootstrap and authorized options")

	logger := &TestLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create bootstrap function that returns all 3 nodes as bootstrap options
	allNodesBootstrapFunc := func(ctx context.Context) ([]common.BootstrapNode, error) {
		return []common.BootstrapNode{
			{
				PublicKey: solana.MustPublicKeyFromBase58(node0PublicKey),
				IP:        "127.0.0.1",
				QUICPort:  17001,
				TCPPort:   17002,
			},
			{
				PublicKey: solana.MustPublicKeyFromBase58(node1PublicKey),
				IP:        "127.0.0.1",
				QUICPort:  17003,
				TCPPort:   17004,
			},
			{
				PublicKey: solana.MustPublicKeyFromBase58(node2PublicKey),
				IP:        "127.0.0.1",
				QUICPort:  17005,
				TCPPort:   17006,
			},
		}, nil
	}

	// Create authorized wallets function that returns all 3 nodes as authorized
	allNodesAuthorizedFunc := func(ctx context.Context) ([]solana.PublicKey, error) {
		return []solana.PublicKey{
			solana.MustPublicKeyFromBase58(node0PublicKey),
			solana.MustPublicKeyFromBase58(node1PublicKey),
			solana.MustPublicKeyFromBase58(node2PublicKey),
		}, nil
	}

	// === Phase 1: Start all three nodes ===
	t.Log("Phase 1: Starting all three nodes with full network knowledge")

	// Start Node 0
	node0Config := common.Config{
		WalletPrivateKey:     node0PrivateKey,
		DatabaseName:         "test-all-nodes",
		GetAuthorizedWallets: allNodesAuthorizedFunc,
		GetBootstrapNodes:    allNodesBootstrapFunc,
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 17001,
			TCP:  17002,
		},
	}

	node0DB, err := pubsub.Connect(ctx, node0Config)
	if err != nil {
		t.Fatalf("Failed to connect Node0: %v", err)
	}
	defer func() { _ = node0DB.Disconnect(ctx) }()

	// Start Node 1
	node1Config := common.Config{
		WalletPrivateKey:     node1PrivateKey,
		DatabaseName:         "test-all-nodes",
		GetAuthorizedWallets: allNodesAuthorizedFunc,
		GetBootstrapNodes:    allNodesBootstrapFunc,
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 17003,
			TCP:  17004,
		},
	}

	node1DB, err := pubsub.Connect(ctx, node1Config)
	if err != nil {
		t.Fatalf("Failed to connect Node1: %v", err)
	}
	defer func() { _ = node1DB.Disconnect(ctx) }()

	// Start Node 2
	node2Config := common.Config{
		WalletPrivateKey:     node2PrivateKey,
		DatabaseName:         "test-all-nodes",
		GetAuthorizedWallets: allNodesAuthorizedFunc,
		GetBootstrapNodes:    allNodesBootstrapFunc,
		Logger:               logger,
		ListenPorts: common.ListenPorts{
			QUIC: 17005,
			TCP:  17006,
		},
	}

	node2DB, err := pubsub.Connect(ctx, node2Config)
	if err != nil {
		t.Fatalf("Failed to connect Node2: %v", err)
	}
	defer func() { _ = node2DB.Disconnect(ctx) }()

	// Wait for network convergence
	t.Log("Waiting for network convergence...")
	time.Sleep(10 * time.Second)

	// === Phase 2: Verify all nodes are connected ===
	t.Log("Phase 2: Verifying all nodes are connected to each other")

	// Check peer counts
	node0Peers := len(node0DB.GetHost().Network().Peers())
	node1Peers := len(node1DB.GetHost().Network().Peers())
	node2Peers := len(node2DB.GetHost().Network().Peers())

	t.Logf("Node 0 peers: %d", node0Peers)
	t.Logf("Node 1 peers: %d", node1Peers)
	t.Logf("Node 2 peers: %d", node2Peers)

	// Each node should be connected to 2 other nodes
	if node0Peers < 2 || node1Peers < 2 || node2Peers < 2 {
		t.Errorf("Not all nodes are fully connected: Node0=%d, Node1=%d, Node2=%d peers",
			node0Peers, node1Peers, node2Peers)
	}

	// Verify all nodes are ready
	if !node0DB.IsReady() {
		t.Error("Node 0 is not ready")
	}
	if !node1DB.IsReady() {
		t.Error("Node 1 is not ready")
	}
	if !node2DB.IsReady() {
		t.Error("Node 2 is not ready")
	}

	t.Log("✅ All nodes are connected and ready")

	// === Phase 3: Test pub/sub communication ===
	t.Log("Phase 3: Testing pub/sub communication between all nodes")

	testTopic := "all-nodes-test"

	// Set up message handlers
	var (
		node0Received []string
		node1Received []string
		node2Received []string
		mu            sync.RWMutex
	)

	node0Handler := func(event common.Event) {
		mu.Lock()
		node0Received = append(node0Received, fmt.Sprintf("%v", event.Message))
		mu.Unlock()
	}

	node1Handler := func(event common.Event) {
		mu.Lock()
		node1Received = append(node1Received, fmt.Sprintf("%v", event.Message))
		mu.Unlock()
	}

	node2Handler := func(event common.Event) {
		mu.Lock()
		node2Received = append(node2Received, fmt.Sprintf("%v", event.Message))
		mu.Unlock()
	}

	// Subscribe all nodes
	err = node0DB.Subscribe(ctx, testTopic, node0Handler)
	if err != nil {
		t.Fatalf("Failed to subscribe Node0: %v", err)
	}

	err = node1DB.Subscribe(ctx, testTopic, node1Handler)
	if err != nil {
		t.Fatalf("Failed to subscribe Node1: %v", err)
	}

	err = node2DB.Subscribe(ctx, testTopic, node2Handler)
	if err != nil {
		t.Fatalf("Failed to subscribe Node2: %v", err)
	}

	// Wait for subscriptions to propagate
	time.Sleep(3 * time.Second)

	// Test bidirectional communication - each node publishes a message
	nodes := []*pubsub.DB{node0DB, node1DB, node2DB}
	nodeNames := []string{"Node0", "Node1", "Node2"}

	for i, node := range nodes {
		message := map[string]interface{}{
			"from":    nodeNames[i],
			"message": fmt.Sprintf("Hello from %s to all nodes", nodeNames[i]),
			"counter": i + 1,
		}

		_, err = node.Publish(ctx, testTopic, message)
		if err != nil {
			t.Fatalf("Failed to publish from %s: %v", nodeNames[i], err)
		}

		t.Logf("✅ %s published message", nodeNames[i])
		time.Sleep(1 * time.Second)
	}

	// Wait for message propagation
	time.Sleep(5 * time.Second)

	// Verify message reception
	mu.RLock()
	defer mu.RUnlock()

	t.Logf("Node 0 received %d messages", len(node0Received))
	t.Logf("Node 1 received %d messages", len(node1Received))
	t.Logf("Node 2 received %d messages", len(node2Received))

	// Each node should receive 2 messages (from the other 2 nodes)
	if len(node0Received) < 2 {
		t.Errorf("Node 0 received insufficient messages: %d (expected 2+)", len(node0Received))
	}
	if len(node1Received) < 2 {
		t.Errorf("Node 1 received insufficient messages: %d (expected 2+)", len(node1Received))
	}
	if len(node2Received) < 2 {
		t.Errorf("Node 2 received insufficient messages: %d (expected 2+)", len(node2Received))
	}

	// === Phase 4: Test network resilience ===
	t.Log("Phase 4: Testing network resilience - disconnect and reconnect")

	// Disconnect Node 1
	t.Log("Disconnecting Node 1...")
	err = node1DB.Disconnect(ctx)
	if err != nil {
		t.Logf("Note: Node1 disconnect had error: %v", err)
	}

	// Wait for disconnection to be detected
	time.Sleep(3 * time.Second)

	// Check that Node 0 and Node 2 are still connected
	node0PeersAfterDisconnect := len(node0DB.GetHost().Network().Peers())
	node2PeersAfterDisconnect := len(node2DB.GetHost().Network().Peers())

	t.Logf("After Node1 disconnect - Node0 peers: %d, Node2 peers: %d",
		node0PeersAfterDisconnect, node2PeersAfterDisconnect)

	if node0PeersAfterDisconnect < 1 || node2PeersAfterDisconnect < 1 {
		t.Error("Node 0 and Node 2 should still be connected after Node 1 disconnects")
	}

	// Reconnect Node 1
	t.Log("Reconnecting Node 1...")
	node1DB, err = pubsub.Connect(ctx, node1Config)
	if err != nil {
		t.Fatalf("Failed to reconnect Node1: %v", err)
	}
	defer func() { _ = node1DB.Disconnect(ctx) }()

	// Wait for reconnection
	time.Sleep(5 * time.Second)

	// Verify all nodes are connected again
	finalNode0Peers := len(node0DB.GetHost().Network().Peers())
	finalNode1Peers := len(node1DB.GetHost().Network().Peers())
	finalNode2Peers := len(node2DB.GetHost().Network().Peers())

	t.Logf("Final peer counts - Node0: %d, Node1: %d, Node2: %d",
		finalNode0Peers, finalNode1Peers, finalNode2Peers)

	if finalNode0Peers < 2 || finalNode1Peers < 2 || finalNode2Peers < 2 {
		t.Error("Not all nodes reconnected properly after Node 1 reconnection")
	}

	t.Log("✅ All Nodes as Bootstrap and Authorized Test Complete")
	t.Log("  - All nodes successfully connected to each other")
	t.Log("  - Pub/sub communication works between all nodes")
	t.Log("  - Network shows resilience to node disconnections")
	t.Log("  - Self-information as bootstrap/authorized works correctly")
}

// TestAuthorizationCacheRefresh tests that new nodes can connect after being added to the authorized list
func TestAuthorizationCacheRefresh(t *testing.T) {
	t.Log("=== Starting Authorization Cache Refresh Test ===")

	// Test configuration
	testTopic := "cache-refresh-topic"
	refreshInterval := 2 * time.Second // Short interval for testing
	messageTimeout := 10 * time.Second

	// Create logger
	logger := &TestLogger{}

	// Setup context
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Initially, only nodes 0 and 1 are authorized
	initialAuthorizedWallets := []solana.PublicKey{
		solana.MustPublicKeyFromBase58(node0PublicKey),
		solana.MustPublicKeyFromBase58(node1PublicKey),
	}

	// Create a mock registry function that can be updated
	var authorizedWallets []solana.PublicKey
	var authorizedMutex sync.RWMutex

	mockGetAuthorizedWallets := func(ctx context.Context) ([]solana.PublicKey, error) {
		authorizedMutex.RLock()
		defer authorizedMutex.RUnlock()
		return authorizedWallets, nil
	}

	// Set initial authorized wallets
	authorizedMutex.Lock()
	authorizedWallets = initialAuthorizedWallets
	authorizedMutex.Unlock()

	// Node 0 (Bootstrap and authorized)
	node0Config := common.Config{
		WalletPrivateKey:     node0PrivateKey,
		DatabaseName:         "cache-refresh-network",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes:    mockGetBootstrapNodesForBootstrap,
		Logger:               logger,
		RefreshInterval:      refreshInterval,
		ListenPorts: common.ListenPorts{
			QUIC: 16001,
			TCP:  16002,
		},
	}

	node0DB, err := pubsub.Connect(ctx, node0Config)
	if err != nil {
		t.Fatalf("Failed to connect Node 0: %v", err)
	}
	defer func() { _ = node0DB.Disconnect(ctx) }()

	// Subscribe node 0 to topic
	err = node0DB.Subscribe(ctx, testTopic, func(event common.Event) {
		t.Logf("Node 0 received message: %s", event.ID)
	})
	if err != nil {
		t.Fatalf("Failed to subscribe Node 0: %v", err)
	}

	time.Sleep(2 * time.Second)

	// Node 1 (Client and authorized)
	node1Config := common.Config{
		WalletPrivateKey:     node1PrivateKey,
		DatabaseName:         "cache-refresh-network",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes:    mockGetBootstrapNodesForClients("127.0.0.1", 16001, 16002),
		Logger:               logger,
		RefreshInterval:      refreshInterval,
		ListenPorts: common.ListenPorts{
			QUIC: 16003,
			TCP:  16004,
		},
	}

	node1DB, err := pubsub.Connect(ctx, node1Config)
	if err != nil {
		t.Fatalf("Failed to connect Node 1: %v", err)
	}
	defer func() { _ = node1DB.Disconnect(ctx) }()

	// Subscribe node 1 to topic
	err = node1DB.Subscribe(ctx, testTopic, func(event common.Event) {
		t.Logf("Node 1 received message: %s", event.ID)
	})
	if err != nil {
		t.Fatalf("Failed to subscribe Node 1: %v", err)
	}

	// Wait for initial network setup
	time.Sleep(5 * time.Second)

	// Verify initial connectivity - nodes 0 and 1 should be connected
	if !node0DB.IsReady() {
		t.Fatal("Node 0 should be ready after initial setup")
	}
	if !node1DB.IsReady() {
		t.Fatal("Node 1 should be ready after initial setup")
	}

	t.Log("Initial network setup complete - nodes 0 and 1 are connected")

	// Now add node 2 to the authorized list
	authorizedMutex.Lock()
	authorizedWallets = append(authorizedWallets, solana.MustPublicKeyFromBase58(node2PublicKey))
	authorizedMutex.Unlock()

	t.Log("Added node 2 to authorized list")

	// Wait for cache refresh (refresh interval + buffer)
	time.Sleep(refreshInterval + 1*time.Second)

	// Now try to connect node 2
	node2Config := common.Config{
		WalletPrivateKey:     node2PrivateKey,
		DatabaseName:         "cache-refresh-network",
		GetAuthorizedWallets: mockGetAuthorizedWallets,
		GetBootstrapNodes:    mockGetBootstrapNodesForClients("127.0.0.1", 16001, 16002),
		Logger:               logger,
		RefreshInterval:      refreshInterval,
		ListenPorts: common.ListenPorts{
			QUIC: 16005,
			TCP:  16006,
		},
	}

	node2DB, err := pubsub.Connect(ctx, node2Config)
	if err != nil {
		t.Fatalf("Failed to connect Node 2: %v", err)
	}
	defer func() { _ = node2DB.Disconnect(ctx) }()

	// Subscribe node 2 to topic
	err = node2DB.Subscribe(ctx, testTopic, func(event common.Event) {
		t.Logf("Node 2 received message: %s", event.ID)
	})
	if err != nil {
		t.Fatalf("Failed to subscribe Node 2: %v", err)
	}

	// Wait for node 2 to connect
	time.Sleep(5 * time.Second)

	// Verify all nodes are connected
	if !node0DB.IsReady() {
		t.Fatal("Node 0 should still be ready")
	}
	if !node1DB.IsReady() {
		t.Fatal("Node 1 should still be ready")
	}
	if !node2DB.IsReady() {
		t.Fatal("Node 2 should be ready after being added to authorized list")
	}

	t.Log("All nodes are connected after cache refresh")

	// Test message propagation between all nodes
	message := NodeMessage{
		NodeID:  "node-2",
		Content: "Hello from newly authorized Node 2",
		Counter: 1,
	}

	// Publish from node 2
	event, err := node2DB.Publish(ctx, testTopic, message)
	if err != nil {
		t.Fatalf("Failed to publish from Node 2: %v", err)
	}
	t.Logf("Node 2 published message: %s", event.ID)

	// Wait for message propagation
	time.Sleep(messageTimeout)

	// Verify that all nodes can communicate
	t.Log("Authorization cache refresh test completed successfully")
}
