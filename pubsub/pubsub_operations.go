package pubsub

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dTelecom/p2p-database/common"
	"github.com/google/uuid"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// Subscribe subscribes to a topic and starts listening for messages
func (db *DB) Subscribe(ctx context.Context, topic string, handler common.PubSubHandler) error {
	db.instance.mutex.Lock()
	defer db.instance.mutex.Unlock()

	// Create topic name with database namespace
	topicName := fmt.Sprintf("%s_%s", db.instance.name, topic)

	// Check if already subscribed with a handler
	if existingSub, exists := db.instance.subscriptions[topic]; exists {
		if existingSub.handler != nil {
			return fmt.Errorf("already subscribed to topic: %s", topic)
		}
		// If subscription exists but no handler, we can allow re-subscription
		// This handles the case where a topic was joined for publishing only
	}

	// Get or join the topic (handle case where topic was already joined for publishing)
	var pubsubTopic *pubsub.Topic
	var err error

	if existingTopic, exists := db.instance.topics[topic]; exists {
		// Topic already joined (likely from publishing), reuse it
		pubsubTopic = existingTopic
	} else {
		// Topic not joined yet, join it now
		pubsubTopic, err = db.infrastructure.gossipSub.Join(topicName)
		if err != nil {
			return fmt.Errorf("failed to join topic %s: %w", topicName, err)
		}
		// Store the topic for future use
		db.instance.topics[topic] = pubsubTopic
	}

	// Subscribe to the topic
	subscription, err := pubsubTopic.Subscribe()
	if err != nil {
		if closeErr := pubsubTopic.Close(); closeErr != nil {
			db.infrastructure.logger.Warn("Failed to close topic during cleanup", "topic", topicName, "error", closeErr.Error())
		}
		return fmt.Errorf("failed to subscribe to topic %s: %w", topicName, err)
	}

	// Create cancellation context for the listener
	listenerCtx, cancel := context.WithCancel(ctx)

	// Create topic subscription
	topicSub := &TopicSubscription{
		subscription: subscription,
		topic:        pubsubTopic,
		handler:      handler,
		cancel:       cancel,
	}

	// Store the subscription
	db.instance.subscriptions[topic] = topicSub

	// Start message listener goroutine
	go db.messageListener(listenerCtx, topicSub, topicName)

	db.infrastructure.logger.Info("Subscribed to topic",
		"topic", topic,
		"full_topic_name", topicName,
		"database", db.instance.name)

	return nil
}

// messageListener listens for messages on a topic subscription
func (db *DB) messageListener(ctx context.Context, topicSub *TopicSubscription, topicName string) {
	defer func() {
		if r := recover(); r != nil {
			db.infrastructure.logger.Error("Message listener panic recovered",
				"topic", topicName,
				"error", r)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			db.infrastructure.logger.Debug("Message listener stopping",
				"topic", topicName,
				"reason", ctx.Err())
			return
		default:
			// Get next message
			msg, err := topicSub.subscription.Next(ctx)
			if err != nil {
				if ctx.Err() != nil {
					// Context cancelled, normal shutdown
					return
				}
				db.infrastructure.logger.Warn("Failed to get next message",
					"topic", topicName,
					"error", err.Error())
				continue
			}

			// Skip messages from ourselves
			if msg.ReceivedFrom == db.infrastructure.host.ID() {
				continue
			}

			// Parse the message
			var event common.Event
			if err := json.Unmarshal(msg.Data, &event); err != nil {
				db.infrastructure.logger.Warn("Failed to unmarshal message",
					"topic", topicName,
					"from", msg.ReceivedFrom.String(),
					"error", err.Error())
				continue
			}

			// Validate the event
			if event.ID == "" {
				db.infrastructure.logger.Warn("Received event with empty ID",
					"topic", topicName,
					"from", msg.ReceivedFrom.String())
				continue
			}

			// Set the peer ID if not already set
			if event.FromPeerId == "" {
				event.FromPeerId = msg.ReceivedFrom.String()
			}

			db.infrastructure.logger.Debug("Received message",
				"topic", topicName,
				"from", msg.ReceivedFrom.String(),
				"event_id", event.ID,
				"timestamp", event.Timestamp)

			// Call the handler
			topicSub.handler(event)
		}
	}
}

// Unsubscribe unsubscribes from a topic and stops listening for messages
func (db *DB) Unsubscribe(ctx context.Context, topic string) error {
	db.instance.mutex.Lock()
	defer db.instance.mutex.Unlock()

	// Check if subscribed to this topic
	topicSub, exists := db.instance.subscriptions[topic]
	if !exists {
		return fmt.Errorf("not subscribed to topic: %s", topic)
	}

	// Cancel the message listener
	if topicSub.cancel != nil {
		topicSub.cancel()
	}

	// Cancel the subscription
	if topicSub.subscription != nil {
		topicSub.subscription.Cancel()
	}

	// Close the topic if no other subscriptions depend on it
	if topicSub.topic != nil {
		if closeErr := topicSub.topic.Close(); closeErr != nil {
			db.infrastructure.logger.Warn("Failed to close topic during unsubscribe", "topic", topic, "error", closeErr.Error())
		}
	}

	// Remove from maps
	delete(db.instance.subscriptions, topic)
	delete(db.instance.topics, topic)

	db.infrastructure.logger.Info("Unsubscribed from topic",
		"topic", topic,
		"database", db.instance.name)

	return nil
}

// Publish publishes a message to a topic
func (db *DB) Publish(ctx context.Context, topic string, value interface{}) (common.Event, error) {
	db.instance.mutex.RLock()
	defer db.instance.mutex.RUnlock()

	// Create topic name with database namespace
	topicName := fmt.Sprintf("%s_%s", db.instance.name, topic)

	// Get or create the topic
	pubsubTopic, exists := db.instance.topics[topic]
	if !exists {
		// Join the topic if not already joined
		var err error
		pubsubTopic, err = db.infrastructure.gossipSub.Join(topicName)
		if err != nil {
			return common.Event{}, fmt.Errorf("failed to join topic %s: %w", topicName, err)
		}

		// Store the topic (need to unlock and relock for write)
		db.instance.mutex.RUnlock()
		db.instance.mutex.Lock()
		db.instance.topics[topic] = pubsubTopic
		db.instance.mutex.Unlock()
		db.instance.mutex.RLock()
	}

	// Create event
	event := common.Event{
		ID:         uuid.New().String(),
		FromPeerId: db.infrastructure.host.ID().String(),
		Message:    value,
		Timestamp:  time.Now().Unix(),
	}

	// Marshal the event to JSON
	eventData, err := json.Marshal(event)
	if err != nil {
		return common.Event{}, fmt.Errorf("failed to marshal event: %w", err)
	}

	// Publish the message
	if err := pubsubTopic.Publish(ctx, eventData); err != nil {
		return common.Event{}, fmt.Errorf("failed to publish message to topic %s: %w", topicName, err)
	}

	db.infrastructure.logger.Debug("Published message",
		"topic", topic,
		"full_topic_name", topicName,
		"event_id", event.ID,
		"database", db.instance.name)

	return event, nil
}

// ConnectedPeers returns information about connected peers
func (db *DB) ConnectedPeers() []*peer.AddrInfo {
	peers := db.infrastructure.host.Network().Peers()
	var peerInfos []*peer.AddrInfo

	for _, peerID := range peers {
		conns := db.infrastructure.host.Network().ConnsToPeer(peerID)
		if len(conns) > 0 {
			peerInfo := &peer.AddrInfo{
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

// GetHost returns the underlying libp2p host
func (db *DB) GetHost() host.Host {
	return db.infrastructure.host
}

// IsReady returns true if the node has at least 1 peer connected
func (db *DB) IsReady() bool {
	return db.infrastructure.IsReady()
}

// Disconnect closes the database connection and cleans up resources
func (db *DB) Disconnect(ctx context.Context) error {
	db.instance.mutex.Lock()
	defer db.instance.mutex.Unlock()

	// Cancel shutdown context first to stop all retry operations immediately
	if db.infrastructure.shutdownCancel != nil {
		db.infrastructure.shutdownCancel()
	}

	// Stop bootstrap retry (this should now be redundant but kept for safety)
	db.infrastructure.stopBootstrapRetry()

	// Cancel all subscriptions
	for topic, subscription := range db.instance.subscriptions {
		if subscription.cancel != nil {
			subscription.cancel()
		}
		if subscription.subscription != nil {
			subscription.subscription.Cancel()
		}
		delete(db.instance.subscriptions, topic)
	}

	// Close all topics
	for topic, pubsubTopic := range db.instance.topics {
		if pubsubTopic != nil {
			if closeErr := pubsubTopic.Close(); closeErr != nil {
				db.infrastructure.logger.Warn("Failed to close topic during disconnect", "topic", topic, "error", closeErr.Error())
			}
		}
		delete(db.instance.topics, topic)
	}

	// Close infrastructure resources in proper order
	// 1. Close GossipSub first to stop message processing
	if db.infrastructure.gossipSub != nil {
		// GossipSub doesn't have explicit close - it's closed when host closes
		db.infrastructure.logger.Debug("GossipSub will be closed when host closes")
	}

	// 2. Close DHT to stop peer discovery
	if db.infrastructure.dht != nil {
		if closeErr := db.infrastructure.dht.Close(); closeErr != nil {
			db.infrastructure.logger.Warn("Failed to close DHT during disconnect", "error", closeErr.Error())
		}
	}

	// 3. Close host last to terminate all connections and streams
	if db.infrastructure.host != nil {
		if closeErr := db.infrastructure.host.Close(); closeErr != nil {
			db.infrastructure.logger.Warn("Failed to close host during disconnect", "error", closeErr.Error())
		}
	}

	// Give goroutines time to shut down
	time.Sleep(100 * time.Millisecond)

	db.infrastructure.logger.Info("Disconnected from database and cleaned up infrastructure",
		"database", db.instance.name)

	return nil
}
