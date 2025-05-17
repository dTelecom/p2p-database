package p2p_database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"

	"github.com/ipfs/go-datastore"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/multiformats/go-multiaddr"

	"github.com/google/uuid"
	ipfs_datastore "github.com/ipfs/go-datastore/sync"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"

	"github.com/libp2p/go-libp2p-kad-dht/dual"

	"github.com/dTelecom/p2p-database/internal/common"
	ipfslite "github.com/hsanjuan/ipfs-lite"
	crdt "github.com/ipfs/go-ds-crdt"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/sync/errgroup"
)

const (
	DefaultPort = 3500

	DefaultDatabaseEventsBufferSize = 10024
	RebroadcastingInterval          = 30 * time.Second

	NetSubscriptionTopicPrefix  = "crdt_net_"
	NetSubscriptionPublishValue = "ping"
)

const DiscoveryTag = "p2p-database-discovery"

var (
	ErrEmptyKey                     = errors.New("empty key")
	ErrKeyNotFound                  = errors.New("key not found")
	ErrIncorrectSubscriptionHandler = errors.New("incorrect subscription handler")
)

var (
	onceInitHostP2P = sync.Once{}
	lock            = sync.RWMutex{}

	globalPubSubCrdtBroadcasters = map[string]*crdt.PubSubBroadcaster{}
	globalHost                   host.Host
	globalDHT                    *dual.DHT
	globalBootstrapNodes         []peer.AddrInfo
	globalGossipSub              *pubsub.PubSub

	globalLockIPFS  = sync.RWMutex{}
	onceInitIPFS    = sync.Once{}
	globalReadyIPFS bool
	globalIPFs      *ipfslite.Peer

	globalDataStorePerDb          = map[string]datastore.Batching{}
	globalJoinedTopicsPerDb       = map[string]map[string]*pubsub.Topic{}
	globalTopicSubscriptionsPerDb = map[string]map[string]*TopicSubscription{}
)

type PubSubHandler func(Event)

type TopicSubscription struct {
	subscription *pubsub.Subscription
	topic        *pubsub.Topic
	handler      PubSubHandler
}

type Event struct {
	ID         string
	FromPeerId string
	Message    interface{}
}

type DB struct {
	Name   string
	selfID peer.ID
	host   host.Host
	crdt   *crdt.Datastore

	ds          datastore.Batching
	pubSub      *pubsub.PubSub
	handleGroup *errgroup.Group
	lock        sync.RWMutex

	cancel context.CancelFunc

	ready             bool
	readyDatabaseLock sync.Mutex
	disconnectOnce    sync.Once
	logger            common.Logger
}

func Connect(
	ctx context.Context,
	config Config,
	logger common.Logger,
	opts ...dht.Option,
) (*DB, error) {
	ctx, cancel := context.WithCancel(ctx)

	crypto.MinRsaKeyBits = 1024

	grp := &errgroup.Group{}
	grp.SetLimit(DefaultDatabaseEventsBufferSize)

	port := config.PeerListenPort
	if port == 0 {
		port = DefaultPort
	}

	h, _, err := makeHost(ctx, config, port, logger)
	if err != nil {
		cancel()
		return nil, errors.Wrap(err, "make lib p2p host")
	}

	lock.RLock()
	pubsubTopic := "crdt_" + config.DatabaseName
	pubsubBC, exists := globalPubSubCrdtBroadcasters[pubsubTopic]
	lock.RUnlock()

	if !exists {
		lock.Lock()
		pubsubBC, err = crdt.NewPubSubBroadcaster(context.Background(), globalGossipSub, pubsubTopic)
		if err != nil && !strings.Contains(err.Error(), "topic already exists") {
			cancel()
			return nil, errors.Wrap(err, "init pub sub crdt broadcaster")
		}
		globalPubSubCrdtBroadcasters[pubsubTopic] = pubsubBC
		lock.Unlock()
	}

	lock.RLock()
	ds, exists := globalDataStorePerDb[config.DatabaseName]
	lock.RUnlock()

	if !exists {
		lock.Lock()
		ds = ipfs_datastore.MutexWrap(datastore.NewMapDatastore())
		globalDataStorePerDb[config.DatabaseName] = ds
		lock.Unlock()
	}

	for i, bootstrapNode := range globalBootstrapNodes {
		logger.Infof("Bootstrap node %d - %s - [%s]", i, bootstrapNode.String(), bootstrapNode.Addrs[0].String())
		h.ConnManager().TagPeer(bootstrapNode.ID, "keep", 100)
	}

	crtdOpts := crdt.DefaultOptions()
	crtdOpts.RebroadcastInterval = RebroadcastingInterval
	crtdOpts.RebroadcastInterval = time.Second

	doneBootstrappingIPFS, err := makeIPFS(ctx, ds, h)
	if err != nil {
		cancel()
		return nil, err
	}

	datastoreCrdt, err := crdt.New(ds, datastore.NewKey("crdt_"+config.DatabaseName), globalIPFs, pubsubBC, crtdOpts)
	if err != nil {
		cancel()
		return nil, errors.Wrap(err, "init crdt")
	}

	err = datastoreCrdt.Sync(ctx, datastore.NewKey("/"))
	if err != nil {
		cancel()
		return nil, errors.Wrap(err, "crdt sync datastore")
	}

	lock.Lock()
	_, ok := globalJoinedTopicsPerDb[config.DatabaseName]
	if !ok {
		globalJoinedTopicsPerDb[config.DatabaseName] = map[string]*pubsub.Topic{}
	}
	_, ok = globalTopicSubscriptionsPerDb[config.DatabaseName]
	if !ok {
		globalTopicSubscriptionsPerDb[config.DatabaseName] = map[string]*TopicSubscription{}
	}
	lock.Unlock()

	db := &DB{
		Name:   config.DatabaseName,
		host:   h,
		selfID: h.ID(),
		logger: logger,

		crdt: datastoreCrdt,

		cancel: cancel,

		pubSub:      globalGossipSub,
		handleGroup: grp,
		lock:        sync.RWMutex{},

		readyDatabaseLock: sync.Mutex{},
		disconnectOnce:    sync.Once{},
	}

	globalLockIPFS.RLock()
	if !globalReadyIPFS {
		//Unlock db after successfully bootstrapping IPFS
		db.readyDatabaseLock.Lock()
		go func() {
			select {
			case <-ctx.Done():
				return
			case <-doneBootstrappingIPFS:
				db.readyDatabaseLock.Unlock()
				return
			}
		}()
	}
	globalLockIPFS.RUnlock()

	db.Subscribe(ctx, NetSubscriptionTopicPrefix+config.DatabaseName, func(event Event) {
		peerId, err := peer.Decode(event.FromPeerId)
		if err != nil {
			db.logger.Errorf("net topic parse peer %s error: %w", event.FromPeerId, err)
			return
		}

		if event.FromPeerId == db.host.ID().String() {
			return
		}

		db.host.ConnManager().TagPeer(peerId, "keep", 100)
	})

	db.netPingPeers(ctx, NetSubscriptionTopicPrefix+config.DatabaseName)
	db.startDiscovery(ctx)

	go func() {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		db.Disconnect(ctx)
	}()

	return db, nil
}

func (db *DB) String() string {
	return db.Name
}

func (db *DB) Subscribe(ctx context.Context, topic string, handler PubSubHandler, opts ...pubsub.TopicOpt) error {
	db.WaitReady(ctx)

	t, err := db.joinTopic(topic, opts...)
	if err != nil {
		return err
	}

	s, err := t.Subscribe()
	if err != nil {
		return errors.Wrap(err, "pub sub subscribe topic")
	}

	if handler == nil {
		return ErrIncorrectSubscriptionHandler
	}

	lock.Lock()
	globalTopicSubscriptionsPerDb[db.Name][topic] = &TopicSubscription{
		subscription: s,
		topic:        t,
		handler:      handler,
	}
	lock.Unlock()

	db.handleGroup.Go(func() error {
		lock.RLock()
		topicSubscription := globalTopicSubscriptionsPerDb[db.Name][topic]
		lock.RUnlock()

		err = db.listenEvents(ctx, topicSubscription)
		if err != nil {
			db.logger.Errorf("pub sub listen events topic %s err %s", topic, err)
		}
		return err
	})

	return nil
}

func (db *DB) Publish(ctx context.Context, topic string, value interface{}, opts ...pubsub.PubOpt) (Event, error) {
	db.WaitReady(ctx)

	t, err := db.joinTopic(topic)
	if err != nil {
		return Event{}, err
	}

	event := Event{
		ID:         uuid.New().String(),
		Message:    value,
		FromPeerId: db.host.ID().String(),
	}
	marshaled, err := json.Marshal(event)
	if err != nil {
		return Event{}, errors.Wrap(err, "try marshal message")
	}

	err = t.Publish(ctx, marshaled, opts...)
	if err != nil {
		return Event{}, errors.Wrap(err, "pub sub publish message")
	}

	return event, nil
}

func (db *DB) Disconnect(ctx context.Context) error {
	var err error
	db.disconnectOnce.Do(func() {
		db.cancel()
		err = db.disconnect(ctx)
	})
	return err
}

func (db *DB) disconnect(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		lock.Lock()
		defer lock.Unlock()

		topics := globalTopicSubscriptionsPerDb[db.Name]
		delete(globalTopicSubscriptionsPerDb, db.Name)
		delete(globalJoinedTopicsPerDb, db.Name)

		for _, s := range topics {
			s.subscription.Cancel()
			err := s.topic.Close()
			if err != nil {
				db.logger.Errorf("try close db topic %s current peer id %s: %s", s.topic, db.host.ID(), err)
			}
		}
		return nil
	})
	g.Go(func() error {
		err := db.handleGroup.Wait()
		return err
	})

	ch := make(chan error, 1)
	go func() {
		ch <- g.Wait()
	}()

	select {
	case <-ctx.Done():
		return errors.Wrap(ctx.Err(), "try close")
	case err := <-ch:
		return err
	}
}

func (db *DB) GetHost() host.Host {
	return db.host
}

func (db *DB) ConnectedPeers() []*peer.AddrInfo {
	var pinfos []*peer.AddrInfo
	for _, c := range db.host.Network().Conns() {
		pinfos = append(pinfos, &peer.AddrInfo{
			ID:    c.RemotePeer(),
			Addrs: []multiaddr.Multiaddr{c.RemoteMultiaddr()},
		})
	}
	return pinfos
}

func (db *DB) joinTopic(topic string, opts ...pubsub.TopicOpt) (*pubsub.Topic, error) {
	lock.Lock()
	defer lock.Unlock()

	ts, ok := globalTopicSubscriptionsPerDb[db.Name][topic]
	//already joined
	if ok {
		return ts.topic, nil
	}

	if t, ok := globalJoinedTopicsPerDb[db.Name][topic]; ok {
		return t, nil
	}

	t, err := db.pubSub.Join(db.Name+"_"+topic, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "pub sub join topic")
	}
	globalJoinedTopicsPerDb[db.Name][topic] = t

	return t, nil
}

func (db *DB) listenEvents(ctx context.Context, topicSub *TopicSubscription) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			msg, err := topicSub.subscription.Next(ctx)
			if err != nil {
				db.logger.Errorf("try get next pub sub message error: %s", err)
				if errors.Is(err, pubsub.ErrSubscriptionCancelled) || errors.Is(err, context.Canceled) {
					return nil
				}
				continue
			}

			//skip self messages
			if msg.ReceivedFrom == db.selfID {
				if msg.Message != nil {
					db.logger.Debugf("fetched message from self publish %s", string(msg.Message.Data))
				}
				continue
			}

			event := Event{}
			err = json.Unmarshal(msg.Data, &event)
			if err != nil {
				db.logger.Errorf("try unmarshal pub sub message from %s error %s, data: %s", msg.ReceivedFrom, err, string(msg.Data))
			}

			topicSub.handler(event)
		}
	}
}

func (db *DB) netPingPeers(ctx context.Context, netTopic string) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				_, err := db.Publish(ctx, netTopic, []byte(NetSubscriptionPublishValue))
				if err != nil {
					db.logger.Errorf("try publish message to net ps topic: %s", err)
					if errors.Is(err, pubsub.ErrTopicClosed) {
						return
					}
				}
				time.Sleep(20 * time.Second)
			}
		}
	}()
}

func (db *DB) WaitReady(ctx context.Context) {
	if db.ready || globalReadyIPFS {
		return
	}

	db.readyDatabaseLock.Lock()
	db.ready = true
	db.readyDatabaseLock.Unlock()
}

func (db *DB) startDiscovery(ctx context.Context) {
	db.WaitReady(ctx)

	rendezvous := DiscoveryTag + "_" + db.Name
	routingDiscovery := routing.NewRoutingDiscovery(globalDHT)
	util.Advertise(ctx, routingDiscovery, rendezvous)

	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			peers, err := util.FindPeers(ctx, routingDiscovery, rendezvous)
			if err != nil {
				db.logger.Errorf("discrovery find peers error %s", err)
				return
			}
			for _, p := range peers {
				db.logger.Errorf("found peer %s", p.String())

				if p.ID == db.host.ID() {
					continue
				}

				if db.host.Network().Connectedness(p.ID) != network.Connected {
					_, err = db.host.Network().DialPeer(ctx, p.ID)
					if err != nil {
						db.logger.Errorf("discrovery connected to peer error %s: %s", p.ID.String(), err)
						continue
					}
					db.logger.Infof("discrovery connected to peer %s\n", p.ID.String())
				}
			}
		}
	}()
}

func makeHost(ctx context.Context, config Config, port int, logger common.Logger) (host.Host, *dual.DHT, error) {

	// Decode the Solana private key from base58
	privKeyBytes, err := base58.Decode(config.WalletPrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "decode solana private key from base58")
	}

	// If it's a full keypair (64 bytes), extract just the private key part (first 32 bytes)
	if len(privKeyBytes) == 64 {
		privKeyBytes = privKeyBytes[:32]
	} else if len(privKeyBytes) != 32 {
		return nil, nil, errors.New("invalid solana private key length")
	}

	// Convert Solana private key to Ed25519 format expected by libp2p
	// Ed25519 private key needs to be 64 bytes: 32 bytes private key + 32 bytes public key
	// Generate the public key from the private key
	privateKey := ed25519.NewKeyFromSeed(privKeyBytes)

	// Create a complete Ed25519 key (64 bytes: private + public)
	edPrivKey := make([]byte, 64)
	copy(edPrivKey, privateKey)

	// Unmarshal as Ed25519 private key
	priv, err := crypto.UnmarshalEd25519PrivateKey(edPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unmarshal Ed25519 private key")
	}

	sourceMultiAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port))
	if err != nil {
		return nil, nil, errors.Wrap(err, "create multi addr")
	}

	var errSetupLibP2P error
	onceInitHostP2P.Do(func() {
		opts := ipfslite.Libp2pOptionsExtra
		gater := NewSolanaConnectionGater(logger, config)
		opts = append(opts, libp2p.ConnectionGater(
			gater,
		))

		globalHost, globalDHT, errSetupLibP2P = ipfslite.SetupLibp2p(
			context.Background(),
			priv,
			nil,
			[]multiaddr.Multiaddr{sourceMultiAddr},
			nil,
			opts...,
		)
		if errSetupLibP2P != nil {
			return
		}

		globalGossipSub, errSetupLibP2P = pubsub.NewGossipSub(context.Background(), globalHost)
		if err != nil {
			return
		}

		// Try to get bootstrap nodes up to 10 times if we get fewer than 3 nodes
		var retryCount int
		maxRetries := 10
		minNodes := 3

		for retryCount < maxRetries {
			globalBootstrapNodes, errSetupLibP2P = gater.GetBoostrapNodes()
			if errSetupLibP2P != nil {
				return
			}

			if len(globalBootstrapNodes) >= minNodes {
				// We have enough bootstrap nodes, break out of the loop
				break
			}

			logger.Infof("Received only %d bootstrap nodes, waiting 1 second and retrying (%d/%d)",
				len(globalBootstrapNodes), retryCount+1, maxRetries)

			// Sleep for 1 second before retrying
			time.Sleep(1 * time.Second)
			retryCount++
		}

		// If we still have fewer than minNodes after all retries, return an error
		if len(globalBootstrapNodes) < minNodes {
			errSetupLibP2P = fmt.Errorf("failed to get at least %d bootstrap nodes after %d attempts, only got %d nodes",
				minNodes, maxRetries, len(globalBootstrapNodes))
			return
		}
	})

	if errSetupLibP2P != nil {
		return nil, nil, errors.Wrap(errSetupLibP2P, "setup lib p2p")
	}

	return globalHost, globalDHT, nil
}

func makeIPFS(ctx context.Context, ds datastore.Batching, h host.Host) (chan struct{}, error) {
	var (
		err               error
		doneBootstrapping = make(chan struct{}, 1)
	)

	onceInitIPFS.Do(func() {
		globalIPFs, err = ipfslite.New(context.Background(), ds, nil, h, globalDHT, &ipfslite.Config{})
		go func() {
			globalIPFs.Bootstrap(globalBootstrapNodes)

			doneBootstrapping <- struct{}{}
			globalLockIPFS.Lock()
			globalReadyIPFS = true
			globalLockIPFS.Unlock()
		}()
	})

	return doneBootstrapping, errors.Wrap(err, "init ipfs")
}
