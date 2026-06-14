// Package cluster turns a single encrypted store into a highly-available one by
// replicating every write through an embedded Raft log (hashicorp/raft). Reads
// are served locally; writes are applied on the leader and replicated. A node
// started without an unseal key runs as a sealed witness: it participates in
// consensus and stores ciphertext but cannot read or write secrets.
package cluster

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/jaigner-hub/stash/internal/store"
)

// ErrNotLeader is returned by write operations attempted on a follower.
var ErrNotLeader = errors.New("stash/cluster: not the leader")

const applyTimeout = 10 * time.Second

// Config configures a cluster node.
type Config struct {
	NodeID        string // unique stable id for this node
	RaftAddr      string // host:port the Raft transport binds to
	RaftAdvertise string // host:port peers dial (defaults to RaftAddr)
	HTTPAddr      string // advertised API URL other nodes use to reach this node
	DataDir       string // directory for raft logs/snapshots (and the store db)
	Bootstrap     bool   // form a new single-node cluster if no state exists
	Witness       bool   // this node has no key; it must never remain leader
}

// JoinRequest is the body of POST /v1/cluster/join.
type JoinRequest struct {
	NodeID   string `json:"node_id"`
	RaftAddr string `json:"raft_addr"`
	HTTPAddr string `json:"http_addr"`
	Secret   string `json:"secret"`
}

// Node is a single member of a stash cluster.
type Node struct {
	cfg         Config
	raft        *raft.Raft
	fsm         *fsm
	store       *store.Store
	tn          *raft.NetworkTransport
	logStore    *raftboltdb.BoltStore
	stableStore *raftboltdb.BoltStore
}

// New constructs a node and its Raft instance. If cfg.Bootstrap is set and no
// prior Raft state exists, it forms a new single-node cluster.
func New(cfg Config, st *store.Store) (*Node, error) {
	f := newFSM(st)

	rc := raft.DefaultConfig()
	rc.LocalID = raft.ServerID(cfg.NodeID)

	advertise := cfg.RaftAdvertise
	if advertise == "" {
		advertise = cfg.RaftAddr
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", advertise)
	if err != nil {
		return nil, fmt.Errorf("stash/cluster: resolve raft advertise addr: %w", err)
	}
	tn, err := raft.NewTCPTransport(cfg.RaftAddr, tcpAddr, 3, 10*time.Second, os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("stash/cluster: raft transport: %w", err)
	}

	snaps, err := raft.NewFileSnapshotStore(cfg.DataDir, 2, os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("stash/cluster: snapshot store: %w", err)
	}
	logStore, err := raftboltdb.NewBoltStore(filepath.Join(cfg.DataDir, "raft-log.db"))
	if err != nil {
		return nil, fmt.Errorf("stash/cluster: log store: %w", err)
	}
	stableStore, err := raftboltdb.NewBoltStore(filepath.Join(cfg.DataDir, "raft-stable.db"))
	if err != nil {
		return nil, fmt.Errorf("stash/cluster: stable store: %w", err)
	}

	r, err := raft.NewRaft(rc, f, logStore, stableStore, snaps, tn)
	if err != nil {
		return nil, fmt.Errorf("stash/cluster: new raft: %w", err)
	}

	hasState, err := raft.HasExistingState(logStore, stableStore, snaps)
	if err != nil {
		return nil, err
	}
	if cfg.Bootstrap && !hasState {
		fut := r.BootstrapCluster(raft.Configuration{Servers: []raft.Server{{
			ID:      raft.ServerID(cfg.NodeID),
			Address: tn.LocalAddr(),
		}}})
		if err := fut.Error(); err != nil {
			return nil, fmt.Errorf("stash/cluster: bootstrap: %w", err)
		}
	}
	n := &Node{
		cfg: cfg, raft: r, fsm: f, store: st, tn: tn,
		logStore: logStore, stableStore: stableStore,
	}
	// A witness can't serve writes (no key), so it must not lead. If it wins an
	// election, hand leadership to a keyed peer.
	if cfg.Witness {
		go n.shedLeadership()
	}
	return n, nil
}

// shedLeadership transfers leadership away whenever this (witness) node becomes
// leader. It exits when Raft shuts down (LeaderCh closes).
func (n *Node) shedLeadership() {
	for isLeader := range n.raft.LeaderCh() {
		if !isLeader {
			continue
		}
		for i := 0; i < 10 && n.raft.State() == raft.Leader; i++ {
			if err := n.raft.LeadershipTransfer().Error(); err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

// IsLeader reports whether this node is the current Raft leader.
func (n *Node) IsLeader() bool { return n.raft.State() == raft.Leader }

// LeaderHTTPAddr returns the advertised API URL of the current leader.
func (n *Node) LeaderHTTPAddr() (string, bool) {
	_, id := n.raft.LeaderWithID()
	if id == "" {
		return "", false
	}
	if string(id) == n.cfg.NodeID {
		return n.cfg.HTTPAddr, true
	}
	return n.fsm.httpAddr(string(id))
}

// Get returns the decrypted value at path (served locally; may be slightly
// stale on a follower). Requires the local store to be unsealed.
func (n *Node) Get(path string) ([]byte, error) { return n.store.Get(path) }

// List returns all secret paths (served locally). Works while sealed.
func (n *Node) List() ([]string, error) { return n.store.List() }

// Sealed reports whether this node's store lacks a usable DEK.
func (n *Node) Sealed() bool { return n.store.Sealed() }

// Put encrypts value locally then replicates the ciphertext via Raft. Must be
// called on the leader (the server forwards otherwise).
func (n *Node) Put(path string, value []byte) error {
	blob, err := n.store.Encrypt(path, value) // requires unseal
	if err != nil {
		return err
	}
	return n.apply(command{Op: opPut, Path: path, Blob: blob, Ts: nowRFC3339()})
}

// ListVersions returns version metadata for path, newest first.
func (n *Node) ListVersions(path string) ([]store.VersionMeta, error) {
	return n.store.ListVersions(path)
}

// GetVersion returns the decrypted value of a specific version.
func (n *Node) GetVersion(path string, seq uint64) ([]byte, error) {
	blob, err := n.store.GetVersionRaw(path, seq)
	if err != nil {
		return nil, err
	}
	return n.store.Decrypt(path, blob)
}

// Delete removes path via Raft, returning store.ErrNotFound if absent.
func (n *Node) Delete(path string) error {
	ok, err := n.store.Exists(path)
	if err != nil {
		return err
	}
	if !ok {
		return store.ErrNotFound
	}
	return n.apply(command{Op: opDelete, Path: path})
}

// Join adds a voter to the cluster and records its API address. Leader-only.
func (n *Node) Join(nodeID, raftAddr, httpAddr string) error {
	if !n.IsLeader() {
		return ErrNotLeader
	}
	cf := n.raft.GetConfiguration()
	if err := cf.Error(); err != nil {
		return err
	}
	already := false
	for _, srv := range cf.Configuration().Servers {
		if srv.ID == raft.ServerID(nodeID) && srv.Address == raft.ServerAddress(raftAddr) {
			already = true
			break
		}
	}
	if !already {
		fut := n.raft.AddVoter(raft.ServerID(nodeID), raft.ServerAddress(raftAddr), 0, applyTimeout)
		if err := fut.Error(); err != nil {
			return fmt.Errorf("stash/cluster: add voter: %w", err)
		}
	}
	return n.apply(command{Op: opMeta, NodeID: nodeID, HTTPAddr: httpAddr})
}

// Initialize is called on a freshly bootstrapped node: it waits for leadership,
// creates the cluster DEK (if not already present) and replicates it through the
// log, records its own API address, and mints a root admin identity. It returns
// the root token (empty if one already existed) to be shown once. The KEK is
// required because this is where the data key is born.
func (n *Node) Initialize(kek []byte, timeout time.Duration) (rootToken string, err error) {
	if err := n.waitLeader(timeout); err != nil {
		return "", err
	}
	init, err := n.store.Initialized()
	if err != nil {
		return "", err
	}
	if !init {
		wrapped, canary, err := store.NewInitBlobs(kek)
		if err != nil {
			return "", err
		}
		if err := n.apply(command{Op: opInit, WrappedDEK: wrapped, Canary: canary}); err != nil {
			return "", err
		}
	}
	// Establish cluster identity + join secret once, replicated to all nodes so
	// any future leader can authenticate join requests.
	if id, secret := n.fsm.clusterConfig(); id == "" || secret == "" {
		id, err := randomHex(8)
		if err != nil {
			return "", err
		}
		secret, err := randomHex(32)
		if err != nil {
			return "", err
		}
		if err := n.apply(command{Op: opConfig, ClusterID: id, Secret: secret}); err != nil {
			return "", err
		}
	}
	if err := n.apply(command{Op: opMeta, NodeID: n.cfg.NodeID, HTTPAddr: n.cfg.HTTPAddr}); err != nil {
		return "", err
	}
	return n.ensureRootIdentity()
}

// ClusterStatus is a snapshot of cluster membership for the UI/status endpoint.
type ClusterStatus struct {
	NodeID   string       `json:"node_id"`
	IsLeader bool         `json:"is_leader"`
	Sealed   bool         `json:"sealed"`
	LeaderID string       `json:"leader_id"`
	Servers  []ServerInfo `json:"servers"`
}

// ServerInfo describes one raft member.
type ServerInfo struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Suffrage string `json:"suffrage"` // voter | nonvoter
	Leader   bool   `json:"leader"`
}

// Status reports this node's view of cluster membership.
func (n *Node) Status() ClusterStatus {
	_, leaderID := n.raft.LeaderWithID()
	cs := ClusterStatus{
		NodeID:   n.cfg.NodeID,
		IsLeader: n.IsLeader(),
		Sealed:   n.store.Sealed(),
		LeaderID: string(leaderID),
	}
	if cf := n.raft.GetConfiguration(); cf.Error() == nil {
		for _, s := range cf.Configuration().Servers {
			suf := "voter"
			if s.Suffrage == raft.Nonvoter {
				suf = "nonvoter"
			}
			cs.Servers = append(cs.Servers, ServerInfo{
				ID:       string(s.ID),
				Address:  string(s.Address),
				Suffrage: suf,
				Leader:   string(s.ID) == string(leaderID),
			})
		}
	}
	return cs
}

// ClusterConfig returns the cluster id and join secret (once initialized).
func (n *Node) ClusterConfig() (id, secret string) { return n.fsm.clusterConfig() }

// VerifyJoinSecret reports whether secret matches the cluster's join secret.
func (n *Node) VerifyJoinSecret(secret string) bool { return n.fsm.verifySecret(secret) }

// AdvertiseHTTP returns this node's advertised API URL.
func (n *Node) AdvertiseHTTP() string { return n.cfg.HTTPAddr }

// Unseal blocks until the cluster's init material has replicated to this node,
// then unseals the local store with kek. Use for joiners and restarts.
func (n *Node) Unseal(kek []byte, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		init, err := n.store.Initialized()
		if err != nil {
			return err
		}
		if init {
			return n.store.Unseal(kek)
		}
		if time.Now().After(deadline) {
			return errors.New("stash/cluster: timed out waiting for init to replicate")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Close shuts down Raft and its backing stores/transport. The caller owns
// closing the secret store passed to New.
func (n *Node) Close() error {
	err := n.raft.Shutdown().Error()
	if n.tn != nil {
		n.tn.Close()
	}
	if n.logStore != nil {
		n.logStore.Close()
	}
	if n.stableStore != nil {
		n.stableStore.Close()
	}
	return err
}

func (n *Node) apply(c command) error {
	if !n.IsLeader() {
		return ErrNotLeader
	}
	buf, err := json.Marshal(c)
	if err != nil {
		return err
	}
	fut := n.raft.Apply(buf, applyTimeout)
	if err := fut.Error(); err != nil {
		return err
	}
	if resp, ok := fut.Response().(error); ok && resp != nil {
		return resp
	}
	return nil
}

func (n *Node) waitLeader(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if n.raft.State() == raft.Leader {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("stash/cluster: timed out waiting for leadership")
}

// RequestJoin asks the cluster at leaderURL to admit this node. The contacted
// node forwards to the leader if needed.
func RequestJoin(leaderURL, nodeID, raftAddr, httpAddr, secret string) error {
	body, err := json.Marshal(JoinRequest{
		NodeID: nodeID, RaftAddr: raftAddr, HTTPAddr: httpAddr, Secret: secret,
	})
	if err != nil {
		return err
	}
	url := strings.TrimRight(leaderURL, "/") + "/v1/cluster/join"
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("join rejected (%d): %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
