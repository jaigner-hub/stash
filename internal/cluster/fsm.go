package cluster

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/hashicorp/raft"
	"github.com/jaigner-hub/stash/internal/store"
)

// cmdOp identifies a replicated operation in the Raft log.
type cmdOp string

const (
	opInit   cmdOp = "init"   // establish the wrapped DEK + canary
	opPut    cmdOp = "put"    // store a pre-encrypted value blob
	opDelete cmdOp = "delete" // remove a path
	opMeta   cmdOp = "meta"   // record a node's API address
	opConfig cmdOp = "config" // set cluster id + join secret
)

// command is one entry in the Raft log. Encryption happens once on the leader;
// Blob/WrappedDEK/Canary carry ciphertext so every replica applies identical
// bytes (encryption is non-deterministic, so we must not re-encrypt per node).
type command struct {
	Op         cmdOp  `json:"op"`
	Path       string `json:"path,omitempty"`
	Blob       []byte `json:"blob,omitempty"`
	WrappedDEK []byte `json:"wrapped_dek,omitempty"`
	Canary     []byte `json:"canary,omitempty"`
	NodeID     string `json:"node_id,omitempty"`
	HTTPAddr   string `json:"http_addr,omitempty"`
	ClusterID  string `json:"cluster_id,omitempty"`
	Secret     string `json:"secret,omitempty"`
}

// fsm is the Raft finite state machine: it applies committed commands to the
// encrypted store and tracks each node's API address (so any node can locate
// the leader's HTTP endpoint for request forwarding).
type fsm struct {
	store *store.Store

	mu         sync.RWMutex
	meta       map[string]string // nodeID -> advertised HTTP addr
	clusterID  string
	joinSecret string
}

func newFSM(st *store.Store) *fsm {
	return &fsm{store: st, meta: map[string]string{}}
}

// Apply runs a committed log entry against the store. The return value becomes
// the ApplyFuture.Response() on the leader.
func (f *fsm) Apply(l *raft.Log) interface{} {
	var c command
	if err := json.Unmarshal(l.Data, &c); err != nil {
		return fmt.Errorf("stash/cluster: decode command: %w", err)
	}
	switch c.Op {
	case opInit:
		return f.store.PutMeta(c.WrappedDEK, c.Canary)
	case opPut:
		return f.store.PutRaw(c.Path, c.Blob)
	case opDelete:
		return f.store.DeleteRaw(c.Path)
	case opMeta:
		f.mu.Lock()
		f.meta[c.NodeID] = c.HTTPAddr
		f.mu.Unlock()
		return nil
	case opConfig:
		f.mu.Lock()
		f.clusterID = c.ClusterID
		f.joinSecret = c.Secret
		f.mu.Unlock()
		return nil
	default:
		return fmt.Errorf("stash/cluster: unknown op %q", c.Op)
	}
}

func (f *fsm) httpAddr(nodeID string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	a, ok := f.meta[nodeID]
	return a, ok
}

func (f *fsm) clusterConfig() (id, secret string) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.clusterID, f.joinSecret
}

// verifySecret constant-time compares a presented join secret against the
// cluster's. Returns false if no secret has been configured yet.
func (f *fsm) verifySecret(secret string) bool {
	f.mu.RLock()
	want := f.joinSecret
	f.mu.RUnlock()
	if want == "" || secret == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(secret), []byte(want)) == 1
}

// snapshotPayload is the serialized FSM state: store contents (ciphertext) plus
// the node-address map.
type snapshotPayload struct {
	Store     *store.Snapshot   `json:"store"`
	Meta      map[string]string `json:"meta"`
	ClusterID string            `json:"cluster_id"`
	Secret    string            `json:"secret"`
}

func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	snap, err := f.store.Export()
	if err != nil {
		return nil, err
	}
	f.mu.RLock()
	meta := make(map[string]string, len(f.meta))
	for k, v := range f.meta {
		meta[k] = v
	}
	payload := snapshotPayload{Store: snap, Meta: meta, ClusterID: f.clusterID, Secret: f.joinSecret}
	f.mu.RUnlock()

	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &fsmSnapshot{data: buf}, nil
}

func (f *fsm) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	buf, err := io.ReadAll(rc)
	if err != nil {
		return err
	}
	var payload snapshotPayload
	if err := json.Unmarshal(buf, &payload); err != nil {
		return err
	}
	if payload.Store != nil {
		if err := f.store.Import(payload.Store); err != nil {
			return err
		}
	}
	f.mu.Lock()
	if payload.Meta == nil {
		payload.Meta = map[string]string{}
	}
	f.meta = payload.Meta
	f.clusterID = payload.ClusterID
	f.joinSecret = payload.Secret
	f.mu.Unlock()
	return nil
}

// fsmSnapshot persists a serialized FSM snapshot to a Raft sink.
type fsmSnapshot struct{ data []byte }

func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s.data); err != nil {
		sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *fsmSnapshot) Release() {}
