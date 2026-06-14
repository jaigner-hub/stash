// Package audit is a per-node, append-only, hash-chained audit log. Each entry
// embeds the hash of the previous one, so any insertion, deletion, or edit
// breaks the chain and is detectable via Verify. It lives in its own bbolt file
// (not the replicated store): every node records the operations it actually
// served, which is the honest thing to attest to — reads are served locally, so
// only a per-node log can capture them.
package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucket = []byte("audit")

// Entry is one audit record. Hash chains over every field except Hash itself.
type Entry struct {
	Seq      uint64 `json:"seq"`
	Time     string `json:"time"`
	Identity string `json:"identity"`
	Action   string `json:"action"` // read|write|delete|list|identity.create|identity.delete
	Path     string `json:"path"`   // secret path or identity name ("" for list)
	Result   string `json:"result"` // ok|denied|not_found|error
	Node     string `json:"node"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Log is an append-only hash-chained audit log backed by bbolt.
type Log struct {
	db   *bolt.DB
	node string

	mu   sync.Mutex
	seq  uint64
	last string
}

// Open opens (creating if needed) the audit log at path, attributing entries to
// node. It recovers the latest sequence/hash so the chain continues across
// restarts.
func Open(path, node string) (*Log, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	l := &Log{db: db, node: node}
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucket)
		if err != nil {
			return err
		}
		if k, v := b.Cursor().Last(); k != nil {
			l.seq = binary.BigEndian.Uint64(k)
			var e Entry
			if err := json.Unmarshal(v, &e); err == nil {
				l.last = e.Hash
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return l, nil
}

func hashEntry(e Entry) string {
	// Canonical over the immutable fields plus the previous hash. Excludes the
	// Hash field itself.
	s := fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		e.Seq, e.Time, e.Identity, e.Action, e.Path, e.Result, e.Node, e.PrevHash)
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Record appends an entry, linking it to the chain. It is safe for concurrent
// use.
func (l *Log) Record(identity, action, path, result string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := Entry{
		Seq:      l.seq + 1,
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
		Identity: identity,
		Action:   action,
		Path:     path,
		Result:   result,
		Node:     l.node,
		PrevHash: l.last,
	}
	e.Hash = hashEntry(e)

	rec, err := json.Marshal(e)
	if err != nil {
		return err
	}
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, e.Seq)
	if err := l.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Put(key, rec)
	}); err != nil {
		return err
	}
	l.seq = e.Seq
	l.last = e.Hash
	return nil
}

// Recent returns up to n entries, newest first.
func (l *Log) Recent(n int) ([]Entry, error) {
	out := []Entry{}
	err := l.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucket).Cursor()
		for k, v := c.Last(); k != nil && len(out) < n; k, v = c.Prev() {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

// Verify walks the whole chain and reports whether it is intact, plus the entry
// count.
func (l *Log) Verify() (bool, uint64, error) {
	intact := true
	prev := ""
	var count uint64
	err := l.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucket).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			if e.PrevHash != prev || hashEntry(e) != e.Hash {
				intact = false
			}
			prev = e.Hash
			count++
		}
		return nil
	})
	return intact, count, err
}

// Close releases the underlying database.
func (l *Log) Close() error { return l.db.Close() }
