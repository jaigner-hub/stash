// Package audit is a per-node, append-only, hash-chained, Ed25519-signed audit
// log. Each entry embeds the hash of the previous one, so any insertion,
// deletion, or edit breaks the chain and is detectable via Verify. It lives in
// its own bbolt file (not the replicated store): every node records the
// operations it actually served, which is the honest thing to attest to — reads
// are served locally, so only a per-node log can capture them.
//
// Hash-chaining alone is tamper-evident only against an actor who lacks the
// power to recompute hashes forward: anyone holding the bbolt file (a backup, a
// Loki copy) can rewrite history from any point and re-chain it undetectably.
// To close that rewrite gap, each entry is additionally signed with this node's
// persistent Ed25519 key (see LoadOrCreateKey): rewriting an entry forces
// recomputing its hash, which forces re-signing, which is impossible without the
// private key. Verify checks both the chain and the signatures.
//
// Residual limits, stated honestly: an attacker with the private key itself
// (full filesystem access to audit.key) can still forge; signing defends the
// log, not the host. Two truncation-shaped attacks also need an external anchor
// to catch (the Loki copy serves as one): dropping the newest entries wholesale
// leaves a valid prefix, and stripping the entire signed prefix re-dates the
// signing epoch so the remainder reads as a legacy unsigned log. What signing
// does close is the in-place rewrite gap — editing the content of any retained
// entry forces a new hash and therefore a new signature, which is impossible
// without the key.
package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucket = []byte("audit")

// Entry is one audit record. Hash chains over every field except Hash and Sig;
// Sig is the node's Ed25519 signature over the entry digest (empty on logs or
// entries written before signing was enabled).
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
	Sig      string `json:"sig,omitempty"` // base64 Ed25519 signature over the digest
}

// Log is an append-only, hash-chained, optionally Ed25519-signed audit log
// backed by bbolt.
type Log struct {
	db       *bolt.DB
	node     string
	priv     ed25519.PrivateKey // signing key; nil leaves entries chain-only
	readOnly bool               // opened for verification only (shared lock)

	mu   sync.Mutex
	seq  uint64
	last string
	sink func(Entry) // optional; invoked with each newly recorded entry
}

// Option configures a Log at Open time.
type Option func(*Log)

// WithSigningKey enables per-entry Ed25519 signing with key (see
// LoadOrCreateKey). Passing a nil/empty key is a no-op, leaving the log
// chain-only.
func WithSigningKey(key ed25519.PrivateKey) Option {
	return func(l *Log) {
		if len(key) > 0 {
			l.priv = key
		}
	}
}

// WithReadOnly opens the bbolt file read-only with a short lock timeout, so
// verifying a log whose writer (the running server) holds the exclusive lock
// fails fast with a clear error instead of blocking. Use it for offline
// verification of a stopped node or an off-host copy; Record must not be called.
func WithReadOnly() Option {
	return func(l *Log) { l.readOnly = true }
}

// PublicKey returns the verifying key for this log's signatures, or nil if
// signing is disabled. Distribute it to let an external holder of the log (or
// its Loki copy) verify entries without trusting the node.
func (l *Log) PublicKey() ed25519.PublicKey {
	if l.priv == nil {
		return nil
	}
	return l.priv.Public().(ed25519.PublicKey)
}

// LoadOrCreateKey loads a PEM-encoded Ed25519 private key from path, generating
// and persisting one (0600) if the file does not yet exist. This is the node's
// stable audit-signing identity; it must outlive restarts, so it is kept on disk
// next to audit.db rather than regenerated like the per-restart TLS leaf.
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("audit: invalid signing key PEM in %s", path)
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("audit: parse signing key %s: %w", path, err)
		}
		priv, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("audit: %s is not an ed25519 key", path)
		}
		return priv, nil
	case errors.Is(err, fs.ErrNotExist):
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		out := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(path, out, 0o600); err != nil {
			return nil, fmt.Errorf("audit: write signing key %s: %w", path, err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("audit: read signing key %s: %w", path, err)
	}
}

// Stream registers a sink invoked with each entry right after it is durably
// persisted (so the on-disk chain stays the source of truth). It's how the
// per-node log ships to a central store like Loki for a unified, durable view.
// The sink must not block; pass nil to disable.
func (l *Log) Stream(sink func(Entry)) {
	l.mu.Lock()
	l.sink = sink
	l.mu.Unlock()
}

// Open opens (creating if needed) the audit log at path, attributing entries to
// node. It recovers the latest sequence/hash so the chain continues across
// restarts. Pass WithSigningKey to enable per-entry signatures, or WithReadOnly
// to verify a log without taking the writer lock.
func Open(path, node string, opts ...Option) (*Log, error) {
	l := &Log{node: node}
	for _, opt := range opts {
		opt(l)
	}
	var bopts *bolt.Options
	if l.readOnly {
		// Shared lock + short timeout: opening a db whose writer (the running
		// server) holds the exclusive lock fails fast instead of blocking forever.
		bopts = &bolt.Options{ReadOnly: true, Timeout: 3 * time.Second}
	}
	db, err := bolt.Open(path, 0o600, bopts)
	if err != nil {
		if errors.Is(err, bolt.ErrTimeout) {
			return nil, fmt.Errorf("audit: %s is locked by the running stash server — "+
				"verify on a stopped node, an off-host copy, or via the API: %w", path, err)
		}
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	l.db = db

	recover := func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return nil // fresh / empty log
		}
		if k, v := b.Cursor().Last(); k != nil {
			l.seq = binary.BigEndian.Uint64(k)
			var e Entry
			if err := json.Unmarshal(v, &e); err == nil {
				l.last = e.Hash
			}
		}
		return nil
	}
	if l.readOnly {
		err = db.View(recover) // can't create buckets in a read-only tx
	} else {
		err = db.Update(func(tx *bolt.Tx) error {
			if _, e := tx.CreateBucketIfNotExists(bucket); e != nil {
				return e
			}
			return recover(tx)
		})
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return l, nil
}

// entryDigest is the canonical SHA-256 over the immutable fields plus the
// previous hash. Excludes the Hash and Sig fields themselves; it is both the
// chain hash and the signed message.
func entryDigest(e Entry) [32]byte {
	s := fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		e.Seq, e.Time, e.Identity, e.Action, e.Path, e.Result, e.Node, e.PrevHash)
	return sha256.Sum256([]byte(s))
}

func hashEntry(e Entry) string {
	d := entryDigest(e)
	return hex.EncodeToString(d[:])
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
	d := entryDigest(e)
	e.Hash = hex.EncodeToString(d[:])
	if l.priv != nil {
		e.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(l.priv, d[:]))
	}

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
	if l.sink != nil {
		l.sink(e) // best-effort ship; must not block (see Stream)
	}
	return nil
}

// Recent returns up to n entries, newest first.
func (l *Log) Recent(n int) ([]Entry, error) { return l.Page(0, n) }

// Page returns up to limit entries with seq < before, newest first. A before of
// 0 starts from the newest entry. Use the seq of the last returned entry as the
// next page's before cursor.
func (l *Log) Page(before uint64, limit int) ([]Entry, error) {
	out := []Entry{}
	err := l.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucket).Cursor()
		var k, v []byte
		if before == 0 {
			k, v = c.Last()
		} else {
			bk := make([]byte, 8)
			binary.BigEndian.PutUint64(bk, before)
			if sk, _ := c.Seek(bk); sk == nil {
				k, v = c.Last() // before is past the newest → start at newest
			} else {
				k, v = c.Prev() // first entry strictly < before
			}
		}
		for ; k != nil && len(out) < limit; k, v = c.Prev() {
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
// count. It checks the hash chain always, and — when this log holds a signing
// key — the per-entry signatures too.
//
// Signatures are enforced from the signing epoch onward: the first signed entry
// marks the point at which this node began signing, and every entry at or after
// it must carry a valid signature. Entries before the epoch (written by an older
// build) are exempt, so a rolling upgrade keeps a previously-clean log clean,
// while stripping the signature off any post-epoch entry is reported as tamper.
func (l *Log) Verify() (bool, uint64, error) {
	pub := l.PublicKey()
	intact := true
	prev := ""
	signedSeen := false
	var count uint64
	err := l.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucket).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			d := entryDigest(e)
			if e.PrevHash != prev || hex.EncodeToString(d[:]) != e.Hash {
				intact = false
			}
			if pub != nil {
				switch {
				case e.Sig != "":
					signedSeen = true
					sig, err := base64.StdEncoding.DecodeString(e.Sig)
					if err != nil || !ed25519.Verify(pub, d[:], sig) {
						intact = false
					}
				case signedSeen:
					// A post-epoch entry lost its signature: downgrade tamper.
					intact = false
				}
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
