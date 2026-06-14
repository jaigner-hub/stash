// Package store is stash's encrypted-at-rest key/value store.
//
// Values are sealed with a data-encryption key (DEK). The DEK is itself sealed
// with a key-encryption key (KEK) and persisted in wrapped form. The KEK never
// touches the database: it is supplied at Unseal (in production, decrypted from
// SOPS to tmpfs at deploy). This is the envelope that lets the on-disk file —
// and the replicated Raft log/snapshots — be safely held by a node that cannot
// read it (the quorum witness).
//
// Under Raft, every write is encrypted ONCE on the leader and the resulting
// ciphertext is replicated verbatim (see the *Raw methods), so all replicas
// hold byte-identical state. Direct Put/Get/Delete remain for single-node use
// and tests.
package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/jaigner-hub/stash/internal/crypto"
	bolt "go.etcd.io/bbolt"
)

// MaxVersions is how many historical versions are kept per secret path.
const MaxVersions = 10

var (
	// ErrNotFound is returned by Get/Delete when a path has no value.
	ErrNotFound = errors.New("stash/store: not found")
	// ErrSealed is returned by data operations before Unseal succeeds.
	ErrSealed = errors.New("stash/store: sealed")
	// ErrAlreadyInit is returned by Init on an already-initialized store.
	ErrAlreadyInit = errors.New("stash/store: already initialized")
	// ErrNotInit is returned by Unseal before the store has been initialized.
	ErrNotInit = errors.New("stash/store: not initialized")
	// ErrUnseal is returned when the supplied KEK cannot unwrap the DEK.
	ErrUnseal = errors.New("stash/store: unseal failed (wrong key?)")
)

var (
	metaBucket       = []byte("meta")
	secretsBucket    = []byte("secrets")
	identitiesBucket = []byte("identities")
	versionsBucket   = []byte("versions")

	keyWrappedDEK = []byte("wrapped_dek")
	keyCanary     = []byte("canary")

	aadDEK    = []byte("stash/dek")
	aadCanary = []byte("stash/canary")
	canaryPT  = []byte("stash-unseal-ok")
)

// Store is a bbolt-backed encrypted KV store. The zero value is not usable;
// call Open. After Open it is sealed until Init or Unseal loads the DEK.
type Store struct {
	db  *bolt.DB
	dek []byte // nil while sealed
}

// Open opens (creating if needed) the bbolt database at path and ensures the
// required buckets exist. The returned store is sealed.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("stash/store: open %s: %w", path, err)
	}
	if err := ensureBuckets(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func ensureBuckets(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{metaBucket, secretsBucket, identitiesBucket, versionsBucket} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
}

// Initialized reports whether the store has been set up (a wrapped DEK exists).
func (s *Store) Initialized() (bool, error) {
	var ok bool
	err := s.db.View(func(tx *bolt.Tx) error {
		ok = tx.Bucket(metaBucket).Get(keyWrappedDEK) != nil
		return nil
	})
	return ok, err
}

// Sealed reports whether the store currently lacks a usable DEK.
func (s *Store) Sealed() bool { return s.dek == nil }

// Init generates a fresh DEK, seals it under kek, and persists the wrapped DEK
// plus an encryption canary. It fails with ErrAlreadyInit if already set up. On
// success the store is left unsealed. This is the single-node path; the Raft
// path uses NewInitBlobs + PutMeta so the material flows through the log.
func (s *Store) Init(kek []byte) error {
	switch init, err := s.Initialized(); {
	case err != nil:
		return err
	case init:
		return ErrAlreadyInit
	}
	wrapped, canary, dek, err := newInitBlobsWithDEK(kek)
	if err != nil {
		return err
	}
	if err := s.PutMeta(wrapped, canary); err != nil {
		return err
	}
	s.dek = dek
	return nil
}

// Unseal loads and unwraps the DEK using kek, then confirms it against the
// canary before trusting it. After Unseal returns nil, data operations work.
func (s *Store) Unseal(kek []byte) error {
	var wrapped, canary []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		m := tx.Bucket(metaBucket)
		wrapped = append([]byte(nil), m.Get(keyWrappedDEK)...)
		canary = append([]byte(nil), m.Get(keyCanary)...)
		return nil
	})
	if err != nil {
		return err
	}
	if len(wrapped) == 0 {
		return ErrNotInit
	}
	dek, err := crypto.Open(kek, wrapped, aadDEK)
	if err != nil {
		return ErrUnseal
	}
	// The DEK unwrapped, but verify it actually decrypts known data before we
	// start serving with it.
	if pt, err := crypto.Open(dek, canary, aadCanary); err != nil || !bytes.Equal(pt, canaryPT) {
		return ErrUnseal
	}
	s.dek = dek
	return nil
}

// Encrypt seals value for path using the in-memory DEK. Requires unseal.
func (s *Store) Encrypt(path string, value []byte) ([]byte, error) {
	if s.Sealed() {
		return nil, ErrSealed
	}
	return crypto.Seal(s.dek, value, valueAAD(path))
}

// Decrypt opens a stored blob for path using the in-memory DEK. Requires unseal.
func (s *Store) Decrypt(path string, blob []byte) ([]byte, error) {
	if s.Sealed() {
		return nil, ErrSealed
	}
	return crypto.Open(s.dek, blob, valueAAD(path))
}

// --- Raw operations: ciphertext in, ciphertext out. Do NOT require unseal, so
// a sealed witness can still replicate the Raft log. ---

// PutRaw stores a pre-encrypted blob verbatim.
func (s *Store) PutRaw(path string, blob []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(secretsBucket).Put([]byte(path), blob)
	})
}

// GetRaw returns the raw stored blob for path, or ErrNotFound.
func (s *Store) GetRaw(path string) ([]byte, error) {
	var blob []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(secretsBucket).Get([]byte(path)); v != nil {
			blob = append([]byte(nil), v...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if blob == nil {
		return nil, ErrNotFound
	}
	return blob, nil
}

// DeleteRaw removes path and all its versions. Idempotent.
func (s *Store) DeleteRaw(path string) error {
	pfx := versionPrefix(path)
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(secretsBucket).Delete([]byte(path)); err != nil {
			return err
		}
		vb := tx.Bucket(versionsBucket)
		c := vb.Cursor()
		var keys [][]byte
		for k, _ := c.Seek(pfx); k != nil && bytes.HasPrefix(k, pfx); k, _ = c.Next() {
			keys = append(keys, append([]byte(nil), k...))
		}
		for _, k := range keys {
			if err := vb.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// VersionMeta describes one historical version (no value).
type VersionMeta struct {
	Seq  uint64 `json:"seq"`
	Time string `json:"time"`
}

type versionRecord struct {
	Time string `json:"t"`
	Blob []byte `json:"b"`
}

// version keys are path + 0x00 + big-endian seq, so they sort by (path, seq).
func versionPrefix(path string) []byte { return append([]byte(path), 0) }

func versionKey(path string, seq uint64) []byte {
	k := versionPrefix(path)
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, seq)
	return append(k, b...)
}

// PutVersionedRaw sets the current value (ciphertext) and appends a new version
// stamped with ts, pruning to keepN most-recent versions. Used by the Raft FSM
// so every replica derives identical version sequences.
func (s *Store) PutVersionedRaw(path string, blob []byte, ts string, keepN int) error {
	rec, err := json.Marshal(versionRecord{Time: ts, Blob: blob})
	if err != nil {
		return err
	}
	pfx := versionPrefix(path)
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(secretsBucket).Put([]byte(path), blob); err != nil {
			return err
		}
		vb := tx.Bucket(versionsBucket)
		var maxSeq uint64
		var keys [][]byte
		c := vb.Cursor()
		for k, _ := c.Seek(pfx); k != nil && bytes.HasPrefix(k, pfx); k, _ = c.Next() {
			if seq := binary.BigEndian.Uint64(k[len(pfx):]); seq > maxSeq {
				maxSeq = seq
			}
			keys = append(keys, append([]byte(nil), k...))
		}
		if err := vb.Put(versionKey(path, maxSeq+1), rec); err != nil {
			return err
		}
		// keys is ascending by seq; drop the oldest beyond keepN (+1 for the new).
		if drop := len(keys) + 1 - keepN; drop > 0 {
			for i := 0; i < drop && i < len(keys); i++ {
				if err := vb.Delete(keys[i]); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ListVersions returns version metadata for path, newest first.
func (s *Store) ListVersions(path string) ([]VersionMeta, error) {
	pfx := versionPrefix(path)
	var out []VersionMeta
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(versionsBucket).Cursor()
		for k, v := c.Seek(pfx); k != nil && bytes.HasPrefix(k, pfx); k, v = c.Next() {
			var rec versionRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			out = append(out, VersionMeta{Seq: binary.BigEndian.Uint64(k[len(pfx):]), Time: rec.Time})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq > out[j].Seq })
	return out, nil
}

// GetVersionRaw returns the stored ciphertext for a specific version.
func (s *Store) GetVersionRaw(path string, seq uint64) ([]byte, error) {
	var blob []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(versionsBucket).Get(versionKey(path, seq))
		if v == nil {
			return nil
		}
		var rec versionRecord
		if err := json.Unmarshal(v, &rec); err != nil {
			return err
		}
		blob = rec.Blob
		return nil
	})
	if err != nil {
		return nil, err
	}
	if blob == nil {
		return nil, ErrNotFound
	}
	return blob, nil
}

// Exists reports whether path has a stored value. Does not require unseal.
func (s *Store) Exists(path string) (bool, error) {
	_, err := s.GetRaw(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}

// --- Identity records (token hashes + policies). Not encrypted (no plaintext
// secret material), replicated like everything else, usable while sealed. ---

// PutIdentityRaw stores an identity record (JSON) keyed by name.
func (s *Store) PutIdentityRaw(name string, record []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(identitiesBucket).Put([]byte(name), record)
	})
}

// DeleteIdentityRaw removes an identity, returning ErrNotFound if absent.
func (s *Store) DeleteIdentityRaw(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(identitiesBucket)
		if b.Get([]byte(name)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(name))
	})
}

// ListIdentitiesRaw returns all identity records keyed by name.
func (s *Store) ListIdentitiesRaw() (map[string][]byte, error) {
	out := map[string][]byte{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(identitiesBucket).ForEach(func(k, v []byte) error {
			out[string(k)] = append([]byte(nil), v...)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PutMeta persists the wrapped DEK + canary. Used by the Raft FSM when applying
// an init command, and by single-node Init. Idempotent.
func (s *Store) PutMeta(wrappedDEK, canary []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		m := tx.Bucket(metaBucket)
		if err := m.Put(keyWrappedDEK, wrappedDEK); err != nil {
			return err
		}
		return m.Put(keyCanary, canary)
	})
}

// --- Convenience (single-node / tests): encrypt+store, fetch+decrypt. ---

// Put encrypts value (bound to path) and stores it. Requires unseal.
func (s *Store) Put(path string, value []byte) error {
	blob, err := s.Encrypt(path, value)
	if err != nil {
		return err
	}
	return s.PutRaw(path, blob)
}

// Get returns the decrypted value at path, or ErrNotFound. Requires unseal.
func (s *Store) Get(path string) ([]byte, error) {
	if s.Sealed() {
		return nil, ErrSealed
	}
	blob, err := s.GetRaw(path)
	if err != nil {
		return nil, err
	}
	return s.Decrypt(path, blob)
}

// Delete removes path, returning ErrNotFound if it was absent. Requires unseal.
func (s *Store) Delete(path string) error {
	if s.Sealed() {
		return ErrSealed
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(secretsBucket)
		if b.Get([]byte(path)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(path))
	})
}

// List returns all secret paths in sorted (byte) order. Values are not
// decrypted, so this works while sealed.
func (s *Store) List() ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(secretsBucket).ForEach(func(k, _ []byte) error {
			out = append(out, string(k))
			return nil
		})
	})
	return out, err
}

// --- Snapshot support for the Raft FSM. ---

// Snapshot is a point-in-time copy of all persisted state. Secret values stay
// encrypted (ciphertext blobs), so snapshots shipped to a witness leak nothing.
type Snapshot struct {
	WrappedDEK []byte            `json:"wrapped_dek"`
	Canary     []byte            `json:"canary"`
	Secrets    map[string][]byte `json:"secrets"`
	Identities map[string][]byte `json:"identities"`
	// Versions use binary keys (path\0seq), so they can't be JSON map keys;
	// store them as explicit key/value pairs ([]byte marshals as base64).
	Versions []KV `json:"versions"`
}

// KV is a raw key/value pair used for snapshotting buckets with binary keys.
type KV struct {
	K []byte `json:"k"`
	V []byte `json:"v"`
}

// Export captures the full store state for a Raft snapshot.
func (s *Store) Export() (*Snapshot, error) {
	snap := &Snapshot{Secrets: map[string][]byte{}, Identities: map[string][]byte{}}
	err := s.db.View(func(tx *bolt.Tx) error {
		m := tx.Bucket(metaBucket)
		snap.WrappedDEK = append([]byte(nil), m.Get(keyWrappedDEK)...)
		snap.Canary = append([]byte(nil), m.Get(keyCanary)...)
		if err := tx.Bucket(secretsBucket).ForEach(func(k, v []byte) error {
			snap.Secrets[string(k)] = append([]byte(nil), v...)
			return nil
		}); err != nil {
			return err
		}
		if err := tx.Bucket(identitiesBucket).ForEach(func(k, v []byte) error {
			snap.Identities[string(k)] = append([]byte(nil), v...)
			return nil
		}); err != nil {
			return err
		}
		return tx.Bucket(versionsBucket).ForEach(func(k, v []byte) error {
			snap.Versions = append(snap.Versions, KV{
				K: append([]byte(nil), k...),
				V: append([]byte(nil), v...),
			})
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return snap, nil
}

// Import replaces all store state from a Raft snapshot.
func (s *Store) Import(snap *Snapshot) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket(secretsBucket); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
			return err
		}
		sb, err := tx.CreateBucket(secretsBucket)
		if err != nil {
			return err
		}
		for k, v := range snap.Secrets {
			if err := sb.Put([]byte(k), v); err != nil {
				return err
			}
		}
		if err := tx.DeleteBucket(identitiesBucket); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
			return err
		}
		ib, err := tx.CreateBucket(identitiesBucket)
		if err != nil {
			return err
		}
		for k, v := range snap.Identities {
			if err := ib.Put([]byte(k), v); err != nil {
				return err
			}
		}
		if err := tx.DeleteBucket(versionsBucket); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
			return err
		}
		vb, err := tx.CreateBucket(versionsBucket)
		if err != nil {
			return err
		}
		for _, kv := range snap.Versions {
			if err := vb.Put(kv.K, kv.V); err != nil {
				return err
			}
		}
		if len(snap.WrappedDEK) > 0 {
			m := tx.Bucket(metaBucket)
			if err := m.Put(keyWrappedDEK, snap.WrappedDEK); err != nil {
				return err
			}
			if err := m.Put(keyCanary, snap.Canary); err != nil {
				return err
			}
		}
		return nil
	})
}

// Close drops the in-memory DEK and releases the database.
func (s *Store) Close() error {
	s.dek = nil
	return s.db.Close()
}

// NewInitBlobs generates a fresh DEK, wraps it under kek, and produces the
// verification canary — without touching any store. The Raft bootstrap path
// submits these as an init command so the DEK material flows through the log to
// every replica (including a sealed witness).
func NewInitBlobs(kek []byte) (wrappedDEK, canary []byte, err error) {
	wrappedDEK, canary, _, err = newInitBlobsWithDEK(kek)
	return wrappedDEK, canary, err
}

func newInitBlobsWithDEK(kek []byte) (wrappedDEK, canary, dek []byte, err error) {
	if len(kek) != crypto.KeyLen {
		return nil, nil, nil, fmt.Errorf("stash/store: kek must be %d bytes", crypto.KeyLen)
	}
	dek, err = crypto.GenerateKey()
	if err != nil {
		return nil, nil, nil, err
	}
	wrappedDEK, err = crypto.Seal(kek, dek, aadDEK)
	if err != nil {
		return nil, nil, nil, err
	}
	canary, err = crypto.Seal(dek, canaryPT, aadCanary)
	if err != nil {
		return nil, nil, nil, err
	}
	return wrappedDEK, canary, dek, nil
}

func valueAAD(path string) []byte { return []byte("secret:" + path) }
