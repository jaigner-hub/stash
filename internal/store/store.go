// Package store is stash's encrypted-at-rest key/value store.
//
// Values are sealed with a data-encryption key (DEK). The DEK is itself sealed
// with a key-encryption key (KEK) and persisted in wrapped form. The KEK never
// touches the database: it is supplied at Unseal (in production, decrypted from
// SOPS to tmpfs at deploy). This is the envelope that lets the on-disk file —
// and, later, the replicated Raft log — be safely held by a node that cannot
// read it (e.g. the quorum witness).
package store

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/jaigner-hub/stash/internal/crypto"
	bolt "go.etcd.io/bbolt"
)

var (
	// ErrNotFound is returned by Get/Delete when a path has no value.
	ErrNotFound = errors.New("stash/store: not found")
	// ErrSealed is returned by data operations before Unseal succeeds.
	ErrSealed = errors.New("stash/store: sealed")
	// ErrAlreadyInit is returned by Init on an already-initialized store.
	ErrAlreadyInit = errors.New("stash/store: already initialized")
	// ErrNotInit is returned by Unseal before Init has ever run.
	ErrNotInit = errors.New("stash/store: not initialized")
	// ErrUnseal is returned when the supplied KEK cannot unwrap the DEK.
	ErrUnseal = errors.New("stash/store: unseal failed (wrong key?)")
)

var (
	metaBucket    = []byte("meta")
	secretsBucket = []byte("secrets")

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
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{metaBucket, secretsBucket} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("stash/store: init buckets: %w", err)
	}
	return &Store{db: db}, nil
}

// Initialized reports whether Init has run (a wrapped DEK is present).
func (s *Store) Initialized() (bool, error) {
	var ok bool
	err := s.db.View(func(tx *bolt.Tx) error {
		ok = tx.Bucket(metaBucket).Get(keyWrappedDEK) != nil
		return nil
	})
	return ok, err
}

// Init generates a fresh DEK, seals it under kek, and persists the wrapped DEK
// plus an encryption canary used to verify future unseals. It fails with
// ErrAlreadyInit if the store is already set up. On success the store is left
// unsealed and ready to use.
func (s *Store) Init(kek []byte) error {
	if len(kek) != crypto.KeyLen {
		return fmt.Errorf("stash/store: kek must be %d bytes", crypto.KeyLen)
	}
	switch init, err := s.Initialized(); {
	case err != nil:
		return err
	case init:
		return ErrAlreadyInit
	}

	dek, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	wrapped, err := crypto.Seal(kek, dek, aadDEK)
	if err != nil {
		return err
	}
	canary, err := crypto.Seal(dek, canaryPT, aadCanary)
	if err != nil {
		return err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		m := tx.Bucket(metaBucket)
		if err := m.Put(keyWrappedDEK, wrapped); err != nil {
			return err
		}
		return m.Put(keyCanary, canary)
	})
	if err != nil {
		return fmt.Errorf("stash/store: persist init: %w", err)
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

// Sealed reports whether the store currently lacks a usable DEK.
func (s *Store) Sealed() bool { return s.dek == nil }

// Put encrypts value under the DEK (bound to path via AAD) and stores it.
func (s *Store) Put(path string, value []byte) error {
	if s.Sealed() {
		return ErrSealed
	}
	blob, err := crypto.Seal(s.dek, value, valueAAD(path))
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(secretsBucket).Put([]byte(path), blob)
	})
}

// Get returns the decrypted value at path, or ErrNotFound.
func (s *Store) Get(path string) ([]byte, error) {
	if s.Sealed() {
		return nil, ErrSealed
	}
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
	return crypto.Open(s.dek, blob, valueAAD(path))
}

// Delete removes path, returning ErrNotFound if it was absent.
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

// List returns all secret paths. bbolt iterates keys in byte order, so the
// result is sorted. Values are never decrypted here.
func (s *Store) List() ([]string, error) {
	if s.Sealed() {
		return nil, ErrSealed
	}
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(secretsBucket).ForEach(func(k, _ []byte) error {
			out = append(out, string(k))
			return nil
		})
	})
	return out, err
}

// Close drops the in-memory DEK and releases the database.
func (s *Store) Close() error {
	s.dek = nil
	return s.db.Close()
}

func valueAAD(path string) []byte { return []byte("secret:" + path) }
