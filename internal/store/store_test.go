package store

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/jaigner-hub/stash/internal/crypto"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "stash.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestInitAndCRUD(t *testing.T) {
	s := newStore(t)
	if err := s.Init(mustKey(t)); err != nil {
		t.Fatal(err)
	}
	if s.Sealed() {
		t.Fatal("store should be unsealed after Init")
	}

	if err := s.Put("kg/web/SECRET_KEY", []byte("abc123")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("kg/web/SECRET_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc123" {
		t.Fatalf("got %q", got)
	}

	if _, err := s.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	if err := s.Delete("kg/web/SECRET_KEY"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("kg/web/SECRET_KEY"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
	if err := s.Delete("kg/web/SECRET_KEY"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound deleting twice, got %v", err)
	}
}

func TestInitTwiceFails(t *testing.T) {
	s := newStore(t)
	kek := mustKey(t)
	if err := s.Init(kek); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(kek); !errors.Is(err, ErrAlreadyInit) {
		t.Fatalf("want ErrAlreadyInit, got %v", err)
	}
}

func TestUnsealRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stash.db")
	kek := mustKey(t)

	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Init(kek); err != nil {
		t.Fatal(err)
	}
	if err := s1.Put("k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	s1.Close()

	// Reopen: must be sealed until Unseal.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if !s2.Sealed() {
		t.Fatal("reopened store must be sealed")
	}
	if _, err := s2.Get("k"); !errors.Is(err, ErrSealed) {
		t.Fatalf("want ErrSealed, got %v", err)
	}
	if err := s2.Unseal(kek); err != nil {
		t.Fatal(err)
	}
	got, err := s2.Get("k")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v" {
		t.Fatalf("got %q", got)
	}
}

func TestUnsealWrongKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stash.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Init(mustKey(t)); err != nil {
		t.Fatal(err)
	}
	s1.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.Unseal(mustKey(t)); !errors.Is(err, ErrUnseal) {
		t.Fatalf("want ErrUnseal, got %v", err)
	}
}

func TestUnsealNotInitialized(t *testing.T) {
	s := newStore(t)
	if err := s.Unseal(mustKey(t)); !errors.Is(err, ErrNotInit) {
		t.Fatalf("want ErrNotInit, got %v", err)
	}
}

func TestList(t *testing.T) {
	s := newStore(t)
	if err := s.Init(mustKey(t)); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"b", "a", "c"} {
		if err := s.Put(p, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a", "b", "c"} // bbolt iterates in sorted order
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}
