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

func TestVersioning(t *testing.T) {
	s := newStore(t)
	if err := s.Init(mustKey(t)); err != nil {
		t.Fatal(err)
	}
	for i, val := range []string{"v1", "v2", "v3"} {
		blob, err := s.Encrypt("p", []byte(val))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.PutVersionedRaw("p", blob, []string{"t1", "t2", "t3"}[i], 10); err != nil {
			t.Fatal(err)
		}
	}
	vers, err := s.ListVersions("p")
	if err != nil {
		t.Fatal(err)
	}
	if len(vers) != 3 || vers[0].Seq != 3 || vers[2].Seq != 1 {
		t.Fatalf("versions (newest first) wrong: %+v", vers)
	}
	b1, err := s.GetVersionRaw("p", 1)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := s.Decrypt("p", b1)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "v1" {
		t.Fatalf("version 1 = %q, want v1", pt)
	}
	if cur, _ := s.Get("p"); string(cur) != "v3" {
		t.Fatalf("current = %q, want v3", cur)
	}
}

func TestVersionPrune(t *testing.T) {
	s := newStore(t)
	if err := s.Init(mustKey(t)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 15; i++ {
		blob, _ := s.Encrypt("p", []byte{byte(i)})
		if err := s.PutVersionedRaw("p", blob, "t", 10); err != nil {
			t.Fatal(err)
		}
	}
	vers, _ := s.ListVersions("p")
	if len(vers) != 10 {
		t.Fatalf("want 10 kept, got %d", len(vers))
	}
	if vers[0].Seq != 15 || vers[9].Seq != 6 {
		t.Fatalf("prune kept wrong range: %d..%d", vers[0].Seq, vers[9].Seq)
	}
	if _, err := s.GetVersionRaw("p", 1); !errors.Is(err, ErrNotFound) {
		t.Fatal("version 1 should have been pruned")
	}
}

func TestDeleteClearsVersions(t *testing.T) {
	s := newStore(t)
	if err := s.Init(mustKey(t)); err != nil {
		t.Fatal(err)
	}
	blob, _ := s.Encrypt("p", []byte("x"))
	s.PutVersionedRaw("p", blob, "t", 10)
	if err := s.DeleteRaw("p"); err != nil {
		t.Fatal(err)
	}
	if vers, _ := s.ListVersions("p"); len(vers) != 0 {
		t.Fatalf("versions should be cleared, got %d", len(vers))
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
