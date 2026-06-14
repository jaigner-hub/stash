package cluster

import (
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jaigner-hub/stash/internal/crypto"
	"github.com/jaigner-hub/stash/internal/store"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// newNode spins up an isolated node and returns it plus its raft and http addrs.
func newNode(t *testing.T, id string, bootstrap bool) (n *Node, raftAddr, httpAddr string) {
	return newNodeW(t, id, bootstrap, false)
}

func newNodeW(t *testing.T, id string, bootstrap, witness bool) (n *Node, raftAddr, httpAddr string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "stash.db"))
	if err != nil {
		t.Fatal(err)
	}
	raftAddr = freeAddr(t)
	httpAddr = "http://" + freeAddr(t)
	n, err = New(Config{
		NodeID: id, RaftAddr: raftAddr, HTTPAddr: httpAddr, DataDir: dir,
		Bootstrap: bootstrap, Witness: witness,
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close(); st.Close() })
	return n, raftAddr, httpAddr
}

func eventually(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition not met within", d)
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSingleNodeCRUD(t *testing.T) {
	kek := mustKey(t)
	n, _, _ := newNode(t, "n1", true)
	if _, err := n.Initialize(kek, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := n.Unseal(kek, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if !n.IsLeader() {
		t.Fatal("single bootstrapped node should be leader")
	}

	if err := n.Put("a/b", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	got, err := n.Get("a/b")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v1" {
		t.Fatalf("got %q", got)
	}
	if err := n.Delete("a/b"); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Get("a/b"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := n.Delete("a/b"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete missing: want ErrNotFound, got %v", err)
	}
}

func TestNodeVersioning(t *testing.T) {
	kek := mustKey(t)
	n, _, _ := newNode(t, "n1", true)
	if _, err := n.Initialize(kek, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := n.Unseal(kek, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := n.Put("p", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := n.Put("p", []byte("two")); err != nil {
		t.Fatal(err)
	}
	vers, err := n.ListVersions("p")
	if err != nil {
		t.Fatal(err)
	}
	if len(vers) != 2 {
		t.Fatalf("want 2 versions, got %d", len(vers))
	}
	old, err := n.GetVersion("p", vers[1].Seq) // newest-first, so [1] is the older
	if err != nil {
		t.Fatal(err)
	}
	if string(old) != "one" {
		t.Fatalf("old version = %q, want one", old)
	}
	if cur, _ := n.Get("p"); string(cur) != "two" {
		t.Fatalf("current = %q, want two", cur)
	}
}

// Re-writing the same value is idempotent: it must not create a new version
// (envelope encryption re-nonces every write, so the dedup compares plaintext).
func TestNodePutIsIdempotent(t *testing.T) {
	kek := mustKey(t)
	n, _, _ := newNode(t, "n1", true)
	if _, err := n.Initialize(kek, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := n.Unseal(kek, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := n.Put("p", []byte("same")); err != nil {
		t.Fatal(err)
	}
	// Three redundant writes of the identical value.
	for i := 0; i < 3; i++ {
		if err := n.Put("p", []byte("same")); err != nil {
			t.Fatal(err)
		}
	}
	vers, err := n.ListVersions("p")
	if err != nil {
		t.Fatal(err)
	}
	if len(vers) != 1 {
		t.Fatalf("redundant writes must not churn versions; want 1, got %d", len(vers))
	}
	// A genuine change still creates a version.
	if err := n.Put("p", []byte("changed")); err != nil {
		t.Fatal(err)
	}
	if vers, _ = n.ListVersions("p"); len(vers) != 2 {
		t.Fatalf("a real change should add a version; want 2, got %d", len(vers))
	}
}

func TestThreeNodeReplication(t *testing.T) {
	kek := mustKey(t)
	n1, _, h1 := newNode(t, "n1", true)
	if _, err := n1.Initialize(kek, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := n1.Unseal(kek, 10*time.Second); err != nil {
		t.Fatal(err)
	}

	n2, r2, h2 := newNode(t, "n2", false)
	n3, r3, h3 := newNode(t, "n3", false)
	if err := n1.Join("n2", r2, h2); err != nil {
		t.Fatal(err)
	}
	if err := n1.Join("n3", r3, h3); err != nil {
		t.Fatal(err)
	}
	if err := n2.Unseal(kek, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := n3.Unseal(kek, 15*time.Second); err != nil {
		t.Fatal(err)
	}

	if err := n1.Put("kg/web/SECRET", []byte("topsecret")); err != nil {
		t.Fatal(err)
	}

	// The write replicates to a follower.
	eventually(t, 10*time.Second, func() bool {
		v, err := n2.Get("kg/web/SECRET")
		return err == nil && string(v) == "topsecret"
	})

	// Writes on a follower are rejected (the HTTP server forwards in real use).
	if err := n2.Put("x", []byte("y")); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("follower Put: want ErrNotLeader, got %v", err)
	}
	// And a follower can locate the leader's API for forwarding.
	addr, ok := n2.LeaderHTTPAddr()
	if !ok || addr != h1 {
		t.Fatalf("leader http addr: got %q ok=%v want %q", addr, ok, h1)
	}
	_ = n3
}

// TestWitnessYieldsLeadership: with two keyed voters + one witness, killing the
// keyed leader must result in the OTHER keyed node leading (never the witness),
// and writes must keep working.
func TestWitnessYieldsLeadership(t *testing.T) {
	kek := mustKey(t)
	n1, _, _ := newNode(t, "n1", true)
	if _, err := n1.Initialize(kek, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := n1.Unseal(kek, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	n2, r2, h2 := newNode(t, "n2", false)
	w, rw, hw := newNodeW(t, "w", false, true)
	if err := n1.Join("n2", r2, h2); err != nil {
		t.Fatal(err)
	}
	if err := n1.Join("w", rw, hw); err != nil {
		t.Fatal(err)
	}
	if err := n2.Unseal(kek, 15*time.Second); err != nil {
		t.Fatal(err)
	}

	// Kill the keyed leader n1; quorum survives as n2 + witness.
	n1.Close()

	// The witness must not end up leader — n2 should.
	eventually(t, 25*time.Second, func() bool { return n2.IsLeader() })
	if w.IsLeader() {
		t.Fatal("witness should never remain leader")
	}
	// And the surviving cluster can still serve writes.
	if err := n2.Put("after", []byte("ok")); err != nil {
		t.Fatalf("write after failover: %v", err)
	}
}

func TestWitnessReplicatesButCannotRead(t *testing.T) {
	kek := mustKey(t)
	n1, _, _ := newNode(t, "n1", true)
	if _, err := n1.Initialize(kek, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := n1.Unseal(kek, 10*time.Second); err != nil {
		t.Fatal(err)
	}

	// Witness joins but is never given the key.
	w, rw, hw := newNode(t, "w", false)
	if err := n1.Join("w", rw, hw); err != nil {
		t.Fatal(err)
	}
	if err := n1.Put("a", []byte("secret")); err != nil {
		t.Fatal(err)
	}

	// It replicates the ciphertext...
	eventually(t, 10*time.Second, func() bool {
		_, err := w.store.GetRaw("a")
		return err == nil
	})
	// ...but stays sealed and cannot read plaintext.
	if !w.Sealed() {
		t.Fatal("witness should be sealed")
	}
	if _, err := w.Get("a"); !errors.Is(err, store.ErrSealed) {
		t.Fatalf("witness Get: want ErrSealed, got %v", err)
	}
}
