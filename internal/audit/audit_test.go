package audit

import (
	"encoding/binary"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func newLog(t *testing.T) (*Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := Open(path, "node1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

func TestAppendAndVerify(t *testing.T) {
	l, _ := newLog(t)
	for i := 0; i < 5; i++ {
		if err := l.Record("root", "read", "kg/web/X", "ok"); err != nil {
			t.Fatal(err)
		}
	}
	intact, count, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !intact || count != 5 {
		t.Fatalf("verify: intact=%v count=%d", intact, count)
	}

	recent, err := l.Recent(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 3 {
		t.Fatalf("want 3 recent, got %d", len(recent))
	}
	// Newest first: seq should descend 5,4,3.
	if recent[0].Seq != 5 || recent[2].Seq != 3 {
		t.Fatalf("ordering wrong: %d..%d", recent[0].Seq, recent[2].Seq)
	}
}

func TestChainContinuesAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	l1, err := Open(path, "node1")
	if err != nil {
		t.Fatal(err)
	}
	l1.Record("a", "write", "p", "ok")
	l1.Record("a", "write", "p", "ok")
	l1.Close()

	l2, err := Open(path, "node1")
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if err := l2.Record("a", "write", "p", "ok"); err != nil {
		t.Fatal(err)
	}
	intact, count, err := l2.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !intact || count != 3 {
		t.Fatalf("after reopen: intact=%v count=%d", intact, count)
	}
}

func TestTamperBreaksChain(t *testing.T) {
	l, _ := newLog(t)
	l.Record("a", "read", "p1", "ok")
	l.Record("a", "read", "p2", "ok")
	l.Record("a", "read", "p3", "ok")

	// Tamper with entry #2 directly in the db, behind the log's back.
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, 2)
	if err := l.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Put(key, []byte(`{"seq":2,"action":"read","path":"EVIL","result":"ok","hash":"x"}`))
	}); err != nil {
		t.Fatal(err)
	}
	intact, _, err := l.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if intact {
		t.Fatal("tampering should break the chain")
	}
}
