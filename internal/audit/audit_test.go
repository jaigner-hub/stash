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

func TestPage(t *testing.T) {
	l, _ := newLog(t)
	for i := 0; i < 10; i++ {
		if err := l.Record("a", "read", "p", "ok"); err != nil {
			t.Fatal(err)
		}
	}
	// First page: newest 4 (seq 10..7).
	p1, err := l.Page(0, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(p1) != 4 || p1[0].Seq != 10 || p1[3].Seq != 7 {
		t.Fatalf("page1 wrong: %v", seqs(p1))
	}
	// Next page: before the oldest of p1 (seq 7) -> 6..3.
	p2, err := l.Page(p1[len(p1)-1].Seq, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(p2) != 4 || p2[0].Seq != 6 || p2[3].Seq != 3 {
		t.Fatalf("page2 wrong: %v", seqs(p2))
	}
	// Final page: 2..1.
	p3, _ := l.Page(p2[len(p2)-1].Seq, 4)
	if len(p3) != 2 || p3[0].Seq != 2 || p3[1].Seq != 1 {
		t.Fatalf("page3 wrong: %v", seqs(p3))
	}
}

func seqs(es []Entry) []uint64 {
	out := make([]uint64, len(es))
	for i, e := range es {
		out[i] = e.Seq
	}
	return out
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

func TestStreamSinkReceivesEntries(t *testing.T) {
	l, _ := newLog(t)
	var got []Entry
	l.Stream(func(e Entry) { got = append(got, e) })

	if err := l.Record("alice", "read", "kg/web/A", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := l.Record("bob", "write", "kg/web/B", "denied"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("sink got %d entries, want 2", len(got))
	}
	// The sink sees the fully-formed, persisted entry (seq, node, hash chained).
	if got[0].Seq != 1 || got[0].Identity != "alice" || got[0].Hash == "" {
		t.Fatalf("entry 0 malformed: %+v", got[0])
	}
	if got[1].Seq != 2 || got[1].PrevHash != got[0].Hash {
		t.Fatalf("entry 1 not chained: prev=%s want=%s", got[1].PrevHash, got[0].Hash)
	}
	// Disabling the sink stops delivery.
	l.Stream(nil)
	if err := l.Record("carol", "list", "", "ok"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("sink still received after nil: %d", len(got))
	}
}
