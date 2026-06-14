package audit

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

// fakeTSA is a fully local RFC 3161 authority: it stamps requests with a fixed
// genTime using a CA-issued timestamping cert, so anchoring + verification run
// offline and deterministically.
type fakeTSA struct {
	srv     *httptest.Server
	roots   *x509.CertPool
	genTime time.Time
}

func newFakeTSA(t *testing.T, genTime time.Time) *fakeTSA {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake-tsa-ca"},
		NotBefore:             genTime.Add(-time.Hour),
		NotAfter:              genTime.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "fake-tsa-signer"},
		NotBefore:    genTime.Add(-time.Hour),
		NotAfter:     genTime.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ts := &timestamp.Timestamp{
			HashAlgorithm:     req.HashAlgorithm,
			HashedMessage:     req.HashedMessage,
			Time:              genTime,
			Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
			Certificates:      []*x509.Certificate{caCert}, // parent chain (signer leaf added by the lib)
			AddTSACertificate: true,
		}
		resp, err := ts.CreateResponse(leafCert, leafKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(resp)
	}))
	t.Cleanup(srv.Close)

	return &fakeTSA{srv: srv, roots: roots, genTime: genTime}
}

func (f *fakeTSA) anchorer() *TSAAnchorer {
	return &TSAAnchorer{URL: f.srv.URL, HTTP: f.srv.Client()}
}

func TestAnchorAndVerify(t *testing.T) {
	l, _ := newSignedLog(t)
	for i := 0; i < 3; i++ {
		if err := l.Record("root", "read", "kg/web/X", "ok"); err != nil {
			t.Fatal(err)
		}
	}
	genTime := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	tsa := newFakeTSA(t, genTime)

	anc, err := l.Anchor(context.Background(), tsa.anchorer())
	if err != nil {
		t.Fatal(err)
	}
	if anc == nil || anc.HeadSeq != 3 {
		t.Fatalf("anchor: %+v", anc)
	}

	results, err := l.VerifyAnchors(tsa.roots)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].OK {
		t.Fatalf("verify anchors: %+v", results)
	}
	if !results[0].Time.Equal(genTime) {
		t.Fatalf("proven time = %v, want %v", results[0].Time, genTime)
	}
	// The chain check is untouched and still passes.
	if intact, _, _ := l.Verify(); !intact {
		t.Fatal("chain verify should still pass after anchoring")
	}
}

// A malicious key holder rewrites the anchored head entry and re-signs it. The
// chain alone would accept it, but the external anchor pinned the original head
// hash — VerifyAnchors detects the mismatch.
func TestAnchorDetectsRewrittenHead(t *testing.T) {
	l, _ := newSignedLog(t)
	l.Record("a", "read", "p1", "ok")
	l.Record("a", "read", "p2", "ok")
	l.Record("a", "read", "p3", "ok")

	tsa := newFakeTSA(t, time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC))
	if _, err := l.Anchor(context.Background(), tsa.anchorer()); err != nil {
		t.Fatal(err)
	}

	// Rewrite entry #3 (the anchored head) with a fresh, internally-consistent
	// hash — exactly what a key holder who controls audit.key could produce.
	entries, _ := l.Page(0, 10)
	var head Entry
	for _, e := range entries {
		if e.Seq == 3 {
			head = e
		}
	}
	head.Path = "EVIL"
	d := entryDigest(head)
	head.Hash = hex.EncodeToString(d[:])
	putEntry(t, l, head)

	results, err := l.VerifyAnchors(tsa.roots)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].OK {
		t.Fatalf("anchor over a rewritten head should fail: %+v", results)
	}
}

// An anchor token that does not chain to the configured trust roots is rejected.
func TestAnchorRejectsUntrustedRoot(t *testing.T) {
	l, _ := newSignedLog(t)
	l.Record("a", "read", "p1", "ok")
	tsa := newFakeTSA(t, time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC))
	if _, err := l.Anchor(context.Background(), tsa.anchorer()); err != nil {
		t.Fatal(err)
	}

	// Verify against an unrelated (empty) root pool.
	results, err := l.VerifyAnchors(x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].OK {
		t.Fatalf("anchor under a foreign root should fail trust: %+v", results)
	}
}

// Verification works on a read-only reopen (the mode `stash audit verify` uses),
// so a stopped node or an off-host copy can be checked without the writer lock.
func TestReadOnlyVerify(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadOrCreateKey(filepath.Join(dir, "audit.key"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit.db")
	l, err := Open(path, "node1", WithSigningKey(key))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		l.Record("root", "read", "kg/web/X", "ok")
	}
	tsa := newFakeTSA(t, time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC))
	if _, err := l.Anchor(context.Background(), tsa.anchorer()); err != nil {
		t.Fatal(err)
	}
	l.Close() // release the writer lock

	ro, err := Open(path, "", WithReadOnly(), WithSigningKey(key))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if intact, count, _ := ro.Verify(); !intact || count != 3 {
		t.Fatalf("read-only chain verify: intact=%v count=%d", intact, count)
	}
	results, err := ro.VerifyAnchors(tsa.roots)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].OK {
		t.Fatalf("read-only anchor verify: %+v", results)
	}
}

func TestAnchorEmptyLogIsNoop(t *testing.T) {
	l, _ := newSignedLog(t)
	tsa := newFakeTSA(t, time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC))
	anc, err := l.Anchor(context.Background(), tsa.anchorer())
	if err != nil {
		t.Fatal(err)
	}
	if anc != nil {
		t.Fatalf("anchoring an empty log should be a no-op, got %+v", anc)
	}
}
