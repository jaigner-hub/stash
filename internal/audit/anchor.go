package audit

// Trusted timestamping (feature-flagged, off by default).
//
// Hash-chaining + Ed25519 signatures make the log tamper-evident against an
// outsider without the signing key. They do nothing against a malicious key
// holder who also controls the clock: holding audit.key, that attacker can
// rewrite every entry, set every Time, recompute every Hash, and re-sign the
// chain. Self-asserted Time is worthless against them.
//
// Anchoring closes the backdating half of that gap. Periodically the current
// chain head hash is sent to an external, append-only, time-bearing authority
// (here an RFC 3161 Time-Stamp Authority) which returns a signed token proving
// "this hash existed no later than T". Because the chain is hash-linked,
// anchoring the head transitively timestamps every prior entry. The attacker
// cannot forge the TSA's signature, so they cannot produce a token over a
// rewritten head dated at the old time — the best they can do is present a log
// with missing/younger anchor coverage, which a verifier expecting anchors at a
// known cadence flags. Anchoring cadence sets the backdating resolution.
//
// Privacy: only the 32-byte head hash is ever sent to the TSA — never entry
// contents, paths, identities, or plaintext. Verification (VerifyAnchors) is
// deterministic and fully offline given the TSA's trust root.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/digitorus/timestamp"
	bolt "go.etcd.io/bbolt"
)

// anchorBucket holds Anchor records keyed by big-endian HeadSeq, in the same
// audit.db but separate from the entry chain — anchoring never touches entry
// serialization, so the existing chain/signature verification is unaffected.
var anchorBucket = []byte("anchors")

func u64key(n uint64) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, n)
	return k
}

// Anchor binds the chain head at HeadSeq (hash HeadHash) to an external trusted
// timestamp. It proves every entry with seq <= HeadSeq existed no later than the
// token's genTime.
type Anchor struct {
	HeadSeq  uint64 `json:"head_seq"`
	HeadHash string `json:"head_hash"` // hex SHA-256; equals entry[HeadSeq].Hash
	Backend  string `json:"backend"`   // e.g. "rfc3161:https://tsa.example/tsr"
	Time     string `json:"time"`      // TSA genTime, RFC3339Nano (re-derived on verify)
	Token    []byte `json:"token"`     // DER RFC 3161 response token
}

// Anchorer turns the chain head hash into an external, time-bearing proof token.
// Implementations must transmit only the hash, and the token must be verifiable
// offline (given a trust root) so VerifyAnchors needs no network.
type Anchorer interface {
	Stamp(ctx context.Context, headHash []byte) (token []byte, genTime time.Time, backend string, err error)
}

// TSAAnchorer anchors to an RFC 3161 Time-Stamp Authority over HTTP. It sends a
// timestamp query whose message imprint is SHA-256 of the head hash and returns
// the authority's signed response token verbatim.
type TSAAnchorer struct {
	URL  string
	HTTP *http.Client // nil → http.DefaultClient
}

// Stamp implements Anchorer against an RFC 3161 TSA.
func (a *TSAAnchorer) Stamp(ctx context.Context, headHash []byte) ([]byte, time.Time, string, error) {
	reqDER, err := timestamp.CreateRequest(bytes.NewReader(headHash), &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true, // ask the TSA to embed its cert so the token self-verifies offline
	})
	if err != nil {
		return nil, time.Time{}, "", fmt.Errorf("audit: build TSA request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, time.Time{}, "", err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	client := a.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, time.Time{}, "", fmt.Errorf("audit: TSA request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, time.Time{}, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, "", fmt.Errorf("audit: TSA HTTP %d", resp.StatusCode)
	}
	ts, err := timestamp.ParseResponse(body)
	if err != nil {
		return nil, time.Time{}, "", fmt.Errorf("audit: parse TSA response: %w", err)
	}
	want := sha256.Sum256(headHash)
	if !bytes.Equal(ts.HashedMessage, want[:]) {
		return nil, time.Time{}, "", fmt.Errorf("audit: TSA imprint does not match head hash")
	}
	return body, ts.Time, "rfc3161:" + a.URL, nil
}

// Anchor stamps the current chain head with a and persists the resulting Anchor
// in audit.db. It is a no-op (nil, nil) on an empty log. The network round-trip
// happens outside the db lock; the head is snapshotted under the lock, and since
// entries are immutable the snapshot stays valid.
func (l *Log) Anchor(ctx context.Context, a Anchorer) (*Anchor, error) {
	l.mu.Lock()
	headSeq, headHashHex := l.seq, l.last
	l.mu.Unlock()
	if headSeq == 0 {
		return nil, nil // nothing to anchor yet
	}
	headBytes, err := hex.DecodeString(headHashHex)
	if err != nil {
		return nil, fmt.Errorf("audit: decode head hash: %w", err)
	}
	token, genTime, backend, err := a.Stamp(ctx, headBytes)
	if err != nil {
		return nil, err
	}
	anc := &Anchor{
		HeadSeq:  headSeq,
		HeadHash: headHashHex,
		Backend:  backend,
		Time:     genTime.UTC().Format(time.RFC3339Nano),
		Token:    token,
	}
	rec, err := json.Marshal(anc)
	if err != nil {
		return nil, err
	}
	if err := l.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(anchorBucket)
		if err != nil {
			return err
		}
		return b.Put(u64key(headSeq), rec)
	}); err != nil {
		return nil, err
	}
	return anc, nil
}

// Anchors returns all stored anchors, oldest first.
func (l *Log) Anchors() ([]Anchor, error) {
	out := []Anchor{}
	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(anchorBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var a Anchor
			if err := json.Unmarshal(v, &a); err != nil {
				return err
			}
			out = append(out, a)
			return nil
		})
	})
	return out, err
}

// AnchorResult is the per-anchor outcome of VerifyAnchors.
type AnchorResult struct {
	HeadSeq  uint64    `json:"head_seq"`
	HeadHash string    `json:"head_hash"`
	Time     time.Time `json:"time"` // proven upper bound (TSA genTime) when OK
	OK       bool      `json:"ok"`
	Err      string    `json:"err,omitempty"`
}

// VerifyAnchors re-checks every stored anchor offline against roots (trusted TSA
// root certs). For each anchor it confirms: the entry still present at HeadSeq
// hashes to the anchored head, the token's message imprint commits to that head,
// and the token chains to a trusted root with the timestamping EKU. No network.
//
// This is additive to Verify: it neither calls nor changes the chain/signature
// check, so a log with no anchors (or anchoring disabled) behaves exactly as
// before. Run Verify for chain integrity and VerifyAnchors for time proofs.
func (l *Log) VerifyAnchors(roots *x509.CertPool) ([]AnchorResult, error) {
	out := []AnchorResult{}
	err := l.db.View(func(tx *bolt.Tx) error {
		ab := tx.Bucket(anchorBucket)
		if ab == nil {
			return nil
		}
		entries := tx.Bucket(bucket)
		c := ab.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var a Anchor
			if err := json.Unmarshal(v, &a); err != nil {
				return err
			}
			res := AnchorResult{HeadSeq: a.HeadSeq, HeadHash: a.HeadHash}
			if t, err := verifyAnchor(entries, a, roots); err != nil {
				res.Err = err.Error()
			} else {
				res.OK = true
				res.Time = t
			}
			out = append(out, res)
		}
		return nil
	})
	return out, err
}

func verifyAnchor(entries *bolt.Bucket, a Anchor, roots *x509.CertPool) (time.Time, error) {
	// 1. The anchored head still matches the entry at that seq.
	if entries == nil {
		return time.Time{}, fmt.Errorf("no entries bucket")
	}
	ev := entries.Get(u64key(a.HeadSeq))
	if ev == nil {
		return time.Time{}, fmt.Errorf("no entry at head seq %d", a.HeadSeq)
	}
	var e Entry
	if err := json.Unmarshal(ev, &e); err != nil {
		return time.Time{}, err
	}
	if e.Hash != a.HeadHash {
		return time.Time{}, fmt.Errorf("head hash mismatch at seq %d", a.HeadSeq)
	}
	// 2. Parse + CMS-verify the token (ParseResponse checks the signature).
	ts, err := timestamp.ParseResponse(a.Token)
	if err != nil {
		return time.Time{}, fmt.Errorf("token: %w", err)
	}
	// 3. The token's imprint commits to the head hash.
	headBytes, err := hex.DecodeString(a.HeadHash)
	if err != nil {
		return time.Time{}, err
	}
	want := sha256.Sum256(headBytes)
	if ts.HashAlgorithm != crypto.SHA256 || !bytes.Equal(ts.HashedMessage, want[:]) {
		return time.Time{}, fmt.Errorf("token imprint does not match head hash")
	}
	// 4. Trust: the signer chains to a pinned root with the timestamping EKU.
	if err := chainToRoot(ts.Certificates, roots, ts.Time); err != nil {
		return time.Time{}, fmt.Errorf("token trust: %w", err)
	}
	return ts.Time, nil
}

func chainToRoot(certs []*x509.Certificate, roots *x509.CertPool, at time.Time) error {
	if roots == nil {
		return fmt.Errorf("no trust roots configured")
	}
	var leaf *x509.Certificate
	inter := x509.NewCertPool()
	for _, c := range certs {
		if leaf == nil && hasTimestampingEKU(c) && !c.IsCA {
			leaf = c
			continue
		}
		inter.AddCert(c)
	}
	if leaf == nil {
		return fmt.Errorf("no timestamping signer certificate in token")
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	})
	return err
}

func hasTimestampingEKU(c *x509.Certificate) bool {
	for _, eku := range c.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			return true
		}
	}
	return false
}
