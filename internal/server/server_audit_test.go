package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jaigner-hub/stash/internal/audit"
)

type fakeAuditor struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (a *fakeAuditor) Record(identity, action, path, result string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, audit.Entry{Identity: identity, Action: action, Path: path, Result: result})
	return nil
}
func (a *fakeAuditor) Page(before uint64, n int) ([]audit.Entry, error) { return a.entries, nil }
func (a *fakeAuditor) Verify() (bool, uint64, error)                    { return true, uint64(len(a.entries)), nil }

func (a *fakeAuditor) writes() []audit.Entry { return a.byAction("write") }
func (a *fakeAuditor) reads() []audit.Entry  { return a.byAction("read") }

func (a *fakeAuditor) byAction(action string) []audit.Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var w []audit.Entry
	for _, e := range a.entries {
		if e.Action == action {
			w = append(w, e)
		}
	}
	return w
}

func TestDirectWriteAuditedOnLeader(t *testing.T) {
	a := &fakeAuditor{}
	h := New(newFake(), a, nil) // newFake is leader
	body, _ := json.Marshal(secretBody{Value: "v"})
	if rec := do(t, h, "PUT", "/v1/secret/bar", body); rec.Code != http.StatusNoContent {
		t.Fatalf("got %d", rec.Code)
	}
	w := a.writes()
	if len(w) != 1 || w[0].Path != "bar" || w[0].Result != "ok" {
		t.Fatalf("leader should record one ok write, got %+v", w)
	}
}

// The edge node (the one the client hit) must record the write even when it
// forwards to the leader, and the leader must NOT double-count it.
func TestForwardedWriteAuditedOnEdgeOnly(t *testing.T) {
	leaderAudit := &fakeAuditor{}
	leaderSrv := httptest.NewServer(New(newFake(), leaderAudit, nil))
	defer leaderSrv.Close()

	edgeAudit := &fakeAuditor{}
	follower := newFake()
	follower.leader = false
	follower.leaderURL = leaderSrv.URL
	h := New(follower, edgeAudit, nil)

	body, _ := json.Marshal(secretBody{Value: "v"})
	if rec := do(t, h, "PUT", "/v1/secret/foo", body); rec.Code != http.StatusNoContent {
		t.Fatalf("forwarded PUT got %d", rec.Code)
	}
	if w := edgeAudit.writes(); len(w) != 1 || w[0].Path != "foo" || w[0].Result != "ok" {
		t.Fatalf("edge should record one ok write, got %+v", w)
	}
	if w := leaderAudit.writes(); len(w) != 0 {
		t.Fatalf("leader must not record a forwarded write, got %+v", w)
	}
}

// A polling client that revalidates with If-None-Match gets 304 and is NOT
// audited (nothing was disclosed) — this is what stops refresh-loop clients
// from flooding the audit log. A stale ETag still reads and records normally.
func TestConditionalGetNotAudited(t *testing.T) {
	a := &fakeAuditor{}
	fake := newFake()
	h := New(fake, a, nil)

	body, _ := json.Marshal(secretBody{Value: "hunter2"})
	if rec := do(t, h, "PUT", "/v1/secret/kg/web/PW", body); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT got %d", rec.Code)
	}

	// First read discloses the value, returns an ETag, and is audited.
	rec := do(t, h, "GET", "/v1/secret/kg/web/PW", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("first GET got %d", rec.Code)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected an ETag on the 200 read")
	}
	if n := len(a.reads()); n != 1 {
		t.Fatalf("first read should be audited once, got %d", n)
	}

	// Revalidate with the matching ETag: 304, no disclosure, no new audit entry.
	for i := 0; i < 5; i++ {
		r := httptest.NewRequest("GET", "/v1/secret/kg/web/PW", nil)
		r.Header.Set("If-None-Match", etag)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if rr.Code != http.StatusNotModified {
			t.Fatalf("revalidation %d got %d, want 304", i, rr.Code)
		}
		if rr.Body.Len() != 0 {
			t.Fatalf("304 must not disclose a body, got %q", rr.Body)
		}
	}
	if n := len(a.reads()); n != 1 {
		t.Fatalf("304 revalidations must not be audited; want 1 read total, got %d", n)
	}

	// A write bumps the version, so the old ETag no longer matches: the next
	// revalidation discloses the new value and is audited again.
	if rec := do(t, h, "PUT", "/v1/secret/kg/web/PW", body); rec.Code != http.StatusNoContent {
		t.Fatalf("second PUT got %d", rec.Code)
	}
	r := httptest.NewRequest("GET", "/v1/secret/kg/web/PW", nil)
	r.Header.Set("If-None-Match", etag)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("stale-ETag GET got %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("ETag"); got == etag || got == "" {
		t.Fatalf("expected a fresh ETag after write, got %q (old %q)", got, etag)
	}
	if n := len(a.reads()); n != 2 {
		t.Fatalf("stale-ETag read should be audited; want 2 reads total, got %d", n)
	}
}

// The -auto agent lists keys every poll; an unchanged key SET must revalidate to
// 304 and add no `list` audit row. A key added/removed changes the ETag, so the
// next list discloses and is recorded again.
func TestListConditionalGetNotAudited(t *testing.T) {
	a := &fakeAuditor{}
	h := New(newFake(), a, nil)
	put := func(p string) {
		b, _ := json.Marshal(secretBody{Value: "v"})
		if rec := do(t, h, "PUT", "/v1/secret/"+p, b); rec.Code != http.StatusNoContent {
			t.Fatalf("PUT %s: %d", p, rec.Code)
		}
	}
	put("kg/web/A")
	put("kg/web/B")

	// First list discloses the set, returns an ETag, and is audited.
	rec := do(t, h, "GET", "/v1/secrets", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("first list: %d", rec.Code)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected an ETag on the 200 list")
	}
	if n := len(a.byAction("list")); n != 1 {
		t.Fatalf("first list should be audited once, got %d", n)
	}

	// Steady polls with the matching ETag: 304, no body, no new audit row.
	for i := 0; i < 5; i++ {
		r := httptest.NewRequest("GET", "/v1/secrets", nil)
		r.Header.Set("If-None-Match", etag)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if rr.Code != http.StatusNotModified {
			t.Fatalf("revalidation %d: %d, want 304", i, rr.Code)
		}
		if rr.Body.Len() != 0 {
			t.Fatalf("304 must not disclose a listing, got %q", rr.Body)
		}
	}
	if n := len(a.byAction("list")); n != 1 {
		t.Fatalf("304 revalidations must not be audited; want 1 list total, got %d", n)
	}

	// Adding a key changes the set → stale ETag misses → 200 + a fresh audit row.
	put("kg/web/C")
	r := httptest.NewRequest("GET", "/v1/secrets", nil)
	r.Header.Set("If-None-Match", etag)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("after add: %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("ETag"); got == etag || got == "" {
		t.Fatalf("expected a fresh list ETag after add, got %q (old %q)", got, etag)
	}
	if n := len(a.byAction("list")); n != 2 {
		t.Fatalf("changed-set list should be audited; want 2, got %d", n)
	}
}
