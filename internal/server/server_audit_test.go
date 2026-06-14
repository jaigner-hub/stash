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

func (a *fakeAuditor) writes() []audit.Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var w []audit.Entry
	for _, e := range a.entries {
		if e.Action == "write" {
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
