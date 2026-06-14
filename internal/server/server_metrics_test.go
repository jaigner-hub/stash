package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jaigner-hub/stash/internal/cluster"
)

func TestMetricsExposition(t *testing.T) {
	f := newFake()
	f.status = &cluster.ClusterStatus{
		NodeID:   "vent.dog",
		IsLeader: true,
		Sealed:   false,
		LeaderID: "vent.dog",
		Servers: []cluster.ServerInfo{
			{ID: "vent.dog", Suffrage: "voter", Leader: true},
			{ID: "vent.dog2", Suffrage: "voter"},
			{ID: "monitor", Suffrage: "voter"},
		},
	}
	h := New(f, nil, nil)

	rec := do(t, h, "GET", "/metrics", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"stash_up 1",
		"stash_sealed 0",
		"stash_is_leader 1",
		"stash_raft_has_leader 1",
		"stash_raft_voters 3",
		"stash_raft_members 3",
		"# TYPE stash_sealed gauge",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q\n--- body ---\n%s", want, body)
		}
	}
}

// A sealed witness with no leadership: the seal/leader gauges flip, voter count
// still reflects the configured membership.
func TestMetricsSealedWitness(t *testing.T) {
	f := newFake()
	f.status = &cluster.ClusterStatus{
		NodeID:   "monitor",
		IsLeader: false,
		Sealed:   true,
		LeaderID: "", // briefly leaderless (e.g. mid-election)
		Servers: []cluster.ServerInfo{
			{ID: "vent.dog", Suffrage: "voter"},
			{ID: "vent.dog2", Suffrage: "voter"},
			{ID: "monitor", Suffrage: "voter"},
		},
	}
	h := New(f, nil, nil)

	body := do(t, h, "GET", "/metrics", nil).Body.String()
	for _, want := range []string{
		"stash_sealed 1",
		"stash_is_leader 0",
		"stash_raft_has_leader 0",
		"stash_raft_voters 3",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q\n--- body ---\n%s", want, body)
		}
	}
}

// /metrics is unauthenticated even when identities are enforced (so Prometheus
// scrapes without a token), like /v1/health.
func TestMetricsNoAuthRequired(t *testing.T) {
	h := New(enforcedFake(), nil, nil)
	if rec := do(t, h, "GET", "/metrics", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics under enforcement: %d (want 200)", rec.Code)
	}
}
