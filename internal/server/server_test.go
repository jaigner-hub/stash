package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jaigner-hub/stash/internal/cluster"
	"github.com/jaigner-hub/stash/internal/store"
)

// fakeBackend is an in-memory Backend for HTTP-layer tests. leader and leaderURL
// are configurable to exercise forwarding.
type fakeBackend struct {
	mu         sync.Mutex
	data       map[string][]byte
	leader     bool
	leaderURL  string
	secret     string
	identities map[string]*cluster.Identity // token -> identity (empty => open mode)
	joined     *struct{ id, raft, http string }
}

func newFake() *fakeBackend {
	return &fakeBackend{data: map[string][]byte{}, leader: true, secret: "good-secret"}
}

func (f *fakeBackend) Get(p string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[p]
	if !ok {
		return nil, store.ErrNotFound
	}
	return v, nil
}

func (f *fakeBackend) List() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.data {
		out = append(out, k)
	}
	return out, nil
}

func (f *fakeBackend) Put(p string, v []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[p] = v
	return nil
}

func (f *fakeBackend) Delete(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.data[p]; !ok {
		return store.ErrNotFound
	}
	delete(f.data, p)
	return nil
}

func (f *fakeBackend) Sealed() bool   { return false }
func (f *fakeBackend) IsLeader() bool { return f.leader }
func (f *fakeBackend) LeaderHTTPAddr() (string, bool) {
	return f.leaderURL, f.leaderURL != ""
}
func (f *fakeBackend) Join(id, raftAddr, httpAddr string) error {
	f.joined = &struct{ id, raft, http string }{id, raftAddr, httpAddr}
	return nil
}
func (f *fakeBackend) VerifyJoinSecret(s string) bool { return s == f.secret }
func (f *fakeBackend) Status() cluster.ClusterStatus {
	return cluster.ClusterStatus{NodeID: "fake", IsLeader: f.leader}
}

// Identity hooks. By default the fake has no identities (open mode), matching
// the existing tests that don't send tokens.
func (f *fakeBackend) HasIdentities() bool { return len(f.identities) > 0 }
func (f *fakeBackend) Authenticate(token string) (*cluster.Identity, error) {
	id, ok := f.identities[token]
	if !ok {
		return nil, nil
	}
	return id, nil
}
func (f *fakeBackend) CreateIdentity(name string, admin bool, policies []cluster.Policy) (string, error) {
	tok := "tok-" + name
	if f.identities == nil {
		f.identities = map[string]*cluster.Identity{}
	}
	f.identities[tok] = &cluster.Identity{Name: name, Admin: admin, Policies: policies}
	return tok, nil
}
func (f *fakeBackend) DeleteIdentity(name string) error {
	for t, id := range f.identities {
		if id.Name == name {
			delete(f.identities, t)
			return nil
		}
	}
	return store.ErrNotFound
}
func (f *fakeBackend) ListIdentities() ([]cluster.Identity, error) {
	var out []cluster.Identity
	for _, id := range f.identities {
		out = append(out, id.Redacted())
	}
	return out, nil
}

func do(t *testing.T, h http.Handler, method, target string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestPutGetDeleteRoundTrip(t *testing.T) {
	h := New(newFake(), nil, nil)
	body, _ := json.Marshal(secretBody{Value: "hunter2"})

	if rec := do(t, h, "PUT", "/v1/secret/kg/web/PW", body); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT: got %d (%s)", rec.Code, rec.Body)
	}

	rec := do(t, h, "GET", "/v1/secret/kg/web/PW", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: got %d", rec.Code)
	}
	var got secretBody
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Value != "hunter2" {
		t.Fatalf("got %q", got.Value)
	}

	if rec := do(t, h, "DELETE", "/v1/secret/kg/web/PW", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE: got %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/secret/kg/web/PW", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("GET after delete: got %d", rec.Code)
	}
}

func TestGetMissing(t *testing.T) {
	h := New(newFake(), nil, nil)
	if rec := do(t, h, "GET", "/v1/secret/nope", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestPutInvalidJSON(t *testing.T) {
	h := New(newFake(), nil, nil)
	if rec := do(t, h, "PUT", "/v1/secret/x", []byte("not json")); rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestList(t *testing.T) {
	h := New(newFake(), nil, nil)
	for _, p := range []string{"a", "b"} {
		body, _ := json.Marshal(secretBody{Value: "v"})
		do(t, h, "PUT", "/v1/secret/"+p, body)
	}
	rec := do(t, h, "GET", "/v1/secrets", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	var out struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Keys) != 2 {
		t.Fatalf("got %v", out.Keys)
	}
}

func TestHealth(t *testing.T) {
	h := New(newFake(), nil, nil)
	rec := do(t, h, "GET", "/v1/health", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
}

// TestWriteForwardsToLeader: a follower must reverse-proxy writes to the leader.
func TestWriteForwardsToLeader(t *testing.T) {
	// Stand up a "leader" HTTP server that records the forwarded write.
	leader := newFake()
	leaderSrv := httptest.NewServer(New(leader, nil, nil))
	defer leaderSrv.Close()

	// Follower: not leader, points at the leader's URL.
	follower := newFake()
	follower.leader = false
	follower.leaderURL = leaderSrv.URL
	h := New(follower, nil, nil)

	body, _ := json.Marshal(secretBody{Value: "forwarded"})
	rec := do(t, h, "PUT", "/v1/secret/foo", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("forwarded PUT: got %d (%s)", rec.Code, rec.Body)
	}
	// The value should have landed on the leader, not the follower.
	if v, err := leader.Get("foo"); err != nil || string(v) != "forwarded" {
		t.Fatalf("leader.Get(foo) = %q, %v", v, err)
	}
	if _, err := follower.Get("foo"); err == nil {
		t.Fatal("value unexpectedly written to follower")
	}
}

func TestWriteNoLeader(t *testing.T) {
	follower := newFake()
	follower.leader = false // no leaderURL set => unknown
	h := New(follower, nil, nil)
	body, _ := json.Marshal(secretBody{Value: "x"})
	if rec := do(t, h, "PUT", "/v1/secret/foo", body); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestJoin(t *testing.T) {
	b := newFake()
	h := New(b, nil, nil)
	body, _ := json.Marshal(map[string]string{
		"node_id": "n2", "raft_addr": "127.0.0.1:8301", "http_addr": "http://127.0.0.1:8201",
		"secret": "good-secret",
	})
	if rec := do(t, h, "POST", "/v1/cluster/join", body); rec.Code != http.StatusOK {
		t.Fatalf("got %d (%s)", rec.Code, rec.Body)
	}
	if b.joined == nil || b.joined.id != "n2" || b.joined.raft != "127.0.0.1:8301" {
		t.Fatalf("join not recorded correctly: %+v", b.joined)
	}
}

func TestJoinWrongSecret(t *testing.T) {
	b := newFake()
	h := New(b, nil, nil)
	body, _ := json.Marshal(map[string]string{
		"node_id": "n2", "raft_addr": "127.0.0.1:8301", "secret": "WRONG",
	})
	if rec := do(t, h, "POST", "/v1/cluster/join", body); rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
	if b.joined != nil {
		t.Fatal("join should not have been recorded with a bad secret")
	}
}
