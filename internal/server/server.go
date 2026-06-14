// Package server exposes a stash node over a small HTTP/JSON API. Reads are
// served locally; writes are accepted only on the leader, so a follower
// transparently reverse-proxies write requests to the current leader.
package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/jaigner-hub/stash/internal/audit"
	"github.com/jaigner-hub/stash/internal/cluster"
	"github.com/jaigner-hub/stash/internal/store"
	"github.com/jaigner-hub/stash/internal/ui"
)

// Auditor records and reports the tamper-evident audit log. *audit.Log
// implements it; pass nil to disable auditing (e.g. in tests).
type Auditor interface {
	Record(identity, action, path, result string) error
	Recent(n int) ([]audit.Entry, error)
	Verify() (bool, uint64, error)
}

const maxBodyBytes = 1 << 20 // 1 MiB — secrets are small; cap abuse.

// Backend is the cluster-aware store the server sits in front of. *cluster.Node
// implements it; tests use a fake.
type Backend interface {
	Get(path string) ([]byte, error)
	List() ([]string, error)
	Put(path string, value []byte) error
	Delete(path string) error
	Sealed() bool
	IsLeader() bool
	LeaderHTTPAddr() (addr string, known bool)
	Join(nodeID, raftAddr, httpAddr string) error
	VerifyJoinSecret(secret string) bool
	Status() cluster.ClusterStatus
	Authenticate(token string) (*cluster.Identity, error)
	HasIdentities() bool
	CreateIdentity(name string, admin bool, policies []cluster.Policy) (string, error)
	DeleteIdentity(name string) error
	ListIdentities() ([]cluster.Identity, error)
}

type server struct {
	backend Backend
	audit   Auditor
	log     *slog.Logger
}

// New returns an http.Handler serving the stash API backed by b. auditor may be
// nil to disable audit logging.
func New(b Backend, auditor Auditor, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	srv := &server{backend: b, audit: auditor, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", srv.health)
	mux.HandleFunc("GET /v1/secrets", srv.list)
	mux.HandleFunc("GET /v1/secret/{path...}", srv.get)
	mux.HandleFunc("PUT /v1/secret/{path...}", srv.put)
	mux.HandleFunc("DELETE /v1/secret/{path...}", srv.delete)
	mux.HandleFunc("POST /v1/cluster/join", srv.join)
	mux.HandleFunc("GET /v1/cluster/status", srv.clusterStatus)
	mux.HandleFunc("GET /v1/identities", srv.listIdentities)
	mux.HandleFunc("POST /v1/identities", srv.createIdentity)
	mux.HandleFunc("DELETE /v1/identities/{name}", srv.deleteIdentity)
	mux.HandleFunc("GET /v1/audit", srv.auditLog)
	// Embedded web console at / (most specific /v1/... routes win over this).
	mux.Handle("/", ui.Handler())
	return mux
}

// record appends an audit entry, attributing it to id (if known). Best-effort:
// a failed record is logged, not surfaced to the caller.
func (s *server) record(id *cluster.Identity, action, path, result string) {
	if s.audit == nil {
		return
	}
	name := "unknown"
	if id != nil {
		name = id.Name
	}
	if err := s.audit.Record(name, action, path, result); err != nil {
		s.log.Error("audit record failed", "err", err)
	}
}

// auth resolves the request's identity. In "open mode" (no identities exist
// yet, e.g. just after an upgrade) it returns a synthetic admin so the cluster
// isn't locked out. Otherwise a valid bearer token is required; on failure it
// writes 401 and returns ok=false.
func (s *server) auth(w http.ResponseWriter, r *http.Request) (*cluster.Identity, bool) {
	if !s.backend.HasIdentities() {
		return &cluster.Identity{Name: "open-mode", Admin: true}, true
	}
	tok := bearerToken(r)
	if tok == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return nil, false
	}
	id, err := s.backend.Authenticate(tok)
	if err != nil {
		s.log.Error("authenticate", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return nil, false
	}
	if id == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return nil, false
	}
	return id, true
}

func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	if c, err := r.Cookie("stash_token"); err == nil {
		return c.Value
	}
	return ""
}

func forbid(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
}

type secretBody struct {
	Value string `json:"value"`
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"sealed":    s.backend.Sealed(),
		"is_leader": s.backend.IsLeader(),
	})
}

func (s *server) get(w http.ResponseWriter, r *http.Request) {
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	path := r.PathValue("path")
	if !id.Can(cluster.CapRead, path) {
		s.record(id, "read", path, "denied")
		forbid(w)
		return
	}
	v, err := s.backend.Get(path)
	if err != nil {
		result := "error"
		if errors.Is(err, store.ErrNotFound) {
			result = "not_found"
		}
		s.record(id, "read", path, result)
		s.writeErr(w, err)
		return
	}
	s.record(id, "read", path, "ok")
	writeJSON(w, http.StatusOK, secretBody{Value: string(v)})
}

func (s *server) put(w http.ResponseWriter, r *http.Request) {
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	path := r.PathValue("path")
	if !id.Can(cluster.CapWrite, path) {
		s.record(id, "write", path, "denied")
		forbid(w)
		return
	}
	if !s.backend.IsLeader() {
		s.proxyToLeader(w, r) // the leader records the actual write
		return
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	var body secretBody
	if err := json.Unmarshal(raw, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if err := s.backend.Put(path, []byte(body.Value)); err != nil {
		s.record(id, "write", path, "error")
		s.writeErr(w, err)
		return
	}
	s.record(id, "write", path, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) delete(w http.ResponseWriter, r *http.Request) {
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	path := r.PathValue("path")
	if !id.Can(cluster.CapDelete, path) {
		s.record(id, "delete", path, "denied")
		forbid(w)
		return
	}
	if !s.backend.IsLeader() {
		s.proxyToLeader(w, r) // the leader records the actual delete
		return
	}
	if err := s.backend.Delete(path); err != nil {
		result := "error"
		if errors.Is(err, store.ErrNotFound) {
			result = "not_found"
		}
		s.record(id, "delete", path, result)
		s.writeErr(w, err)
		return
	}
	s.record(id, "delete", path, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) list(w http.ResponseWriter, r *http.Request) {
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	keys, err := s.backend.List()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// Show only paths this identity may read.
	visible := []string{}
	for _, k := range keys {
		if id.Can(cluster.CapRead, k) {
			visible = append(visible, k)
		}
	}
	s.record(id, "list", "", "ok")
	writeJSON(w, http.StatusOK, map[string]any{"keys": visible})
}

func (s *server) join(w http.ResponseWriter, r *http.Request) {
	if !s.backend.IsLeader() {
		s.proxyToLeader(w, r)
		return
	}
	defer r.Body.Close()
	var req cluster.JoinRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.NodeID == "" || req.RaftAddr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node_id and raft_addr are required"})
		return
	}
	if !s.backend.VerifyJoinSecret(req.Secret) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid join secret"})
		return
	}
	if err := s.backend.Join(req.NodeID, req.RaftAddr, req.HTTPAddr); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "joined"})
}

func (s *server) clusterStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.auth(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.backend.Status())
}

func (s *server) listIdentities(w http.ResponseWriter, r *http.Request) {
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	if !id.Admin {
		forbid(w)
		return
	}
	ids, err := s.backend.ListIdentities()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if ids == nil {
		ids = []cluster.Identity{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"identities": ids})
}

func (s *server) createIdentity(w http.ResponseWriter, r *http.Request) {
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	if !id.Admin {
		s.record(id, "identity.create", "", "denied")
		forbid(w)
		return
	}
	if !s.backend.IsLeader() {
		s.proxyToLeader(w, r)
		return
	}
	defer r.Body.Close()
	var req struct {
		Name     string           `json:"name"`
		Admin    bool             `json:"admin"`
		Policies []cluster.Policy `json:"policies"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	token, err := s.backend.CreateIdentity(req.Name, req.Admin, req.Policies)
	if err != nil {
		s.record(id, "identity.create", req.Name, "error")
		s.writeErr(w, err)
		return
	}
	s.record(id, "identity.create", req.Name, "ok")
	// The token is shown exactly once.
	writeJSON(w, http.StatusCreated, map[string]string{"name": req.Name, "token": token})
}

func (s *server) deleteIdentity(w http.ResponseWriter, r *http.Request) {
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if !id.Admin {
		s.record(id, "identity.delete", name, "denied")
		forbid(w)
		return
	}
	if !s.backend.IsLeader() {
		s.proxyToLeader(w, r)
		return
	}
	if err := s.backend.DeleteIdentity(name); err != nil {
		result := "error"
		if errors.Is(err, store.ErrNotFound) {
			result = "not_found"
		}
		s.record(id, "identity.delete", name, result)
		s.writeErr(w, err)
		return
	}
	s.record(id, "identity.delete", name, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) auditLog(w http.ResponseWriter, r *http.Request) {
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	if !id.Admin {
		forbid(w)
		return
	}
	if s.audit == nil {
		writeJSON(w, http.StatusOK, map[string]any{"entries": []audit.Entry{}, "verified": true, "count": 0})
		return
	}
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	entries, err := s.audit.Recent(limit)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	intact, count, err := s.audit.Verify()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "verified": intact, "count": count})
}

// proxyToLeader reverse-proxies the current request to the leader's API.
func (s *server) proxyToLeader(w http.ResponseWriter, r *http.Request) {
	addr, ok := s.backend.LeaderHTTPAddr()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no leader elected"})
		return
	}
	target, err := url.Parse(addr)
	if err != nil {
		s.log.Error("bad leader address", "addr", addr, "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "bad leader address"})
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		s.log.Error("leader proxy failed", "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "leader unreachable"})
	}
	proxy.ServeHTTP(w, r)
}

func (s *server) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, store.ErrSealed):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sealed"})
	case errors.Is(err, cluster.ErrNotLeader):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "not the leader"})
	default:
		s.log.Error("request failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
