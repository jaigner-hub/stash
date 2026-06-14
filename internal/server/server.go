// Package server exposes a stash node over a small HTTP/JSON API. Reads are
// served locally; writes are accepted only on the leader, so a follower
// transparently reverse-proxies write requests to the current leader.
package server

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
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
	Page(before uint64, limit int) ([]audit.Entry, error)
	Verify() (bool, uint64, error)
}

const maxBodyBytes = 1 << 20 // 1 MiB — secrets are small; cap abuse.

// forwardedHeader marks a request that one node reverse-proxied to the leader,
// so the leader records nothing for it (the edge node already audited it).
const forwardedHeader = "X-Stash-Forwarded"

// statusWriter captures the response status so the edge node can audit the
// result of a request it forwarded to the leader.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// auditResult maps an HTTP status to an audit result string.
func auditResult(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "ok"
	case status == http.StatusForbidden:
		return "denied"
	case status == http.StatusNotFound:
		return "not_found"
	case status == http.StatusServiceUnavailable:
		return "sealed"
	default:
		return "error"
	}
}

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
	ListVersions(path string) ([]store.VersionMeta, error)
	GetVersion(path string, seq uint64) ([]byte, error)
	CurrentVersion(path string) (uint64, error)
	// OutboundTLS is the client TLS config for forwarding to the leader (nil for
	// plaintext clusters).
	OutboundTLS() *tls.Config
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
	mux.HandleFunc("GET /metrics", srv.metrics)
	mux.HandleFunc("GET /v1/secrets", srv.list)
	mux.HandleFunc("GET /v1/secret/{path...}", srv.get)
	mux.HandleFunc("GET /v1/versions/{path...}", srv.versions)
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

// metrics serves a tiny Prometheus exposition for cluster-health alerting. It is
// dependency-free (no client_golang) and intentionally unauthenticated, like
// /v1/health — it exposes only role/seal/leader/voter-count gauges, never secret
// material or member addresses. Bare series (no node label): the scrape config
// attaches instance/role. See keygrip observability (blackbox-stash + stash jobs).
func (s *server) metrics(w http.ResponseWriter, r *http.Request) {
	st := s.backend.Status()
	voters := 0
	for _, m := range st.Servers {
		if m.Suffrage == "voter" {
			voters++
		}
	}
	bit := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, `# HELP stash_up 1 if the node is serving.
# TYPE stash_up gauge
stash_up 1
# HELP stash_sealed 1 if the store is sealed (no DEK — cannot read secrets).
# TYPE stash_sealed gauge
stash_sealed %d
# HELP stash_is_leader 1 if this node is the current raft leader.
# TYPE stash_is_leader gauge
stash_is_leader %d
# HELP stash_raft_has_leader 1 if this node currently sees a raft leader.
# TYPE stash_raft_has_leader gauge
stash_raft_has_leader %d
# HELP stash_raft_voters Number of voting members in the raft configuration.
# TYPE stash_raft_voters gauge
stash_raft_voters %d
# HELP stash_raft_members Total members (voters + non-voters) in the raft configuration.
# TYPE stash_raft_members gauge
stash_raft_members %d
`, bit(st.Sealed), bit(st.IsLeader), bit(st.LeaderID != ""), voters, len(st.Servers))
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
	// Optional ?version=N reads a specific historical version. A version is
	// immutable, so it carries a strong ETag and revalidates trivially.
	if vs := r.URL.Query().Get("version"); vs != "" {
		seq, err := strconv.ParseUint(vs, 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid version"})
			return
		}
		etag := versionETag(seq)
		if ifNoneMatch(r, etag) {
			// Nothing is disclosed, so this is not an audited read.
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		v, err := s.backend.GetVersion(path, seq)
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
		w.Header().Set("ETag", etag)
		writeJSON(w, http.StatusOK, secretBody{Value: string(v)})
		return
	}
	// Conditional GET on the current value: the ETag is the current version seq.
	// We resolve it before reading the value, so a write racing in between yields
	// a stale ETag (one extra fetch next poll) rather than a missed update. A 304
	// discloses nothing and is deliberately not audited — this is what keeps
	// polling clients from flooding the audit log.
	var etag string
	if seq, err := s.backend.CurrentVersion(path); err == nil && seq != 0 {
		etag = versionETag(seq)
		if ifNoneMatch(r, etag) {
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
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
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	writeJSON(w, http.StatusOK, secretBody{Value: string(v)})
}

// versionETag renders a strong ETag for a secret version seq.
func versionETag(seq uint64) string { return fmt.Sprintf("\"v%d\"", seq) }

// ifNoneMatch reports whether r's If-None-Match header matches etag (or "*").
func ifNoneMatch(r *http.Request, etag string) bool {
	h := r.Header.Get("If-None-Match")
	if h == "" {
		return false
	}
	for _, c := range strings.Split(h, ",") {
		c = strings.TrimSpace(c)
		if c == "*" || c == etag {
			return true
		}
	}
	return false
}

func (s *server) versions(w http.ResponseWriter, r *http.Request) {
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	path := r.PathValue("path")
	if !id.Can(cluster.CapRead, path) {
		forbid(w)
		return
	}
	vs, err := s.backend.ListVersions(path)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if vs == nil {
		vs = []store.VersionMeta{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": vs})
}

func (s *server) put(w http.ResponseWriter, r *http.Request) {
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	path := r.PathValue("path")
	forwarded := r.Header.Get(forwardedHeader) != ""
	if !id.Can(cluster.CapWrite, path) {
		if !forwarded {
			s.record(id, "write", path, "denied")
		}
		forbid(w)
		return
	}
	// A follower forwards to the leader and audits the outcome itself (the edge
	// node owns the audit entry); the leader skips recording forwarded requests.
	if !s.backend.IsLeader() {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		s.proxyToLeader(sw, r)
		s.record(id, "write", path, auditResult(sw.status))
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
		if !forwarded {
			s.record(id, "write", path, "error")
		}
		s.writeErr(w, err)
		return
	}
	if !forwarded {
		s.record(id, "write", path, "ok")
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) delete(w http.ResponseWriter, r *http.Request) {
	id, ok := s.auth(w, r)
	if !ok {
		return
	}
	path := r.PathValue("path")
	forwarded := r.Header.Get(forwardedHeader) != ""
	if !id.Can(cluster.CapDelete, path) {
		if !forwarded {
			s.record(id, "delete", path, "denied")
		}
		forbid(w)
		return
	}
	if !s.backend.IsLeader() {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		s.proxyToLeader(sw, r)
		s.record(id, "delete", path, auditResult(sw.status))
		return
	}
	if err := s.backend.Delete(path); err != nil {
		if !forwarded {
			result := "error"
			if errors.Is(err, store.ErrNotFound) {
				result = "not_found"
			}
			s.record(id, "delete", path, result)
		}
		s.writeErr(w, err)
		return
	}
	if !forwarded {
		s.record(id, "delete", path, "ok")
	}
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
	sort.Strings(visible) // deterministic order so the ETag is stable
	// The ETag is the visible key SET (names only): it changes when a key is added
	// or removed, not when a value changes (values come via per-secret reads). A
	// matching If-None-Match means the set is unchanged → 304, and not audited,
	// since no listing was disclosed. Per-identity, since `visible` is ACL-scoped —
	// this is what keeps a polling agent's `list` call out of the audit log too.
	etag := listETag(visible)
	if ifNoneMatch(r, etag) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	s.record(id, "list", "", "ok")
	w.Header().Set("ETag", etag)
	writeJSON(w, http.StatusOK, map[string]any{"keys": visible})
}

// listETag hashes the (sorted) visible key set into a strong ETag. Only the names
// matter — a value change doesn't alter the listing.
func listETag(keys []string) string {
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0}) // delimiter so ["ab","c"] != ["a","bc"]
	}
	return fmt.Sprintf("\"l%s\"", hex.EncodeToString(h.Sum(nil)[:8]))
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
	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	var before uint64
	if q := r.URL.Query().Get("before"); q != "" {
		if n, err := strconv.ParseUint(q, 10, 64); err == nil {
			before = n
		}
	}
	entries, err := s.audit.Page(before, limit)
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
	if cfg := s.backend.OutboundTLS(); cfg != nil {
		proxy.Transport = &http.Transport{TLSClientConfig: cfg}
	}
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		req.Header.Set(forwardedHeader, "1") // tell the leader the edge already audited
	}
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
