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

	"github.com/jaigner-hub/stash/internal/cluster"
	"github.com/jaigner-hub/stash/internal/store"
)

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
}

type server struct {
	backend Backend
	log     *slog.Logger
}

// New returns an http.Handler serving the stash API backed by b.
func New(b Backend, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	srv := &server{backend: b, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", srv.health)
	mux.HandleFunc("GET /v1/secrets", srv.list)
	mux.HandleFunc("GET /v1/secret/{path...}", srv.get)
	mux.HandleFunc("PUT /v1/secret/{path...}", srv.put)
	mux.HandleFunc("DELETE /v1/secret/{path...}", srv.delete)
	mux.HandleFunc("POST /v1/cluster/join", srv.join)
	return mux
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
	v, err := s.backend.Get(r.PathValue("path"))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secretBody{Value: string(v)})
}

func (s *server) put(w http.ResponseWriter, r *http.Request) {
	if !s.backend.IsLeader() {
		s.proxyToLeader(w, r)
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
	if err := s.backend.Put(r.PathValue("path"), []byte(body.Value)); err != nil {
		s.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) delete(w http.ResponseWriter, r *http.Request) {
	if !s.backend.IsLeader() {
		s.proxyToLeader(w, r)
		return
	}
	if err := s.backend.Delete(r.PathValue("path")); err != nil {
		s.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) list(w http.ResponseWriter, r *http.Request) {
	keys, err := s.backend.List()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if keys == nil {
		keys = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
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
