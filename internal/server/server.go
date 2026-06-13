// Package server exposes the stash store over a small HTTP/JSON API. This is
// the node's data plane; clustering (Raft HA) will wrap a Store in a later
// milestone without changing this surface.
package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/jaigner-hub/stash/internal/store"
)

const maxBodyBytes = 1 << 20 // 1 MiB — secrets are small; cap abuse.

// Store is the subset of *store.Store the server depends on. Narrowing it keeps
// the HTTP layer testable and makes the eventual Raft wrapper a drop-in.
type Store interface {
	Put(path string, value []byte) error
	Get(path string) ([]byte, error)
	Delete(path string) error
	List() ([]string, error)
	Sealed() bool
}

type server struct {
	store Store
	log   *slog.Logger
}

// New returns an http.Handler serving the stash API backed by s.
func New(s Store, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	srv := &server{store: s, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", srv.health)
	mux.HandleFunc("GET /v1/secrets", srv.list)
	mux.HandleFunc("GET /v1/secret/{path...}", srv.get)
	mux.HandleFunc("PUT /v1/secret/{path...}", srv.put)
	mux.HandleFunc("DELETE /v1/secret/{path...}", srv.delete)
	return mux
}

type secretBody struct {
	Value string `json:"value"`
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"sealed": s.store.Sealed(),
	})
}

func (s *server) get(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.Get(r.PathValue("path"))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secretBody{Value: string(v)})
}

func (s *server) put(w http.ResponseWriter, r *http.Request) {
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
	if err := s.store.Put(r.PathValue("path"), []byte(body.Value)); err != nil {
		s.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) delete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Delete(r.PathValue("path")); err != nil {
		s.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) list(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.List()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if keys == nil {
		keys = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *server) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, store.ErrSealed):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sealed"})
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
