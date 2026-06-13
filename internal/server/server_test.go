package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/jaigner-hub/stash/internal/crypto"
	"github.com/jaigner-hub/stash/internal/store"
)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "stash.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	kek, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Init(kek); err != nil {
		t.Fatal(err)
	}
	return New(s, nil)
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
	h := newTestServer(t)
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
	h := newTestServer(t)
	if rec := do(t, h, "GET", "/v1/secret/nope", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestPutInvalidJSON(t *testing.T) {
	h := newTestServer(t)
	if rec := do(t, h, "PUT", "/v1/secret/x", []byte("not json")); rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestList(t *testing.T) {
	h := newTestServer(t)
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
	h := newTestServer(t)
	rec := do(t, h, "GET", "/v1/health", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
}
