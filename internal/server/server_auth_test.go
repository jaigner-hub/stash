package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jaigner-hub/stash/internal/cluster"
)

func doTok(t *testing.T, h http.Handler, method, target, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// enforcedFake has identities, so the server enforces auth (not open mode).
func enforcedFake() *fakeBackend {
	f := newFake()
	f.identities = map[string]*cluster.Identity{
		"admintok": {Name: "root", Admin: true},
		"readtok": {Name: "ci", Policies: []cluster.Policy{
			{Prefix: "kg/web/", Caps: []string{cluster.CapRead}},
		}},
	}
	return f
}

func TestAuthRequiredWhenEnforced(t *testing.T) {
	h := New(enforcedFake(), nil)
	if rec := doTok(t, h, "GET", "/v1/secrets", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401 got %d", rec.Code)
	}
	if rec := doTok(t, h, "GET", "/v1/secrets", "bogus", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: want 401 got %d", rec.Code)
	}
}

func TestCapEnforcement(t *testing.T) {
	f := enforcedFake()
	f.data["kg/web/A"] = []byte("x")
	h := New(f, nil)
	body, _ := json.Marshal(secretBody{Value: "y"})

	if rec := doTok(t, h, "GET", "/v1/secret/kg/web/A", "readtok", nil); rec.Code != http.StatusOK {
		t.Fatalf("read within prefix: got %d", rec.Code)
	}
	if rec := doTok(t, h, "PUT", "/v1/secret/kg/web/A", "readtok", body); rec.Code != http.StatusForbidden {
		t.Fatalf("write with read-only: want 403 got %d", rec.Code)
	}
	if rec := doTok(t, h, "GET", "/v1/secret/other/B", "readtok", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("read outside prefix: want 403 got %d", rec.Code)
	}
	if rec := doTok(t, h, "PUT", "/v1/secret/other/B", "admintok", body); rec.Code != http.StatusNoContent {
		t.Fatalf("admin write: got %d", rec.Code)
	}
}

func TestListFiltersByCap(t *testing.T) {
	f := enforcedFake()
	f.data["kg/web/A"] = []byte("x")
	f.data["other/B"] = []byte("y")
	h := New(f, nil)

	rec := doTok(t, h, "GET", "/v1/secrets", "readtok", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	var out struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Keys) != 1 || out.Keys[0] != "kg/web/A" {
		t.Fatalf("expected only kg/web/A visible, got %v", out.Keys)
	}
}

func TestIdentityEndpointsAdminOnly(t *testing.T) {
	h := New(enforcedFake(), nil)
	if rec := doTok(t, h, "GET", "/v1/identities", "readtok", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: want 403 got %d", rec.Code)
	}
	if rec := doTok(t, h, "GET", "/v1/identities", "admintok", nil); rec.Code != http.StatusOK {
		t.Fatalf("admin: got %d", rec.Code)
	}
	body, _ := json.Marshal(map[string]any{"name": "newone", "admin": false})
	rec := doTok(t, h, "POST", "/v1/identities", "admintok", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d (%s)", rec.Code, rec.Body)
	}
	var cr struct {
		Token string `json:"token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &cr)
	if cr.Token == "" {
		t.Fatal("create should return a one-time token")
	}
}

func TestOpenModeAllowsNoToken(t *testing.T) {
	// No identities => open mode => requests succeed without a token.
	h := New(newFake(), nil)
	if rec := doTok(t, h, "GET", "/v1/secrets", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("open mode should allow: got %d", rec.Code)
	}
}
