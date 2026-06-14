package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The agent's fetcher must revalidate with If-None-Match and treat a 304 as
// "reuse the cached value" — so a steady poll of an unchanged secret transfers
// no body (and the server records no audit entry).
func TestSecretClientConditionalGet(t *testing.T) {
	var disclosures int32 // 200s that actually returned a body (== audited reads)
	etag := `"v1"`
	value := `{"value":"hunter2"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secret/kg/web/PW" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if inm := r.Header.Get("If-None-Match"); inm == etag {
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		atomic.AddInt32(&disclosures, 1)
		w.Header().Set("ETag", etag)
		w.Write([]byte(value))
	}))
	defer srv.Close()

	c := newSecretClient(srv.Client(), srv.URL, "")

	// First fetch discloses the value and caches the ETag.
	if v, err := c.fetch("kg/web/PW"); err != nil || v != "hunter2" {
		t.Fatalf("first fetch: got %q, %v", v, err)
	}
	// Subsequent polls revalidate and reuse the cached value without a disclosure.
	for i := 0; i < 5; i++ {
		if v, err := c.fetch("kg/web/PW"); err != nil || v != "hunter2" {
			t.Fatalf("poll %d: got %q, %v", i, v, err)
		}
	}
	if got := atomic.LoadInt32(&disclosures); got != 1 {
		t.Fatalf("expected exactly one disclosure across 6 polls, got %d", got)
	}
}

// When the secret changes (new ETag), the stale validator misses and the agent
// picks up the new value.
func TestSecretClientPicksUpChange(t *testing.T) {
	var etag, value atomic.Value
	etag.Store(`"v1"`)
	value.Store(`{"value":"old"}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := etag.Load().(string)
		if r.Header.Get("If-None-Match") == cur {
			w.Header().Set("ETag", cur)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", cur)
		w.Write([]byte(value.Load().(string)))
	}))
	defer srv.Close()

	c := newSecretClient(srv.Client(), srv.URL, "")
	if v, err := c.fetch("a"); err != nil || v != "old" {
		t.Fatalf("first fetch: got %q, %v", v, err)
	}
	// A write bumps the version on the server.
	etag.Store(`"v2"`)
	value.Store(`{"value":"new"}`)
	if v, err := c.fetch("a"); err != nil || v != "new" {
		t.Fatalf("after change: got %q, %v", v, err)
	}
	// And the new ETag revalidates as unchanged again.
	if v, err := c.fetch("a"); err != nil || v != "new" {
		t.Fatalf("revalidate new: got %q, %v", v, err)
	}
}

func TestSecretClientSendsToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer t0ken" {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte(`{"value":"x"}`))
	}))
	defer srv.Close()

	c := newSecretClient(srv.Client(), srv.URL, "t0ken")
	if _, err := c.fetch("p"); err != nil {
		t.Fatal(err)
	}
}

// A path with multiple segments is escaped into the URL the same way the server
// routes it.
func TestSecretClientEscapesPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte(`{"value":"x"}`))
	}))
	defer srv.Close()

	c := newSecretClient(srv.Client(), srv.URL, "")
	if _, err := c.fetch("kg/web/DB_PW"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(gotPath, "/v1/secret/kg/web/DB_PW") {
		t.Fatalf("path = %q", gotPath)
	}
}

// The agent's list() must revalidate with If-None-Match and reuse the cached key
// set on a 304 — so steady polls of an unchanged set transfer no body (and the
// server records no `list` audit row).
func TestSecretClientListConditionalGet(t *testing.T) {
	var disclosures int32
	etag := `"l0001"`
	keys := `{"keys":["kg/web/A","kg/web/B"]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secrets" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Header.Get("If-None-Match") == etag {
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		atomic.AddInt32(&disclosures, 1)
		w.Header().Set("ETag", etag)
		w.Write([]byte(keys))
	}))
	defer srv.Close()

	c := newSecretClient(srv.Client(), srv.URL, "")
	want := []string{"kg/web/A", "kg/web/B"}
	for i := 0; i < 6; i++ {
		got, err := c.list()
		if err != nil || strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("poll %d: got %v, %v", i, got, err)
		}
	}
	if got := atomic.LoadInt32(&disclosures); got != 1 {
		t.Fatalf("expected one list disclosure across 6 polls, got %d", got)
	}
}

// A changed key set (new ETag) makes the stale validator miss, and the agent
// picks up the new set.
func TestSecretClientListPicksUpChange(t *testing.T) {
	var etag, keys atomic.Value
	etag.Store(`"l1"`)
	keys.Store(`{"keys":["a"]}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := etag.Load().(string)
		if r.Header.Get("If-None-Match") == cur {
			w.Header().Set("ETag", cur)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", cur)
		w.Write([]byte(keys.Load().(string)))
	}))
	defer srv.Close()

	c := newSecretClient(srv.Client(), srv.URL, "")
	if got, err := c.list(); err != nil || strings.Join(got, ",") != "a" {
		t.Fatalf("first list: %v, %v", got, err)
	}
	etag.Store(`"l2"`)
	keys.Store(`{"keys":["a","b"]}`)
	if got, err := c.list(); err != nil || strings.Join(got, ",") != "a,b" {
		t.Fatalf("after change: %v, %v", got, err)
	}
}
