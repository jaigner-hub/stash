package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jaigner-hub/stash/internal/audit"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestLokiShipperPost(t *testing.T) {
	var gotPath string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := newLokiShipper(srv.URL, "vent.dog", srv.Client(), discardLog())
	when := "2026-06-14T00:00:00.5Z"
	s.post([]audit.Entry{
		{Seq: 1, Time: when, Identity: "alice", Action: "read", Path: "kg/web/A", Result: "ok", Node: "vent.dog", Hash: "abc"},
	})

	if gotPath != "/loki/api/v1/push" {
		t.Fatalf("push path = %q", gotPath)
	}
	var push lokiPush
	if err := json.Unmarshal(gotBody, &push); err != nil {
		t.Fatalf("bad push body: %v\n%s", err, gotBody)
	}
	if len(push.Streams) != 1 {
		t.Fatalf("streams = %d", len(push.Streams))
	}
	st := push.Streams[0]
	if st.Stream["job"] != "stash-audit" || st.Stream["node"] != "vent.dog" {
		t.Fatalf("labels = %v", st.Stream)
	}
	if len(st.Values) != 1 {
		t.Fatalf("values = %d", len(st.Values))
	}
	parsed, _ := time.Parse(time.RFC3339Nano, when)
	if wantTS := strconv.FormatInt(parsed.UnixNano(), 10); st.Values[0][0] != wantTS {
		t.Fatalf("timestamp = %q, want %q", st.Values[0][0], wantTS)
	}
	if !strings.Contains(st.Values[0][1], `"path":"kg/web/A"`) {
		t.Fatalf("line missing entry JSON: %q", st.Values[0][1])
	}
}

// A bad URL / dead Loki must not panic or block — push is best-effort.
func TestLokiShipperPostFailsQuietly(t *testing.T) {
	s := newLokiShipper("http://127.0.0.1:1", "n", &http.Client{Timeout: time.Second}, discardLog())
	s.post([]audit.Entry{{Seq: 1, Time: "2026-06-14T00:00:00Z", Action: "read"}}) // no panic, returns
}
