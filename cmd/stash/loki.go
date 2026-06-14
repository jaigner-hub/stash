package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jaigner-hub/stash/internal/audit"
)

// lokiShipper streams audit entries to a Loki push endpoint, best-effort: the
// durable source of truth is the local hash-chained audit.db, and Loki is the
// aggregated, off-box copy (so a unified, durable view survives a node's disk).
// Drops on a full buffer or a failed push rather than blocking the audit path.
type lokiShipper struct {
	url    string // <base>/loki/api/v1/push
	labels map[string]string
	client *http.Client
	ch     chan audit.Entry
	log    *slog.Logger
}

// newLokiShipper wires a shipper to base (e.g. http://loki:3100) and starts its
// background worker. Pass aud.Stream(shipper.ship) to feed it.
func newLokiShipper(base, node string, client *http.Client, log *slog.Logger) *lokiShipper {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	s := &lokiShipper{
		url:    strings.TrimRight(base, "/") + "/loki/api/v1/push",
		labels: map[string]string{"job": "stash-audit", "node": node},
		client: client,
		ch:     make(chan audit.Entry, 4096),
		log:    log,
	}
	go s.run()
	return s
}

// ship enqueues an entry without blocking (drops + warns if the buffer is full).
func (s *lokiShipper) ship(e audit.Entry) {
	select {
	case s.ch <- e:
	default:
		s.log.Warn("audit loki: buffer full, dropping entry", "seq", e.Seq)
	}
}

func (s *lokiShipper) run() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	var batch []audit.Entry
	flush := func() {
		if len(batch) > 0 {
			s.post(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case e, ok := <-s.ch:
			if !ok {
				flush()
				return
			}
			if batch = append(batch, e); len(batch) >= 500 {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

type lokiPush struct {
	Streams []lokiStream `json:"streams"`
}
type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"` // [ [ "<unix-ns>", "<line>" ], ... ]
}

func (s *lokiShipper) post(batch []audit.Entry) {
	values := make([][2]string, 0, len(batch))
	for _, e := range batch {
		line, err := json.Marshal(e)
		if err != nil {
			continue
		}
		values = append(values, [2]string{lokiTimestamp(e.Time), string(line)})
	}
	body, err := json.Marshal(lokiPush{Streams: []lokiStream{{Stream: s.labels, Values: values}}})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		s.log.Warn("audit loki push failed", "err", err, "entries", len(values))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		s.log.Warn("audit loki push rejected", "status", resp.StatusCode, "entries", len(values))
	}
}

// lokiTimestamp converts an RFC3339Nano time to a Unix-nanoseconds string (Loki's
// required stream-value timestamp), falling back to now if it can't be parsed.
func lokiTimestamp(rfc3339 string) string {
	t, err := time.Parse(time.RFC3339Nano, rfc3339)
	if err != nil {
		t = time.Now()
	}
	return strconv.FormatInt(t.UnixNano(), 10)
}
