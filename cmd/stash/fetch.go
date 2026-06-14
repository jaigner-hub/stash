package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// secretClient fetches secret values over HTTP for the agent. It remembers the
// ETag and value last seen for each path and revalidates with If-None-Match, so
// a steady poll of unchanged secrets gets a 304 back: no body transferred and,
// on the server side, no audit entry. That 304 path is what keeps the agent's
// render loop from flooding the audit log (see the server's get handler).
type secretClient struct {
	http  *http.Client
	base  string // trimmed API base URL
	token string // bearer token; empty in open mode

	mu     sync.Mutex
	cached map[string]cachedSecret
}

type cachedSecret struct {
	etag  string
	value string
}

func newSecretClient(c *http.Client, base, token string) *secretClient {
	return &secretClient{http: c, base: base, token: token, cached: map[string]cachedSecret{}}
}

// fetch returns the plaintext value at path (an agent.Fetcher). On a 304 it
// returns the value cached from the last 200 for that path.
func (s *secretClient) fetch(path string) (string, error) {
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	req, err := http.NewRequest(http.MethodGet, s.base+"/v1/secret/"+strings.Join(segs, "/"), nil)
	if err != nil {
		return "", err
	}
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	s.mu.Lock()
	prev, hasPrev := s.cached[path]
	s.mu.Unlock()
	if hasPrev && prev.etag != "" {
		req.Header.Set("If-None-Match", prev.etag)
	}

	resp, err := s.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		if !hasPrev {
			// Unchanged-but-nothing-cached can't happen unless we sent no
			// validator; treat it as a protocol error rather than render "".
			return "", fmt.Errorf("fetch %s: 304 with no cached value", path)
		}
		return prev.value, nil
	case http.StatusOK:
		var body struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return "", err
		}
		s.mu.Lock()
		s.cached[path] = cachedSecret{etag: resp.Header.Get("ETag"), value: body.Value}
		s.mu.Unlock()
		return body.Value, nil
	default:
		return "", fmt.Errorf("fetch %s: status %d", path, resp.StatusCode)
	}
}
