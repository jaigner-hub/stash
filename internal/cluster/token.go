package cluster

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const tokenPrefix = "stash1."

// JoinToken is the single opaque value a new node needs to join a cluster. It
// bundles the rendezvous (LeaderAPI), the membership secret, and — for the easy
// path — the unseal key itself, so an operator copies one value instead of two.
//
// SECURITY: when UnsealKey is set the token can decrypt every secret in the
// cluster. Treat it like the master key: short-lived handling, never paste it
// into shared logs/chat, prefer a trusted network. Use a keyless token
// (--no-key) for witnesses and for any posture where the KEK stays in SOPS.
type JoinToken struct {
	ClusterID string `json:"cid"`
	LeaderAPI string `json:"api"`           // e.g. https://10.0.0.1:8200
	Secret    string `json:"sec"`           // cluster membership secret
	UnsealKey string `json:"key,omitempty"` // base64 KEK; omitted for keyless tokens
	// For TLS clusters, the CA (base64 PEM) so a joiner can issue its own leaf.
	CACert string `json:"ca,omitempty"`
	CAKey  string `json:"cak,omitempty"`
}

// Encode renders the token as a copy-pasteable string.
func (t JoinToken) Encode() (string, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeToken parses a token string produced by Encode.
func DecodeToken(s string) (*JoinToken, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, tokenPrefix) {
		return nil, errors.New("stash/cluster: not a stash join token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, tokenPrefix))
	if err != nil {
		return nil, fmt.Errorf("stash/cluster: malformed token: %w", err)
	}
	var t JoinToken
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("stash/cluster: malformed token: %w", err)
	}
	if t.ClusterID == "" || t.LeaderAPI == "" || t.Secret == "" {
		return nil, errors.New("stash/cluster: incomplete token")
	}
	return &t, nil
}

// HasKey reports whether the token carries an unseal key.
func (t JoinToken) HasKey() bool { return t.UnsealKey != "" }

// HasTLS reports whether the token carries CA material (a TLS cluster).
func (t JoinToken) HasTLS() bool { return t.CACert != "" }

// LocalConfig is a node's local cluster membership state, persisted next to the
// data dir (cluster.json) so the node can mint further join tokens and so a
// restart recovers its own identity/addresses without re-typing flags. It
// deliberately does NOT hold the unseal key (that lives in its own 0600 file).
type LocalConfig struct {
	// Cluster-wide.
	ClusterID string `json:"cluster_id"`
	Secret    string `json:"join_secret"`
	LeaderAPI string `json:"leader_api"`
	// This node's own identity/addresses (for restart).
	NodeID        string `json:"node_id"`
	Listen        string `json:"listen"`
	RaftBind      string `json:"raft_bind"`
	RaftAdvertise string `json:"raft_advertise"`
	HTTPAdvertise string `json:"http_advertise"`
}

func localConfigPath(dir string) string { return filepath.Join(dir, "cluster.json") }

// WriteLocalConfig persists c to <dir>/cluster.json with 0600 perms.
func WriteLocalConfig(dir string, c LocalConfig) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(localConfigPath(dir), b, 0o600)
}

// ReadLocalConfig loads <dir>/cluster.json.
func ReadLocalConfig(dir string) (*LocalConfig, error) {
	b, err := os.ReadFile(localConfigPath(dir))
	if err != nil {
		return nil, err
	}
	var c LocalConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("stash/cluster: bad cluster.json: %w", err)
	}
	return &c, nil
}

// OutboundIP returns the local IP the OS would use to reach hostPort. It opens
// no real connection (UDP dial just selects a route), so it works offline and
// gives the address a peer on the same network will see — letting a joiner
// self-detect its address instead of the operator typing one.
func OutboundIP(hostPort string) (string, error) {
	conn, err := net.Dial("udp", hostPort)
	if err != nil {
		return "", fmt.Errorf("stash/cluster: detect outbound ip: %w", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

// APIHostPort extracts host:port from an API URL, supplying a default port for
// the scheme when none is present (needed for OutboundIP's UDP dial).
func APIHostPort(apiURL string) (string, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return "", fmt.Errorf("stash/cluster: bad api url %q: %w", apiURL, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("stash/cluster: bad api url %q", apiURL)
	}
	if u.Port() != "" {
		return u.Host, nil
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443"), nil
	}
	return net.JoinHostPort(u.Hostname(), "80"), nil
}

func randomHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
