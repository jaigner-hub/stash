package cluster

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"
)

// Capabilities.
const (
	CapRead   = "read"
	CapWrite  = "write"
	CapDelete = "delete"
)

// Policy grants a set of capabilities under a path prefix. An empty prefix or
// "*" matches all paths; "*" in Caps grants all capabilities.
type Policy struct {
	Prefix string   `json:"prefix"`
	Caps   []string `json:"caps"`
}

// Identity is a machine identity: a named bearer token (stored only as a hash)
// with policies. Admin identities bypass policy checks and may manage identities.
type Identity struct {
	Name      string   `json:"name"`
	TokenHash string   `json:"token_hash"` // hex sha256 of the token
	Admin     bool     `json:"admin"`
	Policies  []Policy `json:"policies"`
	Created   string   `json:"created"`
}

// Can reports whether the identity may perform cap on path.
func (i *Identity) Can(cap, path string) bool {
	if i.Admin {
		return true
	}
	for _, p := range i.Policies {
		if prefixMatch(p.Prefix, path) && capMatch(p.Caps, cap) {
			return true
		}
	}
	return false
}

func prefixMatch(prefix, path string) bool {
	return prefix == "" || prefix == "*" || strings.HasPrefix(path, prefix)
}

func capMatch(caps []string, want string) bool {
	for _, c := range caps {
		if c == want || c == "*" {
			return true
		}
	}
	return false
}

// Redacted returns a copy without the token hash, for listing over the API.
func (i Identity) Redacted() Identity {
	i.TokenHash = ""
	return i
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newToken() (string, error) {
	b := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return "stash-" + base64.RawURLEncoding.EncodeToString(b), nil
}

// CreateIdentity mints a new identity, returns its token once (never recoverable
// afterwards), and replicates the record via Raft. Leader-only.
func (n *Node) CreateIdentity(name string, admin bool, policies []Policy) (string, error) {
	if name == "" {
		return "", errors.New("stash/cluster: identity name required")
	}
	token, err := newToken()
	if err != nil {
		return "", err
	}
	id := Identity{
		Name:      name,
		TokenHash: hashToken(token),
		Admin:     admin,
		Policies:  policies,
		Created:   nowRFC3339(),
	}
	rec, err := json.Marshal(id)
	if err != nil {
		return "", err
	}
	if err := n.apply(command{Op: opPutIdentity, IdentityName: name, IdentityRecord: rec}); err != nil {
		return "", err
	}
	return token, nil
}

// DeleteIdentity removes an identity by name. Leader-only.
func (n *Node) DeleteIdentity(name string) error {
	return n.apply(command{Op: opDeleteIdentity, IdentityName: name})
}

// ListIdentities returns all identities (token hashes redacted), sorted by name.
func (n *Node) ListIdentities() ([]Identity, error) {
	raw, err := n.store.ListIdentitiesRaw()
	if err != nil {
		return nil, err
	}
	out := make([]Identity, 0, len(raw))
	for _, rec := range raw {
		var id Identity
		if err := json.Unmarshal(rec, &id); err != nil {
			continue
		}
		out = append(out, id.Redacted())
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

// HasIdentities reports whether any identity exists. When false, the server runs
// in "open mode" (no auth) so an upgraded cluster isn't locked out until the
// first identity is created.
func (n *Node) HasIdentities() bool {
	raw, err := n.store.ListIdentitiesRaw()
	return err == nil && len(raw) > 0
}

// Authenticate resolves a bearer token to its identity, or (nil, nil) if no
// identity matches. The token hash is compared in constant time.
func (n *Node) Authenticate(token string) (*Identity, error) {
	if token == "" {
		return nil, nil
	}
	want := hashToken(token)
	raw, err := n.store.ListIdentitiesRaw()
	if err != nil {
		return nil, err
	}
	for _, rec := range raw {
		var id Identity
		if err := json.Unmarshal(rec, &id); err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(id.TokenHash)) == 1 {
			return &id, nil
		}
	}
	return nil, nil
}

// ensureRootIdentity creates an admin "root" identity if none exists, returning
// the new token (empty if one already existed). Called at bootstrap.
func (n *Node) ensureRootIdentity() (string, error) {
	if n.HasIdentities() {
		return "", nil
	}
	return n.CreateIdentity("root", true, nil)
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
