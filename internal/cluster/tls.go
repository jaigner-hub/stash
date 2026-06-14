package cluster

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jaigner-hub/stash/internal/pki"
)

func (n *Node) tlsEnabled() bool { return len(n.cfg.CertPEM) > 0 }

// ServerTLSConfig returns the TLS config for the HTTPS API listener, or nil when
// TLS is disabled. Browsers without a client cert are allowed (token auth);
// node-to-node forwarding presents a cert and is verified.
func (n *Node) ServerTLSConfig() *tls.Config {
	if !n.tlsEnabled() {
		return nil
	}
	cfg, err := pki.ServerConfig(n.cfg.CertPEM, n.cfg.KeyPEM, n.cfg.CACertPEM)
	if err != nil {
		return nil // material was validated in New
	}
	return cfg
}

// OutboundTLS returns the client TLS config for forwarding to the leader, or nil.
func (n *Node) OutboundTLS() *tls.Config {
	if !n.tlsEnabled() {
		return nil
	}
	cfg, err := pki.ClientConfig(n.cfg.CertPEM, n.cfg.KeyPEM, n.cfg.CACertPEM)
	if err != nil {
		return nil
	}
	return cfg
}

// tlsStreamLayer is a raft.StreamLayer that dials/accepts over mutual TLS. Addr
// returns the advertised address (not the bind address) so Raft hands peers a
// reachable address even when bound to 0.0.0.0.
type tlsStreamLayer struct {
	ln        net.Listener
	advertise net.Addr
	dial      *tls.Config
}

func newTLSStreamLayer(bind string, advertise net.Addr, server, client *tls.Config) (*tlsStreamLayer, error) {
	ln, err := tls.Listen("tcp", bind, server)
	if err != nil {
		return nil, err
	}
	return &tlsStreamLayer{ln: ln, advertise: advertise, dial: client}, nil
}

func (t *tlsStreamLayer) Accept() (net.Conn, error) { return t.ln.Accept() }
func (t *tlsStreamLayer) Close() error              { return t.ln.Close() }
func (t *tlsStreamLayer) Addr() net.Addr            { return t.advertise }
func (t *tlsStreamLayer) Dial(addr raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", string(addr), t.dial)
}
