package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
)

func TestGenerateAndIssue(t *testing.T) {
	caCert, caKey, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := IssueCert(caCert, caKey, "node1", []string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	// Leaf must be a valid keypair.
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		t.Fatalf("keypair: %v", err)
	}
	// Leaf must verify against the CA, including the IP SAN.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCert) {
		t.Fatal("append CA")
	}
	block, _ := pem.Decode(cert)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	found := false
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			found = true
		}
	}
	if !found {
		t.Fatal("missing 127.0.0.1 IP SAN")
	}
}

func TestConfigsBuild(t *testing.T) {
	caCert, caKey, _ := GenerateCA()
	cert, key, _ := IssueCert(caCert, caKey, "n", []string{"127.0.0.1"})
	if _, err := ServerConfig(cert, key, caCert); err != nil {
		t.Fatal(err)
	}
	if _, err := MutualServerConfig(cert, key, caCert); err != nil {
		t.Fatal(err)
	}
	if _, err := ClientConfig(cert, key, caCert); err != nil {
		t.Fatal(err)
	}
	if _, err := CAOnlyConfig(caCert); err != nil {
		t.Fatal(err)
	}
}
