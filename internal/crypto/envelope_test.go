package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("super-secret-value")
	aad := []byte("secret:kg/web/SECRET_KEY")

	blob, err := Seal(key, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, pt) {
		t.Fatal("plaintext leaked into ciphertext")
	}
	got, err := Open(key, blob, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, pt)
	}
}

func TestOpenWrongKey(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	blob, _ := Seal(k1, []byte("x"), nil)
	if _, err := Open(k2, blob, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestOpenWrongAAD(t *testing.T) {
	k, _ := GenerateKey()
	blob, _ := Seal(k, []byte("x"), []byte("aad-a"))
	if _, err := Open(k, blob, []byte("aad-b")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestOpenTampered(t *testing.T) {
	k, _ := GenerateKey()
	blob, _ := Seal(k, []byte("hello"), nil)
	blob[len(blob)-1] ^= 0xff
	if _, err := Open(k, blob, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestOpenTooShort(t *testing.T) {
	k, _ := GenerateKey()
	if _, err := Open(k, []byte("short"), nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}
