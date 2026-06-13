// Package crypto implements the envelope-encryption primitives stash is built
// on: a 32-byte key that seals/opens arbitrary plaintext with XChaCha20-
// Poly1305 (AEAD), plus key generation. The store layer composes these into
// the KEK→DEK envelope — see internal/store.
package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeyLen is the length in bytes of every key stash uses (KEK and DEK alike).
const KeyLen = chacha20poly1305.KeySize // 32

// ErrDecrypt is returned when authentication fails — wrong key, wrong AAD, or
// tampered ciphertext. It is deliberately opaque: callers must not branch on
// the precise reason a decryption failed.
var ErrDecrypt = errors.New("stash/crypto: decryption failed")

// GenerateKey returns KeyLen cryptographically-random bytes.
func GenerateKey() ([]byte, error) {
	k := make([]byte, KeyLen)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("stash/crypto: generate key: %w", err)
	}
	return k, nil
}

// Seal encrypts plaintext under key, binding aad (additional authenticated
// data) into the authentication tag. The returned blob is nonce || ciphertext
// and is safe to persist as-is. aad is authenticated but NOT encrypted; the
// same aad must be passed to Open or decryption fails — we use it to bind a
// value to its path so ciphertext can't be replayed at a different key.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("stash/crypto: new cipher: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("stash/crypto: nonce: %w", err)
	}
	// Seal appends the ciphertext to its first argument, so passing the nonce
	// as the prefix yields nonce||ciphertext in a single allocation.
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Open reverses Seal. blob must be nonce || ciphertext and aad must match what
// was passed to Seal. Any mismatch returns ErrDecrypt.
func Open(key, blob, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("stash/crypto: new cipher: %w", err)
	}
	if len(blob) < aead.NonceSize() {
		return nil, ErrDecrypt
	}
	nonce, ct := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
