package bluetooth

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
)

const sealedMagic = "ZC01"

// AtRestKey is the key that wraps secrets stored under /tmp.
// The key itself lives in the user application-support directory, not beside
// the ciphertext.
func AtRestKey() ([]byte, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, "Library", "Application Support", "terp-kms")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "atrest.key")
	b, err := os.ReadFile(path)
	if err == nil && len(b) == 32 {
		return b, nil
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

// SealBlob encrypts plain with a random nonce. The same plaintext seals to a
// different file each time.
func SealBlob(key, plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	box := aead.Seal(nil, nonce[:], plain, []byte(sealedMagic))
	out := make([]byte, 0, len(sealedMagic)+len(nonce)+len(box))
	out = append(out, sealedMagic...)
	out = append(out, nonce[:]...)
	out = append(out, box...)
	return out, nil
}

// OpenBlob reverses SealBlob.
func OpenBlob(key, blob []byte) ([]byte, error) {
	if !IsSealed(blob) {
		return nil, errors.New("bluetooth: secret is not sealed")
	}
	rest := blob[len(sealedMagic):]
	if len(rest) < 12+16 {
		return nil, errors.New("bluetooth: sealed secret is short")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, rest[:12], rest[12:], []byte(sealedMagic))
}

// IsSealed reports whether a file starts with the at-rest header.
func IsSealed(blob []byte) bool {
	return len(blob) >= len(sealedMagic) && string(blob[:len(sealedMagic)]) == sealedMagic
}

// ReadSecret returns the plaintext of a sealed file. A legacy 32-byte seed is
// accepted once and rewritten sealed.
func ReadSecret(path string, key []byte) ([]byte, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if IsSealed(blob) {
		return OpenBlob(key, blob)
	}
	if len(blob) == 32 {
		if err := WriteSecret(path, key, blob); err != nil {
			return nil, err
		}
		return append([]byte(nil), blob...), nil
	}
	return nil, errors.New("bluetooth: secret file is not a seed")
}

// WriteSecret stores plain sealed at path.
func WriteSecret(path string, key, plain []byte) error {
	blob, err := SealBlob(key, plain)
	if err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o600)
}
