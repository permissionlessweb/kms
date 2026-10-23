package bluetooth

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSealedSecretDoesNotContainTheSeed(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x41}, 32)
	plain := bytes.Repeat([]byte{0x42}, 32)
	path := filepath.Join(dir, "ephemeral.bin")
	if err := WriteSecret(path, key, plain); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, plain) || !IsSealed(blob) {
		t.Fatal("seed was stored in the clear")
	}
	got, err := ReadSecret(path, key)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "legacy.bin")
	if err := os.WriteFile(legacy, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = ReadSecret(legacy, key)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal(err)
	}
	again, err := os.ReadFile(legacy)
	if err != nil || bytes.Contains(again, plain) || !IsSealed(again) {
		t.Fatal("legacy seed was left in the clear")
	}
}

func TestFingerprintMatchesThePhoneVector(t *testing.T) {
	got := Fingerprint(bytes.Repeat([]byte{0x11}, 32))
	if got != "02 d4 49 a3 1f bb 26 7c" {
		t.Fatal(got)
	}
	if Fingerprint(bytes.Repeat([]byte{0x12}, 32)) == got {
		t.Fatal("different key, same fingerprint")
	}
}
