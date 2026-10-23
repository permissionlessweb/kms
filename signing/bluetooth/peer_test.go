package bluetooth

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestUnknownPhoneIsNotPinned(t *testing.T) {
	dir := t.TempDir()
	pub := bytes.Repeat([]byte{0x44}, 32)
	if err := acceptPhone(dir, pub); err == nil {
		t.Fatal("missing pin trusted the phone")
	}
	pending, err := os.ReadFile(filepath.Join(dir, "phone.pending"))
	if err != nil || !bytes.Equal(pending, pub) {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "phone.peer"), bytes.Repeat([]byte{0x45}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := acceptPhone(dir, pub); err == nil {
		t.Fatal("different phone was accepted")
	}
	if err := acceptPhone(dir, bytes.Repeat([]byte{0x45}, 32)); err != nil {
		t.Fatal(err)
	}
}
