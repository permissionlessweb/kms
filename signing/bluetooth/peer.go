package bluetooth

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SupportDir, when set, replaces ~/Library/Application Support/terp-kms
// (tests point it at a temp dir).
var SupportDir string

func supportDir() (string, error) {
	if SupportDir != "" {
		return SupportDir, os.MkdirAll(SupportDir, 0o700)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "Library", "Application Support", "terp-kms")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func phonePeerPath() (string, error) {
	dir, err := supportDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "phone.peer"), nil
}

// AcceptPhone refuses a Noise responder that is not pinned for any slot
// (or the legacy global pin). Which slots it may sign for is checked per
// vote by SlotAllows.
// A missing pin does not trust the next peer. The public key is left in
// phone.pending so the operator can confirm that fingerprint.
func AcceptPhone(pub []byte) error {
	return acceptPhone(Dir, pub)
}

func acceptPhone(dir string, pub []byte) error {
	if len(pub) != 32 {
		return errors.New("bluetooth: phone identity is not a public key")
	}
	path := filepath.Join(dir, "phone.peer")
	pending := filepath.Join(dir, "phone.pending")
	if dir == Dir {
		var err error
		path, err = phonePeerPath()
		if err != nil {
			return err
		}
	}
	if anySlotPinned(dir, pub) {
		_ = os.Remove(pending)
		return nil
	}
	pin, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err := os.WriteFile(pending, pub, 0o600); err != nil {
			return err
		}
		return fmt.Errorf("bluetooth: confirm phone %s", Fingerprint(pub))
	}
	if len(pin) != 32 || !bytes.Equal(pin, pub) {
		// A phone pinned for no slot waits in phone.pending so a handoff can
		// confirm it for one slot without replacing the global pin.
		_ = os.WriteFile(pending, pub, 0o600)
		return errors.New("bluetooth: phone is not the pinned signer")
	}
	_ = os.Remove(pending)
	return nil
}

// ConfirmPhone admits the pending responder after the operator compared its
// fingerprint tiles. The first phone becomes the global pin (every slot
// without its own pin). A later phone only joins the device registry: it is
// a mesh member with no slots, and gets slots through a key move, so
// confirming a second phone never moves a live validator. It returns the
// confirmed Noise static.
func ConfirmPhone() ([]byte, error) { return confirmPhone(Dir) }

func confirmPhone(home string) ([]byte, error) {
	pending, err := os.ReadFile(filepath.Join(home, "phone.pending"))
	if err != nil || len(pending) != 32 {
		return nil, errors.New("bluetooth: no phone is waiting to be confirmed")
	}
	path, err := globalPinPath(home)
	if err != nil {
		return nil, err
	}
	if cur := read32(path); cur == nil {
		if err := writeAtomic(path, pending); err != nil {
			return nil, err
		}
	}
	if err := registerDevice(home, pending, "", ""); err != nil {
		return nil, err
	}
	return pending, os.Remove(filepath.Join(home, "phone.pending"))
}

// PhonePinned reports whether a confirmed phone identity is stored.
func PhonePinned() bool {
	path, err := phonePeerPath()
	if err != nil {
		return false
	}
	pin, err := os.ReadFile(path)
	return err == nil && len(pin) == 32
}

// PendingPhone is the fingerprint of a responder that is not pinned yet.
func PendingPhone() string {
	pending, err := os.ReadFile(filepath.Join(Dir, "phone.pending"))
	if err != nil || len(pending) != 32 {
		return ""
	}
	return Fingerprint(pending)
}

// extensionHeightRound reads the height and round from a canonical vote extension.
// A missing round field is round 0, which protobuf omits.
func extensionHeightRound(msg []byte) (uint64, uint32, bool) {
	i := 0
	for i < len(msg) && msg[i]&0x80 != 0 {
		i++
	}
	if i >= len(msg) {
		return 0, 0, false
	}
	i++
	if i >= len(msg) {
		return 0, 0, false
	}
	if msg[i] == 0x0a {
		i++
		if i >= len(msg) {
			return 0, 0, false
		}
		n := int(msg[i])
		i += 1 + n
	}
	if i >= len(msg) || msg[i] != 0x11 || i+9 > len(msg) {
		return 0, 0, false
	}
	i++
	height := binary.LittleEndian.Uint64(msg[i : i+8])
	i += 8
	var round uint64
	if i < len(msg) && msg[i] == 0x19 && i+9 <= len(msg) {
		i++
		round = binary.LittleEndian.Uint64(msg[i : i+8])
	}
	return height, uint32(round), true
}
