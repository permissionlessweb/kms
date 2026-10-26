package bluetooth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Per-validator phone pins.
//
// A slot (config chain id with "/" -> "_", e.g. morocco-1_zcinti2) is served
// only by the phone whose Noise static is in peers/<slot>.peer. A slot with
// no file of its own falls back to the legacy global phone.peer, so a KMS
// that was paired before per-slot pins keeps every slot on that phone with
// no re-pair. A static listed in peers/<slot>.retired is refused for that
// slot forever, including through the global fallback.
//
// peers/<slot>.handoff holds a freeze and a height floor while a key moves
// between phones: a frozen slot signs nothing, and after the move nothing
// at or below the floor is sent to any phone.

var slotMu sync.Mutex

// ErrSlotFrozen refuses a vote while the slot's key is moving.
var ErrSlotFrozen = errors.New("bluetooth: slot is frozen for a key handoff")

func validLabel(label string) error {
	if label == "" || len(label) > 96 || strings.Contains(label, "/") || strings.Contains(label, "..") || strings.ContainsAny(label, "\\\x00") {
		return fmt.Errorf("bluetooth: bad slot label %q", label)
	}
	return nil
}

func peersDir(dir string) (string, error) {
	base := dir
	if dir == Dir {
		var err error
		if base, err = supportDir(); err != nil {
			return "", err
		}
	}
	p := filepath.Join(base, "peers")
	return p, os.MkdirAll(p, 0o700)
}

func globalPinPath(dir string) (string, error) {
	if dir == Dir {
		return phonePeerPath()
	}
	return filepath.Join(dir, "phone.peer"), nil
}

func read32(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil || len(b) != 32 {
		return nil
	}
	return b
}

// slotPin is the phone that serves label: its own pin, else the legacy global pin.
func slotPin(dir, label string) ([]byte, bool, error) {
	if err := validLabel(label); err != nil {
		return nil, false, err
	}
	pd, err := peersDir(dir)
	if err != nil {
		return nil, false, err
	}
	if b := read32(filepath.Join(pd, label+".peer")); b != nil {
		return b, true, nil
	}
	gp, err := globalPinPath(dir)
	if err != nil {
		return nil, false, err
	}
	return read32(gp), false, nil
}

func isRetired(dir, label string, pub []byte) bool {
	pd, err := peersDir(dir)
	if err != nil {
		return true
	}
	raw, err := os.ReadFile(filepath.Join(pd, label+".retired"))
	if err != nil {
		return false
	}
	for i := 0; i+32 <= len(raw); i += 32 {
		if bytes.Equal(raw[i:i+32], pub) {
			return true
		}
	}
	return false
}

// anySlotPinned reports whether pub is the pin of some slot (or the global pin).
func anySlotPinned(dir string, pub []byte) bool {
	if gp, err := globalPinPath(dir); err == nil {
		if b := read32(gp); b != nil && bytes.Equal(b, pub) {
			return true
		}
	}
	pd, err := peersDir(dir)
	if err != nil {
		return false
	}
	files, _ := filepath.Glob(filepath.Join(pd, "*.peer"))
	for _, f := range files {
		if b := read32(f); b != nil && bytes.Equal(b, pub) {
			return true
		}
	}
	return false
}

// SlotAllows checks that pub may sign for label.
func SlotAllows(label string, pub []byte) error { return slotAllows(Dir, label, pub) }

func slotAllows(dir, label string, pub []byte) error {
	slotMu.Lock()
	defer slotMu.Unlock()
	if len(pub) != 32 {
		return errors.New("bluetooth: phone identity is not a public key")
	}
	pin, _, err := slotPin(dir, label)
	if err != nil {
		return err
	}
	if isRetired(dir, label, pub) {
		return fmt.Errorf("bluetooth: phone %s is retired for %s", Fingerprint(pub), label)
	}
	if pin == nil || !bytes.Equal(pin, pub) {
		return fmt.Errorf("bluetooth: phone %s is not pinned for %s", Fingerprint(pub), label)
	}
	return nil
}

// SlotPinFingerprint is the fingerprint of the phone serving label ("" if none).
func SlotPinFingerprint(label string) string {
	slotMu.Lock()
	defer slotMu.Unlock()
	pin, _, err := slotPin(Dir, label)
	if err != nil || pin == nil || isRetired(Dir, label, pin) {
		return ""
	}
	return Fingerprint(pin)
}

// SlotPinPub is the static of the phone serving label (nil if none).
func SlotPinPub(label string) []byte {
	slotMu.Lock()
	defer slotMu.Unlock()
	pin, _, err := slotPin(Dir, label)
	if err != nil || pin == nil || isRetired(Dir, label, pin) {
		return nil
	}
	return pin
}

// PendingPub is the static of the phone waiting to be confirmed (nil if none).
func PendingPub() []byte { return read32(filepath.Join(Dir, "phone.pending")) }

// PinSlot pins pub as the only phone for label. A retired phone is refused.
func PinSlot(label string, pub []byte) error { return pinSlot(Dir, label, pub) }

func pinSlot(dir, label string, pub []byte) error {
	slotMu.Lock()
	defer slotMu.Unlock()
	if err := validLabel(label); err != nil {
		return err
	}
	if len(pub) != 32 {
		return errors.New("bluetooth: phone identity is not a public key")
	}
	if isRetired(dir, label, pub) {
		return errors.New("bluetooth: that phone is retired for this slot")
	}
	pd, err := peersDir(dir)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(pd, label+".peer"), pub)
}

// RetirePeer refuses pub for label from now on and drops its pin there.
// Other slots pinned to the same phone are untouched.
func RetirePeer(label string, pub []byte) error { return retirePeer(Dir, label, pub) }

func retirePeer(dir, label string, pub []byte) error {
	slotMu.Lock()
	defer slotMu.Unlock()
	if err := validLabel(label); err != nil {
		return err
	}
	if len(pub) != 32 {
		return errors.New("bluetooth: phone identity is not a public key")
	}
	pd, err := peersDir(dir)
	if err != nil {
		return err
	}
	if !isRetired(dir, label, pub) {
		path := filepath.Join(pd, label+".retired")
		old, _ := os.ReadFile(path)
		if err := writeAtomic(path, append(append([]byte(nil), old...), pub...)); err != nil {
			return err
		}
	}
	own := filepath.Join(pd, label+".peer")
	if b := read32(own); b != nil && bytes.Equal(b, pub) {
		return os.Remove(own)
	}
	return nil
}

// Handoff is the freeze and floor of one slot.
type Handoff struct {
	Frozen bool   `json:"frozen"`
	Floor  uint64 `json:"floor"`
	// Sent: the new phone holds the key. Until retire the move cannot be
	// cancelled, and it survives a console restart (Chain..Target, hex).
	Sent   bool   `json:"sent,omitempty"`
	Chain  string `json:"chain,omitempty"`
	Slot   string `json:"slot,omitempty"`
	Nonce  string `json:"nonce,omitempty"`
	KeyPub string `json:"key_pub,omitempty"`
	Old    string `json:"old,omitempty"`
	Target string `json:"target,omitempty"`
}

// SetHandoff stores the freeze and floor for label. The floor never goes down.
func SetHandoff(label string, h Handoff) error { return setHandoff(Dir, label, h) }

func setHandoff(dir, label string, h Handoff) error {
	slotMu.Lock()
	defer slotMu.Unlock()
	if err := validLabel(label); err != nil {
		return err
	}
	cur, err := readHandoff(dir, label)
	if err != nil {
		return err
	}
	if cur.Floor > h.Floor {
		h.Floor = cur.Floor
	}
	if cur.Sent && h.Frozen && !h.Sent {
		// Only finish (unfreeze) clears a sent move.
		h.Sent, h.Chain, h.Slot, h.Nonce, h.KeyPub, h.Old, h.Target = true, cur.Chain, cur.Slot, cur.Nonce, cur.KeyPub, cur.Old, cur.Target
	}
	pd, err := peersDir(dir)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(h)
	return writeAtomic(filepath.Join(pd, label+".handoff"), raw)
}

// GetHandoff reads the freeze and floor for label.
func GetHandoff(label string) (Handoff, error) {
	slotMu.Lock()
	defer slotMu.Unlock()
	return readHandoff(Dir, label)
}

func readHandoff(dir, label string) (Handoff, error) {
	var h Handoff
	pd, err := peersDir(dir)
	if err != nil {
		return h, err
	}
	raw, err := os.ReadFile(filepath.Join(pd, label+".handoff"))
	if os.IsNotExist(err) {
		return h, nil
	}
	if err != nil {
		return h, err
	}
	if json.Unmarshal(raw, &h) != nil {
		// A damaged handoff file fails closed.
		return Handoff{Frozen: true}, nil
	}
	return h, nil
}

// handoffGate refuses a vote for a frozen slot or at/below its floor.
func handoffGate(dir, label string, height uint64) error {
	slotMu.Lock()
	h, err := readHandoff(dir, label)
	slotMu.Unlock()
	if err != nil {
		return err
	}
	if h.Frozen {
		return ErrSlotFrozen
	}
	if h.Floor > 0 && height <= h.Floor {
		return fmt.Errorf("bluetooth: height %d is at or below the handoff floor %d for %s", height, h.Floor, label)
	}
	return nil
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Tombstone is the KMS record that a phone retired a slot's key.
type Tombstone struct {
	KeyID   string `json:"key_id"`
	OldPeer string `json:"old_peer"`
	NewPeer string `json:"new_peer"`
	Floor   uint64 `json:"floor"`
	Nonce   string `json:"nonce"`
	Sig     string `json:"sig"`
	At      string `json:"at"`
}

// RecordTombstone appends t to peers/<label>.tomb (one JSON per line).
func RecordTombstone(label string, t Tombstone) error { return recordTombstone(Dir, label, t) }

func recordTombstone(dir, label string, t Tombstone) error {
	slotMu.Lock()
	defer slotMu.Unlock()
	if err := validLabel(label); err != nil {
		return err
	}
	pd, err := peersDir(dir)
	if err != nil {
		return err
	}
	line, _ := json.Marshal(t)
	f, err := os.OpenFile(filepath.Join(pd, label+".tomb"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// LastTombstone is the newest tombstone for label (ok false if none).
func LastTombstone(label string) (Tombstone, bool) { return lastTombstone(Dir, label) }

func lastTombstone(dir, label string) (Tombstone, bool) {
	slotMu.Lock()
	defer slotMu.Unlock()
	var t Tombstone
	if validLabel(label) != nil {
		return t, false
	}
	pd, err := peersDir(dir)
	if err != nil {
		return t, false
	}
	raw, err := os.ReadFile(filepath.Join(pd, label+".tomb"))
	if err != nil {
		return t, false
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if json.Unmarshal([]byte(lines[len(lines)-1]), &t) != nil {
		return t, false
	}
	return t, true
}

// PendingPubAt is the static waiting to be confirmed under home.
func PendingPubAt(home string) []byte { return read32(filepath.Join(home, "phone.pending")) }
