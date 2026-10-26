package bluetooth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSecret(t *testing.T) []byte {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(priv)
}

func TestRetireProofV2(t *testing.T) {
	sec := testSecret(t)
	pub := sec[32:]
	var nonce [NonceSize]byte
	rand.Read(nonce[:])
	target := bytes.Repeat([]byte{0xB}, 32)
	sig := ed25519.Sign(ed25519.PrivateKey(sec), RetireMessageV2("morocco-1", "zcinti2", pub, 100, nonce, target))
	q := RetiredPrefixV2 + base64.StdEncoding.EncodeToString(target) + ":" + base64.StdEncoding.EncodeToString(sig)
	got, _, err := VerifyRetireV2(q, "morocco-1", "zcinti2", pub, 100, nonce)
	if err != nil || !bytes.Equal(got, target) {
		t.Fatal(err)
	}
	// phone format
	if want := "zcinti-retire:2|morocco-1|zcinti2|" + KeyIDHex(pub) + "|100|"; !strings.HasPrefix(string(RetireMessageV2("morocco-1", "zcinti2", pub, 100, nonce, target)), want) {
		t.Fatal("message format")
	}
	var n2 [NonceSize]byte
	if _, _, err := VerifyRetireV2(q, "morocco-1", "zcinti2", pub, 100, n2); err == nil {
		t.Fatal("other nonce accepted (replay)")
	}
	if _, _, err := VerifyRetireV2(q, "morocco-1", "zcinti2", pub, 101, nonce); err == nil {
		t.Fatal("other floor accepted")
	}
	if _, _, err := VerifyRetireV2(q, "morocco-1", "zcinti", pub, 100, nonce); err == nil {
		t.Fatal("other slot accepted")
	}
	other := testSecret(t)
	if _, _, err := VerifyRetireV2(q, "morocco-1", "zcinti2", other[32:], 100, nonce); err == nil {
		t.Fatal("other key accepted")
	}
	swapped := RetiredPrefixV2 + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xC}, 32)) + ":" + base64.StdEncoding.EncodeToString(sig)
	if _, _, err := VerifyRetireV2(swapped, "morocco-1", "zcinti2", pub, 100, nonce); err == nil {
		t.Fatal("swapped target accepted")
	}
	if _, _, err := VerifyRetireV2("zcinti-retired:1:AAAA", "morocco-1", "zcinti2", pub, 100, nonce); err == nil {
		t.Fatal("v1 accepted")
	}
}

func TestSlotPinMigrationAndRetire(t *testing.T) {
	dir := t.TempDir()
	a := bytes.Repeat([]byte{0xA}, 32)
	b := bytes.Repeat([]byte{0xB}, 32)
	// legacy global pin serves every slot
	os.WriteFile(filepath.Join(dir, "phone.peer"), a, 0o600)
	for _, l := range []string{"morocco-1_zcinti", "morocco-1_zcinti2"} {
		if err := slotAllows(dir, l, a); err != nil {
			t.Fatal(l, err)
		}
	}
	if slotAllows(dir, "morocco-1_zcinti2", b) == nil {
		t.Fatal("unpinned phone allowed")
	}
	// move zcinti2 to b
	if err := pinSlot(dir, "morocco-1_zcinti2", b); err != nil {
		t.Fatal(err)
	}
	if err := retirePeer(dir, "morocco-1_zcinti2", a); err != nil {
		t.Fatal(err)
	}
	if slotAllows(dir, "morocco-1_zcinti2", a) == nil {
		t.Fatal("retired phone still signs moved slot")
	}
	if err := slotAllows(dir, "morocco-1_zcinti2", b); err != nil {
		t.Fatal(err)
	}
	if err := slotAllows(dir, "morocco-1_zcinti", a); err != nil {
		t.Fatal("other slot cut off:", err)
	}
	if slotAllows(dir, "morocco-1_zcinti", b) == nil {
		t.Fatal("new phone got the other slot")
	}
	if pinSlot(dir, "morocco-1_zcinti2", a) == nil {
		t.Fatal("re-pinned a retired phone")
	}
	if !anySlotPinned(dir, a) || !anySlotPinned(dir, b) {
		t.Fatal("anySlotPinned")
	}
	if slotAllows(dir, "../x", a) == nil {
		t.Fatal("bad label")
	}
}

func TestHandoffGateFreezeAndFloor(t *testing.T) {
	dir := t.TempDir()
	l := "morocco-1_zcinti2"
	if err := handoffGate(dir, l, 5); err != nil {
		t.Fatal(err)
	}
	setHandoff(dir, l, Handoff{Frozen: true, Floor: 100})
	if handoffGate(dir, l, 1000) != ErrSlotFrozen {
		t.Fatal("frozen slot signed")
	}
	setHandoff(dir, l, Handoff{Frozen: false, Floor: 50})
	h, _ := readHandoff(dir, l)
	if h.Floor != 100 {
		t.Fatal("floor went down")
	}
	if handoffGate(dir, l, 100) == nil || handoffGate(dir, l, 101) != nil {
		t.Fatal("floor")
	}
	pd, _ := peersDir(dir)
	os.WriteFile(filepath.Join(pd, l+".handoff"), []byte("{bad"), 0o600)
	if handoffGate(dir, l, 1<<40) == nil {
		t.Fatal("damaged handoff not fail-closed")
	}
	if handoffGate(dir, "morocco-1_zcinti", 1) != nil {
		t.Fatal("other slot frozen")
	}
	recordTombstone(dir, l, Tombstone{KeyID: "x", Floor: 1})
	recordTombstone(dir, l, Tombstone{KeyID: "y", Floor: 2})
	if tb, ok := lastTombstone(dir, l); !ok || tb.KeyID != "y" {
		t.Fatal("tombstone")
	}
}

func TestAcceptPhoneAnySlotPin(t *testing.T) {
	dir := t.TempDir()
	a := bytes.Repeat([]byte{0xA}, 32)
	b := bytes.Repeat([]byte{0xB}, 32)
	if acceptPhone(dir, a) == nil {
		t.Fatal("first phone trusted")
	}
	pinSlot(dir, "c_s", b)
	if err := acceptPhone(dir, b); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "phone.peer"), a, 0o600)
	if acceptPhone(dir, a) != nil || acceptPhone(dir, b) != nil {
		t.Fatal("pinned phones refused")
	}
}
