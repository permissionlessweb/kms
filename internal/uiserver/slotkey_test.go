package uiserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/cosmos/kms/signing/bluetooth"
)

func TestSlotQRAndPhoneKeys(t *testing.T) {
	v := ValidatorView{Name: "zcinti2", ChainID: "morocco-1", Slot: "morocco-1/zcinti2", Signer: "phone"}
	if got := SlotQRPayload(v); got != "zcinti:1:terp:morocco-1:zcinti2" {
		t.Fatal(got)
	}
	list := []ValidatorView{v, {Name: "zcinti", ChainID: "morocco-1", Slot: "morocco-1/zcinti", Signer: "phone"}}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := filepath.Join(bluetooth.Dir, "keys", "morocco-1_zcinti")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "pub.hex"), []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fillPhoneKeys(list)
	if list[0].PhoneKey || list[0].SlotName != "zcinti2" {
		t.Fatalf("zcinti2 has no key yet: %+v", list[0])
	}
	if !list[1].PhoneKey || list[1].PhoneKeyID != bluetooth.KeyIDHex(pub) {
		t.Fatalf("zcinti key: %+v", list[1])
	}
}

func TestSetValidatorsDedupesBySlot(t *testing.T) {
	a := ValidatorView{Name: "zcinti", ChainID: "morocco-1", Privval: "tcp://127.0.0.1:27159"}
	b := ValidatorView{Name: "zcinti2", ChainID: "morocco-1", Privval: "tcp://127.0.0.1:28159"}
	got := dedupeValidators([]ValidatorView{a, b, a, b, {Name: "x", ChainID: "c"}, {Name: "x", ChainID: "c"}})
	if len(got) != 3 || got[0].Name != "zcinti" || got[1].Name != "zcinti2" {
		t.Fatalf("%+v", got)
	}
}
