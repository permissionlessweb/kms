package uiserver

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmos/kms/signing/bluetooth"
)

func retireQR(sec ed25519.PrivateKey, chain, slot string, floor uint64, nonce [16]byte, target []byte) string {
	sig := ed25519.Sign(sec, bluetooth.RetireMessageV2(chain, slot, sec.Public().(ed25519.PublicKey), floor, nonce, target))
	return bluetooth.RetiredPrefixV2 + base64.StdEncoding.EncodeToString(target) + ":" + base64.StdEncoding.EncodeToString(sig)
}

func TestHandoffFlow(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, "state"), 0o700)
	os.WriteFile(filepath.Join(home, "kms.yaml"), []byte("chains:\n  - {id: morocco-1/zcinti2, network: morocco-1, state_file: state/morocco-1_zcinti2.json}\n"), 0o600)
	os.WriteFile(filepath.Join(home, "state", "morocco-1_zcinti2.json"), []byte(`{"height":"1000","round":0,"step":3}`), 0o600)
	_, sec, _ := ed25519.GenerateKey(rand.Reader)
	pub := []byte(sec[32:])
	kd := filepath.Join(bluetooth.Dir, "keys", "morocco-1_zcinti2")
	os.MkdirAll(kd, 0o700)
	os.WriteFile(filepath.Join(kd, "pub.hex"), []byte(hexs(pub)), 0o600)
	defer os.RemoveAll(kd)
	oldPhone := bytes.Repeat([]byte{0xA}, 32)
	newPhone := bytes.Repeat([]byte{0xB}, 32)
	os.MkdirAll(bluetooth.SupportDir, 0o700)
	os.WriteFile(filepath.Join(bluetooth.SupportDir, "phone.peer"), oldPhone, 0o600)
	defer os.RemoveAll(bluetooth.SupportDir)

	seed := bytes.Repeat([]byte{0x42}, 32)
	kmsStatic = func() ([]byte, error) { return append([]byte(nil), seed...), nil }
	kp, _ := ecdh.X25519().NewPrivateKey(seed)
	kmsPub := kp.PublicKey().Bytes()
	s := &Server{}
	v := ValidatorView{ID: "dab", Name: "dabarber", ChainID: "morocco-1", Slot: "morocco-1/zcinti2", Signer: "phone", Source: filepath.Join(home, "kms.yaml")}
	s.vals.list = []ValidatorView{v}
	ctx := context.Background()
	step := func(n, qr string) (map[string]any, error) {
		movesMu.Lock()
		defer movesMu.Unlock()
		return s.doStep(ctx, n, v, qr)
	}
	for _, n := range []string{"export", "target", "send"} {
		if _, err := step(n, ""); err == nil {
			t.Fatal(n + " step still exists")
		}
	}
	if _, err := step("retire", ""); err == nil {
		t.Fatal("retire before start")
	}
	// owner binding is checked at start
	if _, err := step("start", ""); err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("start without owner: %v", err)
	}
	if h, _ := bluetooth.GetHandoff("morocco-1_zcinti2"); h.Frozen {
		t.Fatal("frozen without owner")
	}
	ownerPriv := bytes.Repeat([]byte{2}, 33)
	s.ownerStore().m["dab"] = Owner{Granter: AccountAddress(ownerPriv), PubkeyHex: hexs(ownerPriv)}
	if _, err := step("start", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := step("start", ""); err == nil {
		t.Fatal("double start")
	}
	h, _ := bluetooth.GetHandoff("morocco-1_zcinti2")
	if !h.Frozen || h.Floor != 1010 || h.Nonce == "" || h.Sent {
		t.Fatalf("handoff %+v", h)
	}
	m := moves["morocco-1_zcinti2"]
	q := handoffPayload(m, kmsPub)
	if !strings.HasPrefix(q, "zcinti-move:2:morocco-1:zcinti2:"+hexs(m.nonce[:])+":1010:") {
		t.Fatal("start QR " + q)
	}
	// console restart before retire: the move resumes from the file
	movesMu.Lock()
	delete(moves, "morocco-1_zcinti2")
	movesMu.Unlock()
	if _, err := step("pair", ""); err == nil {
		t.Fatal("pair before retire")
	}
	m = moves["morocco-1_zcinti2"]
	if m == nil || m.stage != "retire" {
		t.Fatal("not resumed")
	}
	var other [16]byte
	if _, err := step("retire", retireQR(sec, "morocco-1", "zcinti2", 1010, other, newPhone)); err == nil {
		t.Fatal("other nonce (replay)")
	}
	if _, err := step("retire", retireQR(sec, "morocco-1", "zcinti2", 1009, m.nonce, newPhone)); err == nil {
		t.Fatal("other floor")
	}
	if _, err := step("retire", retireQR(sec, "morocco-1", "zcinti2", 1010, m.nonce, oldPhone)); err == nil {
		t.Fatal("old phone as target")
	}
	_, sec2, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := step("retire", retireQR(sec2, "morocco-1", "zcinti2", 1010, m.nonce, newPhone)); err == nil {
		t.Fatal("other key")
	}
	if _, err := step("retire", retireQR(sec, "morocco-1", "zcinti2", 1010, m.nonce, newPhone)); err != nil {
		t.Fatal(err)
	}
	if bluetooth.SlotAllows("morocco-1_zcinti2", oldPhone) == nil {
		t.Fatal("old phone still allowed after retire")
	}
	if bluetooth.SlotAllows("morocco-1_zcinti", oldPhone) != nil {
		t.Fatal("other slot lost old phone")
	}
	if _, err := step("cancel", ""); err == nil {
		t.Fatal("cancel after retire")
	}
	// restart after retire: still refused to cancel, resumes at pair
	movesMu.Lock()
	delete(moves, "morocco-1_zcinti2")
	movesMu.Unlock()
	if _, err := step("cancel", ""); err == nil {
		t.Fatal("cancel after retire and restart")
	}
	if _, err := step("finish", ""); err == nil {
		t.Fatal("finish before pair")
	}
	// a different phone asking to pair is refused
	os.WriteFile(filepath.Join(bluetooth.Dir, "phone.pending"), bytes.Repeat([]byte{0xC}, 32), 0o600)
	if _, err := step("pair", ""); err == nil {
		t.Fatal("wrong phone paired")
	}
	os.WriteFile(filepath.Join(bluetooth.Dir, "phone.pending"), newPhone, 0o600)
	defer os.Remove(filepath.Join(bluetooth.Dir, "phone.pending"))
	if _, err := step("pair", ""); err != nil {
		t.Fatal(err)
	}
	if bluetooth.SlotAllows("morocco-1_zcinti2", newPhone) != nil {
		t.Fatal("new phone not pinned")
	}
	if h, _ := bluetooth.GetHandoff("morocco-1_zcinti2"); !h.Frozen {
		t.Fatal("unfrozen before finish")
	}
	if _, err := step("finish", ""); err != nil {
		t.Fatal(err)
	}
	h, _ = bluetooth.GetHandoff("morocco-1_zcinti2")
	if h.Frozen || h.Floor != 1010 {
		t.Fatalf("after finish %+v", h)
	}
	if _, ok := bluetooth.LastTombstone("morocco-1_zcinti2"); !ok {
		t.Fatal("tombstone")
	}
}

func TestHandoffCancelUnfreezes(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, "state"), 0o700)
	os.WriteFile(filepath.Join(home, "kms.yaml"), []byte("chains:\n  - {id: n/s, state_file: state/n_s.json}\n"), 0o600)
	os.WriteFile(filepath.Join(home, "state", "n_s.json"), []byte(`{"height":"7"}`), 0o600)
	kd := filepath.Join(bluetooth.Dir, "keys", "n_s")
	os.MkdirAll(kd, 0o700)
	os.WriteFile(filepath.Join(kd, "pub.hex"), []byte(strings.Repeat("ab", 32)), 0o600)
	defer os.RemoveAll(kd)
	os.MkdirAll(bluetooth.SupportDir, 0o700)
	os.WriteFile(filepath.Join(bluetooth.SupportDir, "phone.peer"), bytes.Repeat([]byte{0xA}, 32), 0o600)
	defer os.RemoveAll(bluetooth.SupportDir)
	s := &Server{}
	v := ValidatorView{ID: "x", ChainID: "n", Slot: "n/s", Signer: "phone", Source: filepath.Join(home, "kms.yaml")}
	s.vals.list = []ValidatorView{v}
	s.ownerStore().m["x"] = Owner{Granter: "terp1x"}
	movesMu.Lock()
	_, err := s.doStep(context.Background(), "start", v, "")
	movesMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	movesMu.Lock()
	_, err = s.doStep(context.Background(), "cancel", v, "")
	movesMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	h, _ := bluetooth.GetHandoff("n_s")
	if h.Frozen || h.Floor != 17 {
		t.Fatalf("%+v", h)
	}
}

func hexs(b []byte) string { return hex.EncodeToString(b) }

func TestHandoffExpiresUnsent(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, "state"), 0o700)
	os.WriteFile(filepath.Join(home, "kms.yaml"), []byte("chains:\n  - {id: e/s, state_file: state/e_s.json}\n"), 0o600)
	os.WriteFile(filepath.Join(home, "state", "e_s.json"), []byte(`{"height":"7"}`), 0o600)
	kd := filepath.Join(bluetooth.Dir, "keys", "e_s")
	os.MkdirAll(kd, 0o700)
	os.WriteFile(filepath.Join(kd, "pub.hex"), []byte(strings.Repeat("ab", 32)), 0o600)
	defer os.RemoveAll(kd)
	os.MkdirAll(bluetooth.SupportDir, 0o700)
	os.WriteFile(filepath.Join(bluetooth.SupportDir, "phone.peer"), bytes.Repeat([]byte{0xA}, 32), 0o600)
	defer os.RemoveAll(bluetooth.SupportDir)
	now := time.Unix(1_800_000_000, 0)
	handoffNow = func() time.Time { return now }
	defer func() { handoffNow = time.Now }()
	s := &Server{}
	v := ValidatorView{ID: "e", ChainID: "e", Slot: "e/s", Signer: "phone", Source: filepath.Join(home, "kms.yaml")}
	s.vals.list = []ValidatorView{v}
	s.ownerStore().m["e"] = Owner{Granter: "terp1x"}
	movesMu.Lock()
	_, err := s.doStep(context.Background(), "start", v, "")
	movesMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(14 * time.Minute)
	movesMu.Lock()
	m := resume("e_s")
	movesMu.Unlock()
	if m == nil {
		t.Fatal("expired too early")
	}
	now = now.Add(2 * time.Minute)
	movesMu.Lock()
	delete(moves, "e_s") // as after a console restart
	m = resume("e_s")
	movesMu.Unlock()
	if m != nil {
		t.Fatal("stale move not expired")
	}
	h, _ := bluetooth.GetHandoff("e_s")
	if h.Frozen || h.Floor != 17 {
		t.Fatalf("%+v", h)
	}
}

func TestHandoffGetNeedsLoopbackHost(t *testing.T) {
	h := localGet(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	for host, want := range map[string]int{"127.0.0.1:8791": 200, "localhost:9000": 200, "evil.example:8791": 403} {
		r := httptest.NewRequest("GET", "/api/handoff/state", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != want {
			t.Fatalf("%s: %d", host, w.Code)
		}
	}
}
