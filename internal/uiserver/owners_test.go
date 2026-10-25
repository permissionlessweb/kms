package uiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmos/kms/internal/takeoff"
	"github.com/cosmos/kms/signing/bluetooth"
)

const testOwner = "terp1ykzh2fgzm7fvchwhq6wfwqp97jtsw4pn3tup0h"

func twoSlotServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	s, err := New("127.0.0.1:0", "http://127.0.0.1:1", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	s.SetValidators([]ValidatorView{
		{Name: "zcinti", ChainID: "morocco-1", Slot: "morocco-1/zcinti", RPC: "http://127.0.0.1:1", Privval: "tcp://127.0.0.1:27159", Signer: "phone"},
		{Name: "zcinti2", ChainID: "morocco-1", Slot: "morocco-1/zcinti2", RPC: "http://127.0.0.1:1", Privval: "tcp://127.0.0.1:28159", Signer: "phone"},
	})
	path := filepath.Join(t.TempDir(), "state", "console", "owners.json")
	if err := s.SetOwnersPath(path); err != nil {
		t.Fatal(err)
	}
	return s, "http://" + s.Addr(), path
}

func getOwners(t *testing.T, base string) map[string]Owner {
	t.Helper()
	resp, err := http.Get(base + "/api/owners")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var d struct{ Owners map[string]Owner }
	_ = json.NewDecoder(resp.Body).Decode(&d)
	return d.Owners
}

// Owners are per slot, persist across restarts, and clearing one slot
// leaves the other (and everything else) alone.
func TestOwnersPerSlotPersistAndClear(t *testing.T) {
	s, base, path := twoSlotServer(t)
	if code, body := post(t, base+"/api/owners", "", map[string]any{"id": "v0", "granter": testOwner, "name": "zcinti"}); code != 200 {
		t.Fatal(code, body)
	}
	if code, body := post(t, base+"/api/owners", "", map[string]any{"id": "v1", "name": "zcinti two"}); code != 200 {
		t.Fatal(code, body)
	}
	o := getOwners(t, base)
	if o["v0"].Granter != testOwner || o["v1"].Granter != "" || o["v1"].Name != "zcinti two" {
		t.Fatalf("owners leak across slots: %+v", o)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"morocco-1/zcinti2"`) || !strings.Contains(string(raw), testOwner) {
		t.Fatalf("not persisted by slot: %s", raw)
	}
	// a new console process reads the same file
	s2, _ := New("127.0.0.1:0", "http://127.0.0.1:1", false)
	defer s2.Close()
	s2.SetValidators(s.Validators())
	if err := s2.SetOwnersPath(path); err != nil {
		t.Fatal(err)
	}
	if o, _ := s2.ownerStore().get("morocco-1/zcinti"); o.Granter != testOwner {
		t.Fatalf("not reloaded: %+v", o)
	}
	engine := s.Validators()
	if code, _ := post(t, base+"/api/owners", "", map[string]any{"id": "v0", "clear": true}); code != 200 {
		t.Fatal(code)
	}
	o = getOwners(t, base)
	if _, ok := o["v0"]; ok || o["v1"].Name != "zcinti two" {
		t.Fatalf("clear touched the wrong slot: %+v", o)
	}
	after := s.Validators()
	for i := range engine {
		if engine[i].Engine != after[i].Engine || engine[i].Privval != after[i].Privval {
			t.Fatal("clearing an owner changed engine state")
		}
	}
	if code, _ := post(t, base+"/api/owners", "", map[string]any{"id": "v0", "granter": "terp1bad"}); code != http.StatusUnprocessableEntity {
		t.Fatal("bad granter accepted")
	}
	if code, _ := post(t, base+"/api/owners", "", map[string]any{"id": "v0", "granter": testOwner, "pubkey_hex": strings.Repeat("02", 33)}); code != http.StatusUnprocessableEntity {
		t.Fatal("foreign pubkey accepted")
	}
}

func TestOwnersNeedToken(t *testing.T) {
	s, base, _ := twoSlotServer(t)
	tok := s.EnableToken()
	if code, _ := post(t, base+"/api/owners", "", map[string]any{"id": "v0", "clear": true}); code != http.StatusForbidden {
		t.Fatal("owners POST without token")
	}
	if code, _ := post(t, base+"/api/owners", tok, map[string]any{"id": "v0", "clear": true}); code != 200 {
		t.Fatal("owners POST with token")
	}
}

// Phone names, on-chain registration and create-only mode per slot.
func TestSlotInfoNamesAndOnchain(t *testing.T) {
	dir := t.TempDir()
	old := bluetooth.Dir
	bluetooth.Dir = dir
	defer func() { bluetooth.Dir = old }()
	pub1, pub2 := strings.Repeat("11", 32), strings.Repeat("22", 32)
	for label, pub := range map[string]string{"morocco-1_zcinti": pub1, "morocco-1_zcinti2": pub2} {
		_ = os.MkdirAll(filepath.Join(dir, "keys", label), 0o700)
		_ = os.WriteFile(filepath.Join(dir, "keys", label, "pub.hex"), []byte(pub+"\n"), 0o600)
	}
	_ = os.WriteFile(filepath.Join(dir, "keys.json"), []byte(`{"keys":[{"label":"morocco-1_zcinti","name":"Zcinti Main"},{"label":"morocco-1_zcinti2","name":""}]}`), 0o600)
	oldQ := queryByCons
	defer func() { queryByCons = oldQ; forgetOnchain() }()
	forgetOnchain()
	queryByCons = func(_ context.Context, _ string, cons string) (takeoff.ValidatorInfo, bool, error) {
		if cons == takeoff.ConsensusAddr(mustHex(pub1)) {
			return takeoff.ValidatorInfo{Operator: "terpvaloper1x", Moniker: "zcinti", Status: "BOND_STATUS_BONDED"}, true, nil
		}
		return takeoff.ValidatorInfo{}, false, nil
	}
	s, base, _ := twoSlotServer(t)
	list := s.Validators()
	fillPhoneKeys(list)
	s.fillSlotInfo(list)
	a, b := list[0], list[1]
	if !a.PhoneNames || a.PhoneName != "Zcinti Main" || a.DisplayName != "Zcinti Main" {
		t.Fatalf("phone name: %+v", a)
	}
	if a.OnChain == nil || !a.OnChain.Found || a.OnChain.Moniker != "zcinti" {
		t.Fatalf("on-chain: %+v", a.OnChain)
	}
	if b.OnChain == nil || !b.OnChain.Checked || b.OnChain.Found || b.PhonePub != pub2 {
		t.Fatalf("zcinti2 must read as not a validator: %+v", b.OnChain)
	}
	// create on an existing validator's slot is refused before any rpc
	code, body := post(t, base+"/api/actions/review", "", map[string]any{"id": "v0", "request": map[string]any{"action": "create", "granter": testOwner, "amount": "1"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "already validator") {
		t.Fatalf("create on validator slot: %d %s", code, body)
	}
	// rpc errors never read as "not a validator"
	forgetOnchain()
	queryByCons = func(context.Context, string, string) (takeoff.ValidatorInfo, bool, error) {
		return takeoff.ValidatorInfo{}, false, context.DeadlineExceeded
	}
	if oc := onchainFor("http://x", pub2); oc.Checked {
		t.Fatal("an rpc error must not mark the slot as not a validator")
	}
}

func mustHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, c := range s[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			default:
				v |= byte(c-'a') + 10
			}
		}
		b[i] = v
	}
	return b
}
