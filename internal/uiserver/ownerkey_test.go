package uiserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cosmos/kms/internal/takeoff"
)

const (
	vecPub  = "02950e1cdfcb133d6024109fd489f734eeb4502418e538c28481f22bce276f248c"
	vecAddr = "terp10s4mg25tu6termrk8egltfyme4q7sg3h7fra00" // cross-checked with terpd debug addr
	// zigner export_key (rust/db_handling/src/interface_signer.rs):
	// format!("{prefix}:{address}:0x{genesis_hash}"), prefix "cosmos" for Cosmos keys.
	vecZignerAddr = "cosmos:" + vecAddr + ":0x8a0e1e3f2b9d4c5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c"
	// zigner export_cosmos_accounts (rust/signer/src/lib.rs) JSON.
	vecZignerExport = `{"type":"cosmos-accounts","version":1,"label":"Zigner","account_index":0,"public_key":"` + vecPub + `","xpub":"xpub6Cosmos","addresses":[{"chain_id":"osmosis","address":"osmo10s4mg25tu6termrk8egltfyme4q7sg3hxxxxxx","prefix":"osmo"}]}`
)

func TestOwnerQRFormats(t *testing.T) {
	pub, _ := hex.DecodeString(vecPub)
	if AccountAddress(pub) != vecAddr {
		t.Fatal(AccountAddress(pub))
	}
	cases := []struct {
		in, format, addr string
		pub              bool
	}{
		{vecZignerAddr, "zigner address (cosmos:addr:genesis)", vecAddr, false},
		{strings.ToUpper(vecZignerAddr[:0]) + "cosmos:" + vecAddr + ":0x" + strings.Repeat("A", 64), "zigner address (cosmos:addr:genesis)", vecAddr, false},
		{vecZignerExport, "zigner cosmos-accounts export", vecAddr, true},
		{vecPub, "pubkey (hex)", "", true},
		{`{"type":"tendermint/PubKeySecp256k1","value":"ApUOHN/LEz1gJBCf1In3NO60UCQY5TjChIHyK84nbySM"}`, "pubkey (base64)", "", true},
		{"cosmos:" + vecAddr + ":" + vecPub, "pubkey (hex)", vecAddr, true},
		{vecAddr, "address only", vecAddr, false},
	}
	for _, c := range cases {
		q, err := ParseOwnerQR(c.in)
		if err != nil || q.Format != c.format || q.Addr != c.addr || (q.Pub != nil) != c.pub {
			t.Fatalf("%q: %+v %v", c.in, q, err)
		}
		if c.pub && hex.EncodeToString(q.Pub) != vecPub {
			t.Fatalf("%q: wrong key", c.in)
		}
	}
	for _, bad := range []string{"nothing", "cosmos:terp10s4mg25tu6termrk8egltfyme4q7sg3h7fra01:0x" + strings.Repeat("0", 64), `{"type":"cosmos-accounts","public_key":"zz"}`} {
		if _, err := ParseOwnerQR(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestOwnerPubkeyEndpoint(t *testing.T) {
	pub, _ := hex.DecodeString(vecPub)
	s, _ := newTestServer(t)
	id := s.Validators()[0].ID
	var chainPub []byte
	var chainErr error
	accountPubKey = func(context.Context, string, string) ([]byte, error) { return chainPub, chainErr }
	t.Cleanup(func() { accountPubKey = takeoff.AccountPubKey })
	try := func(g, q string) (int, map[string]string) {
		b, _ := json.Marshal(map[string]string{"id": id, "granter": g, "qr": q})
		w := httptest.NewRecorder()
		s.ownerPubkey(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(b))))
		var out map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if c, out := try(vecAddr, vecPub); c != 200 || out["source"] != "qr" {
		t.Fatal(c, out)
	}
	if c, _ := try("terp1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", vecPub); c != 422 {
		t.Fatal("mismatch accepted", c)
	}
	// address-only zigner QR, chain has the key
	chainPub = pub
	if c, out := try("", vecZignerAddr); c != 200 || out["pubkey_hex"] != vecPub || out["source"] != "chain" || out["address"] != vecAddr {
		t.Fatal(c, out)
	}
	// granter differs from the QR's address
	if c, _ := try("terp1qyqszqgpqyqszqgpqyqszqgpqyqszqgpjh3rcj", vecZignerAddr); c != 422 {
		t.Fatal(c)
	}
	// chain returns somebody else's key
	other, _ := hex.DecodeString("03" + vecPub[2:])
	chainPub = other
	if c, _ := try(vecAddr, vecZignerAddr); c == 200 {
		t.Fatal("foreign chain key accepted")
	}
	// no on-chain key yet (never signed) or account missing
	for _, e := range []error{nil, takeoff.ErrAccountMissing} {
		chainPub, chainErr = nil, e
		c, out := try(vecAddr, vecZignerAddr)
		if c != 200 || out["pubkey_hex"] != "" || !strings.Contains(out["note"], "no public key") {
			t.Fatal(c, out)
		}
	}
	if c, _ := try(vecAddr, "nothing"); c != 422 {
		t.Fatal(c)
	}
}
