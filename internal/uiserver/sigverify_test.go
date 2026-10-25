package uiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	dcrsecp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/cosmos/kms/internal/takeoff"
)

func TestVerifyScannedSignatureGatesBroadcast(t *testing.T) {
	s, base := newTestServer(t)
	tok := s.EnableToken()
	k, _ := hex.DecodeString("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
	priv := dcrsecp.PrivKeyFromBytes(k)
	pub := priv.PubKey().SerializeCompressed()
	granter := takeoff.AccountOfPub(pub)
	now := time.Date(2026, 10, 24, 21, 0, 0, 0, time.UTC)
	req := takeoff.ActionRequest{Action: takeoff.ActionDelegate, Granter: granter, Amount: "1"}
	inner, _, errs := takeoff.BuildAction(req, takeoff.Holdings{Found: true, Spendable: "5000000", Thiol: "900000", Rewards: "0", Commission: "0", Delegated: "0"}, now)
	if errs != nil {
		t.Fatal(errs)
	}
	old, _ := takeoff.PrepareDirect(granter, "morocco-1", 7, 2, inner)
	cur, _ := takeoff.PrepareDirect(granter, "morocco-1", 7, 3, inner)
	var sent []takeoff.Prepared
	s.acts.mu.Lock()
	s.acts.send = func(_ context.Context, _ string, p takeoff.Prepared, _, _ []byte) (takeoff.TxOutcome, error) {
		sent = append(sent, p)
		return takeoff.TxOutcome{Hash: "AB", Height: 9, Stage: "committed"}, nil
	}
	s.acts.pending["v0"] = &pendingAction{req: req, rpc: "http://127.0.0.1:1", chain: "morocco-1", prepared: cur, history: []takeoff.Prepared{old}, qrAt: now}
	s.acts.mu.Unlock()
	frame := func(doc []byte) string {
		h := sha256.Sum256(doc)
		c := dcrecdsa.SignCompact(priv, h[:], true)
		return takeoff.EncodeCworchForTest(pub, c[1:])
	}
	ownerHex := hex.EncodeToString(pub)

	// Submit without a verified scan is refused before anything is sent.
	if code, body := post(t, base+"/api/actions/signature", tok, map[string]string{"id": "v0", "payload": ""}); code != http.StatusConflict || !strings.Contains(body, "scan and verify") {
		t.Fatalf("unverified send: %d %s", code, body)
	}
	code, body := post(t, base+"/api/actions/verify", "", map[string]any{"id": "v0", "frames": []string{frame(old.Amino)}, "owner_pubkey_hex": ownerHex})
	var c map[string]any
	_ = json.Unmarshal([]byte(body), &c)
	if code != http.StatusUnprocessableEntity || c["mismatch"] != "sequence" || !strings.Contains(c["reason"].(string), "older QR") {
		t.Fatalf("stale: %d %s", code, body)
	}
	if code, body := post(t, base+"/api/actions/verify", "", map[string]any{"id": "v0", "frames": []string{"cosmos:" + granter + ":0x00"}}); code != http.StatusUnprocessableEntity || !strings.Contains(body, "not a zigner signature") {
		t.Fatalf("account QR: %d %s", code, body)
	}
	code, body = post(t, base+"/api/actions/verify", "", map[string]any{"id": "v0", "frames": []string{frame(cur.Amino)}, "owner_pubkey_hex": ownerHex})
	if code != http.StatusOK || !strings.Contains(body, `"ok":true`) || !strings.Contains(body, cur.ID()) {
		t.Fatalf("verify: %d %s", code, body)
	}
	s.acts.mu.Lock()
	v := s.acts.pending["v0"].verified
	s.acts.mu.Unlock()
	if v == nil || v.AuthID != cur.ID() {
		t.Fatal("a verified scan must be kept for the QR on screen")
	}
	// One broadcast of the one owner-signed tx, then no second send.
	code, body = post(t, base+"/api/actions/signature", tok, map[string]string{"id": "v0"})
	if code != http.StatusOK || !strings.Contains(body, `"stage":"committed"`) || len(sent) != 1 || sent[0].Kind != "direct" || len(sent[0].Msgs) != 1 || sent[0].Msgs[0].TypeUrl != "/cosmos.staking.v1beta1.MsgDelegate" {
		t.Fatalf("broadcast: %d %s %d", code, body, len(sent))
	}
	if code, _ := post(t, base+"/api/actions/signature", tok, map[string]string{"id": "v0"}); code != http.StatusConflict || len(sent) != 1 {
		t.Fatalf("second broadcast must be refused: %d", code)
	}
}
