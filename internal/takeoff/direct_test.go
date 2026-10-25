package takeoff

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secp "cosmossdk.io/api/cosmos/crypto/secp256k1"
	tx "cosmossdk.io/api/cosmos/tx/v1beta1"
	"google.golang.org/protobuf/proto"
)

// testdata/terpd-amino holds txs that terpd itself signed in amino-json mode
// with a throwaway test-keyring key (account 11219903587360570885, seq 7,
// chain morocco-1, memo cw-orch-action:v1). Each signature must verify over
// the sign doc PrepareDirect builds for the same messages: that proves our
// amino JSON is byte-identical to the chain's.
func TestDirectDocMatchesTerpd(t *testing.T) {
	files, _ := filepath.Glob("testdata/terpd-amino/*.b64")
	if len(files) < 7 {
		t.Fatalf("fixtures missing: %v", files)
	}
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		wire, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		var txr tx.TxRaw
		var body tx.TxBody
		var auth tx.AuthInfo
		if err := proto.Unmarshal(wire, &txr); err != nil {
			t.Fatal(err)
		}
		_ = proto.Unmarshal(txr.BodyBytes, &body)
		_ = proto.Unmarshal(txr.AuthInfoBytes, &auth)
		var pk secp.PubKey
		_ = auth.SignerInfos[0].PublicKey.UnmarshalTo(&pk)
		owner := AccountOfPub(pk.Key)
		p, err := PrepareDirect(owner, "morocco-1", 11219903587360570885, 7, body.Messages)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		gas, fee := DirectFee(len(body.Messages))
		if auth.Fee.GasLimit != gas || auth.Fee.Amount[0].Amount != fee || body.Memo != DirectMemo {
			t.Fatalf("%s: fixture fee/memo differ", f)
		}
		if !verifyAmino(pk.Key, txr.Signatures[0], p.Amino) {
			t.Fatalf("%s: terpd's amino signature does not verify over our doc:\n%s", f, p.Amino)
		}
		// Re-assemble with our encoder: the tx must be byte-identical to terpd's.
		ours, err := SignedTx(p, pk.Key, txr.Signatures[0])
		if err != nil {
			t.Fatal(err)
		}
		var o tx.TxRaw
		_ = proto.Unmarshal(ours, &o)
		if string(o.BodyBytes) != string(txr.BodyBytes) {
			t.Fatalf("%s: body bytes differ", f)
		}
	}
}

func TestDirectBuildActionRoundTrip(t *testing.T) {
	owner := "terp1sqczdzsyfzry02duvj50t0cucmdj05cqj6sk68"
	h := Holdings{Found: true, Spendable: "5000000", Delegated: "999000", Rewards: "10", Commission: "5", Validator: ValidatorInfo{Rate: "50000000000000000", MaxRate: "200000000000000000", MaxChangeRate: "10000000000000000"}}
	for _, req := range []ActionRequest{
		{Action: ActionDelegate, Granter: owner, Amount: "1"},
		{Action: ActionRewards, Granter: owner},
	} {
		inner, _, errs := BuildAction(req, h, testNow)
		if errs != nil {
			t.Fatal(errs)
		}
		p, err := PrepareDirect(owner, "morocco-1", 1, 2, inner)
		if err != nil {
			t.Fatal(err)
		}
		if p.Kind != "direct" || !strings.Contains(string(p.Amino), `"memo":"cw-orch-action:v1"`) || len(p.PNG) == 0 {
			t.Fatalf("bad prepared %s", p.Amino)
		}
	}
	if _, err := PrepareDirect(owner, "morocco-1", 1, 2, nil); err == nil {
		t.Fatal("empty must fail")
	}
}

func TestDecAmino(t *testing.T) {
	for in, want := range map[string]string{"50000000000000000": "0.050000000000000000", "1000000000000000000": "1.000000000000000000", "0": "0.000000000000000000"} {
		if got, _ := decAmino(in); got != want {
			t.Fatalf("%s: %s", in, got)
		}
	}
}
