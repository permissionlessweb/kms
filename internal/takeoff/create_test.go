package takeoff

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	ed "cosmossdk.io/api/cosmos/crypto/ed25519"
	staking "cosmossdk.io/api/cosmos/staking/v1beta1"
	tx "cosmossdk.io/api/cosmos/tx/v1beta1"
	"google.golang.org/protobuf/proto"
)

// The form must build exactly the message terpd built for create.b64
// (terpd tx staking create-validator, throwaway key, random consensus key).
func TestCreateFormMatchesTerpd(t *testing.T) {
	raw, _ := os.ReadFile("testdata/terpd-amino/create.b64")
	wire, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	var txr tx.TxRaw
	var body tx.TxBody
	_ = proto.Unmarshal(wire, &txr)
	_ = proto.Unmarshal(txr.BodyBytes, &body)
	var want staking.MsgCreateValidator
	if err := proto.Unmarshal(body.Messages[0].Value, &want); err != nil {
		t.Fatal(err)
	}
	var pk ed.PubKey
	_ = proto.Unmarshal(want.Pubkey.Value, &pk)
	owner := "terp1ykzh2fgzm7fvchwhq6wfwqp97jtsw4pn3tup0h"
	req := ActionRequest{Action: ActionCreate, Granter: owner, Amount: "1.5", Create: CreateFields{
		Moniker: "zcinti two", Identity: "ABCD1234", Website: "https://terp.network", SecurityContact: "sec@terp.network",
		Details: "phone-held key & <test>", RatePercent: "7", MaxRatePercent: "25", MaxChangePercent: "2", MinSelfDelegation: "1",
		ConsPubHex: hex.EncodeToString(pk.Key),
	}}
	inner, rv, errs := BuildAction(req, Holdings{Spendable: "9000000", Thiol: "100000"}, testNow)
	if errs != nil {
		t.Fatal(errs)
	}
	if !bytes.Equal(inner[0].Value, body.Messages[0].Value) || inner[0].TypeUrl != body.Messages[0].TypeUrl {
		t.Fatalf("message differs from terpd's")
	}
	if rv.ExecFee != "20000" || rv.Gas != 400000 || !strings.HasPrefix(rv.Title, "Create validator") {
		t.Fatalf("review %+v", rv)
	}
}

func TestCreateValidation(t *testing.T) {
	owner := "terp1ykzh2fgzm7fvchwhq6wfwqp97jtsw4pn3tup0h"
	ok := CreateFields{Moniker: "m", RatePercent: "10", MaxRatePercent: "20", MaxChangePercent: "1", ConsPubHex: strings.Repeat("ab", 32)}
	h := Holdings{Spendable: "5000000"}
	field := func(c CreateFields, amt string, h Holdings) string {
		_, _, errs := BuildAction(ActionRequest{Action: ActionCreate, Granter: owner, Amount: amt, Create: c}, h, testNow)
		if len(errs) == 0 {
			return ""
		}
		return errs[0].Field
	}
	if f := field(ok, "1", h); f != "" {
		t.Fatalf("valid form refused: %s", f)
	}
	bad := ok
	bad.RatePercent = "30"
	if f := field(bad, "1", h); f != "rate_percent" {
		t.Fatal(f)
	}
	bad = ok
	bad.ConsPubHex = "00"
	if f := field(bad, "1", h); f != "consensus_pubkey_hex" {
		t.Fatal(f)
	}
	bad = ok
	bad.Moniker = " "
	if f := field(bad, "1", h); f != "moniker" {
		t.Fatal(f)
	}
	if f := field(ok, "6", h); f != "amount" {
		t.Fatal(f)
	}
	bad = ok
	bad.MinSelfDelegation = "2000000"
	if f := field(bad, "1", h); f != "amount" {
		t.Fatal(f)
	}
	if f := field(ok, "1", Holdings{Spendable: "5000000", Found: true}); f != "action" {
		t.Fatal(f)
	}
}
