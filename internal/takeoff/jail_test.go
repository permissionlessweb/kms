package takeoff

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	auth "cosmossdk.io/api/cosmos/auth/v1beta1"
	ed25519 "cosmossdk.io/api/cosmos/crypto/ed25519"
	secp "cosmossdk.io/api/cosmos/crypto/secp256k1"
	slashing "cosmossdk.io/api/cosmos/slashing/v1beta1"
	staking "cosmossdk.io/api/cosmos/staking/v1beta1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// zcinti's public consensus key on morocco-1.
const zcintiConsB64 = "CKxv9iTFm4mN0Mua691qnX8kl9931KnuJDn/NmdrnT8="

func jailChain(t *testing.T, jailed, tomb bool, until time.Time, missed int64) (string, func()) {
	pub, _ := base64.StdEncoding.DecodeString(zcintiConsB64)
	kb, _ := proto.Marshal(&ed25519.PubKey{Key: pub})
	cpk := &anypb.Any{TypeUrl: "/cosmos.crypto.ed25519.PubKey", Value: kb}
	val := valoper(testGranter)
	other, _ := proto.Marshal(&ed25519.PubKey{Key: make([]byte, 32)})
	srv := fakeChain(t, map[string]proto.Message{
		"/cosmos.slashing.v1beta1.Query/Params": &slashing.QueryParamsResponse{Params: &slashing.Params{SignedBlocksWindow: 10000, MinSignedPerWindow: []byte("50000000000000000")}},
		"/cosmos.slashing.v1beta1.Query/SigningInfo": &slashing.QuerySigningInfoResponse{ValSigningInfo: &slashing.ValidatorSigningInfo{
			JailedUntil: timestamppb.New(until), Tombstoned: tomb, MissedBlocksCounter: missed}},
		"/cosmos.staking.v1beta1.Query/Validators": &staking.QueryValidatorsResponse{Validators: []*staking.Validator{
			{OperatorAddress: "terpvaloper1other", ConsensusPubkey: &anypb.Any{TypeUrl: "/cosmos.crypto.ed25519.PubKey", Value: other}},
			{OperatorAddress: val, Jailed: jailed, ConsensusPubkey: cpk}}},
		"/cosmos.staking.v1beta1.Query/Validator": &staking.QueryValidatorResponse{Validator: &staking.Validator{OperatorAddress: val, Jailed: jailed, ConsensusPubkey: cpk,
			Description: &staking.Description{Moniker: "zcinti"}, Commission: &staking.Commission{CommissionRates: &staking.CommissionRates{Rate: "1"}}}},
	})
	return srv.URL, srv.Close
}

func TestConsAddrMatchesZcinti(t *testing.T) {
	pub, _ := base64.StdEncoding.DecodeString(zcintiConsB64)
	h := sha256.Sum256(pub)
	if got := strings.ToUpper(hex.EncodeToString(h[:20])); got != "E7353DEE98FFE8D7A3ABA2D8641A060879D1DD05" {
		t.Fatal(got)
	}
	c, err := ConsAddrFromHex("E7353DEE98FFE8D7A3ABA2D8641A060879D1DD05")
	if err != nil || c != "terpvalcons1uu6nmm5cll5d0gat5tvxgxsxppuarhg90evefa" {
		t.Fatal(c, err)
	}
}

func TestQueryJailReadsAllThreeSources(t *testing.T) {
	until := time.Date(2026, 10, 24, 19, 25, 37, 0, time.UTC)
	rpc, done := jailChain(t, true, false, until, 9501)
	defer done()
	j, err := QueryJail(context.Background(), rpc, "E7353DEE98FFE8D7A3ABA2D8641A060879D1DD05")
	if err != nil {
		t.Fatal(err)
	}
	if !j.Jailed || j.Operator != valoper(testGranter) || !j.JailedUntil.Equal(until) || j.Missed != 9501 || j.Window != 10000 || j.MaxMissed != 9500 {
		t.Fatalf("%+v", j)
	}
	j.Evaluate(until.Add(-time.Minute))
	if j.CanUnjail || !strings.Contains(j.Reason, "jailed until") {
		t.Fatal(j.Reason)
	}
	j.Evaluate(until.Add(time.Second))
	if !j.CanUnjail {
		t.Fatal(j.Reason)
	}
}

func TestLivenessWarning(t *testing.T) {
	j := JailInfo{Missed: 4700, MaxMissed: 9500, Window: 10000}
	j.Evaluate(time.Now())
	if j.Warn {
		t.Fatal("warned below half")
	}
	j.Missed = 4750
	j.Evaluate(time.Now())
	if !j.Warn {
		t.Fatal("no warning at half the allowance")
	}
	if maxMissed(100, []byte("500000000000000000")) != 50 || maxMissed(3, []byte("500000000000000000")) != 1 {
		t.Fatal("max missed")
	}
}

func TestUnjailReviewAndRefusals(t *testing.T) {
	until := time.Date(2026, 10, 24, 19, 25, 37, 0, time.UTC)
	now := until.Add(time.Hour)
	req := ActionRequest{Action: ActionUnjail, Granter: testGranter}

	rpc, done := jailChain(t, true, false, until, 9501)
	h, err := QueryHoldings(context.Background(), rpc, testGranter, valoper(testGranter))
	done()
	if err != nil || h.Jail == nil || h.Validator.ConsHex != "E7353DEE98FFE8D7A3ABA2D8641A060879D1DD05" {
		t.Fatal(err, h.Jail, h.Validator.ConsHex)
	}
	h.Thiol = "900000"
	msgs, rv, errs := BuildAction(req, h, now)
	if len(errs) > 0 || len(msgs) != 1 || msgs[0].TypeUrl != unjailURL || rv.Title != "Unjail validator" {
		t.Fatal(errs, rv.Title)
	}
	var m slashing.MsgUnjail
	if proto.Unmarshal(msgs[0].Value, &m) != nil || m.ValidatorAddr != valoper(testGranter) {
		t.Fatal(m.ValidatorAddr)
	}
	// too early
	if _, _, errs := BuildAction(req, h, until.Add(-time.Second)); len(errs) == 0 || !strings.Contains(errs[0].Message, "jailed until") {
		t.Fatal(errs)
	}
	// someone else's account
	other := req
	other.Validator = "terpvaloper1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz0" // placeholder, fails bech32 or operator check
	if _, _, errs := BuildAction(other, h, now); len(errs) == 0 {
		t.Fatal("unjail for another validator accepted")
	}
	// tombstoned
	rpc, done = jailChain(t, true, true, until, 0)
	h2, _ := QueryHoldings(context.Background(), rpc, testGranter, valoper(testGranter))
	done()
	if _, _, errs := BuildAction(req, h2, now); len(errs) == 0 || !strings.Contains(errs[0].Message, "tombstoned") {
		t.Fatal(errs)
	}
	// not jailed
	rpc, done = jailChain(t, false, false, time.Unix(0, 0), 3)
	h3, _ := QueryHoldings(context.Background(), rpc, testGranter, valoper(testGranter))
	done()
	if _, _, errs := BuildAction(req, h3, now); len(errs) == 0 || !strings.Contains(errs[0].Message, "not jailed") {
		t.Fatal(errs)
	}
}

func TestAccountPubKey(t *testing.T) {
	pub, _ := hex.DecodeString("02950e1cdfcb133d6024109fd489f734eeb4502418e538c28481f22bce276f248c")
	kb, _ := proto.Marshal(&secp.PubKey{Key: pub})
	withKey, _ := proto.Marshal(&auth.BaseAccount{Address: "terp10s4mg25tu6termrk8egltfyme4q7sg3h7fra00", PubKey: &anypb.Any{TypeUrl: "/cosmos.crypto.secp256k1.PubKey", Value: kb}})
	srv := fakeChain(t, map[string]proto.Message{"/cosmos.auth.v1beta1.Query/Account": &auth.QueryAccountResponse{Account: &anypb.Any{TypeUrl: acctURL, Value: withKey}}})
	got, err := AccountPubKey(context.Background(), srv.URL, "terp10s4mg25tu6termrk8egltfyme4q7sg3h7fra00")
	srv.Close()
	if err != nil || hex.EncodeToString(got) != hex.EncodeToString(pub) {
		t.Fatal(err)
	}
	noKey, _ := proto.Marshal(&auth.BaseAccount{Address: "terp10s4mg25tu6termrk8egltfyme4q7sg3h7fra00"})
	srv = fakeChain(t, map[string]proto.Message{"/cosmos.auth.v1beta1.Query/Account": &auth.QueryAccountResponse{Account: &anypb.Any{TypeUrl: acctURL, Value: noKey}}})
	got, err = AccountPubKey(context.Background(), srv.URL, "terp10s4mg25tu6termrk8egltfyme4q7sg3h7fra00")
	srv.Close()
	if err != nil || got != nil {
		t.Fatal(got, err)
	}
	srv = fakeChain(t, nil) // code 1 for everything
	_, err = AccountPubKey(context.Background(), srv.URL, "terp10s4mg25tu6termrk8egltfyme4q7sg3h7fra00")
	srv.Close()
	if err == nil {
		t.Fatal("missing account read as ok")
	}
}
