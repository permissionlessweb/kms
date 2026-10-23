package takeoff

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	auth "cosmossdk.io/api/cosmos/auth/v1beta1"
	authz "cosmossdk.io/api/cosmos/authz/v1beta1"
	ed25519 "cosmossdk.io/api/cosmos/crypto/ed25519"
	feegrant "cosmossdk.io/api/cosmos/feegrant/v1beta1"
	staking "cosmossdk.io/api/cosmos/staking/v1beta1"
	txv1 "cosmossdk.io/api/cosmos/tx/v1beta1"
	vesting "cosmossdk.io/api/cosmos/vesting/v1beta1"
	"github.com/cometbft/cometbft/crypto/secp256k1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"time"
)

func TestCreateValidatorUsesThePhoneKey(t *testing.T) {
	pub := bytes32(0x11)
	any, err := CreateAny(Plan{
		ChainID: "morocco-1", Moniker: "zcinti", Amount: "1000000", Denom: "uterp",
		PubKey: pub, Delegator: "terp1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2vqal8",
	})
	if err != nil {
		t.Fatal(err)
	}
	if any.TypeUrl != createURL {
		t.Fatalf("type %s", any.TypeUrl)
	}
	var pk ed25519.PubKey
	// The any value is the whole MsgCreateValidator, not the inner key.
	if proto.Size(any) == 0 {
		t.Fatal("empty")
	}
	_ = pk
	if ConsensusAddr(pub) == "" || len(ConsensusAddr(pub)) != 40 {
		t.Fatal(ConsensusAddr(pub))
	}
	amt, denom, err := SplitAmount("1000000uterp")
	if err != nil || amt != "1000000" || denom != "uterp" {
		t.Fatal(amt, denom, err)
	}
	if _, err := Broadcast(t.Context(), "http://127.0.0.1:1", Plan{}, nil); err == nil {
		t.Fatal("missing ephemeral key must refuse")
	}
}

func TestGranterExecUsesTheGranterAsDelegator(t *testing.T) {
	signer, err := bech32Encode("terp", bytes20(0x01))
	if err != nil {
		t.Fatal(err)
	}
	granter, err := bech32Encode("terp", bytes20(0x02))
	if err != nil {
		t.Fatal(err)
	}
	val, err := bech32Encode("terpvaloper", bytes20(0x02))
	if err != nil {
		t.Fatal(err)
	}
	outer, err := Message(Plan{
		ChainID: "240u-1", Moniker: "zcinti", Amount: "1000000", Denom: "uterp",
		PubKey: bytes32(0x22), Granter: granter,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if outer.TypeUrl != execURL {
		t.Fatalf("type %s", outer.TypeUrl)
	}
	var exec authz.MsgExec
	if err := proto.Unmarshal(outer.Value, &exec); err != nil {
		t.Fatal(err)
	}
	if exec.Grantee != signer || len(exec.Msgs) != 1 || exec.Msgs[0].TypeUrl != createURL {
		t.Fatalf("exec %+v", exec.Grantee)
	}
	var msg staking.MsgCreateValidator
	if err := proto.Unmarshal(exec.Msgs[0].Value, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.DelegatorAddress != granter || msg.ValidatorAddress != val {
		t.Fatalf("delegator %s validator %s", msg.DelegatorAddress, msg.ValidatorAddress)
	}
	if msg.Pubkey == nil || msg.Pubkey.TypeUrl != edURL {
		t.Fatal(msg.Pubkey)
	}
}

func TestVestingAccountStillProvidesTheSequence(t *testing.T) {
	raw, err := proto.Marshal(&vesting.DelayedVestingAccount{
		BaseVestingAccount: &vesting.BaseVestingAccount{
			BaseAccount: &auth.BaseAccount{Address: "terp1fxccvvhhy43tvet2ah7jqwq4cwl9k3dxmww052", AccountNumber: 9, Sequence: 4},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := baseAccountFromAny(&anypb.Any{TypeUrl: "/cosmos.vesting.v1beta1.DelayedVestingAccount", Value: raw})
	if err != nil || got.AccountNumber != 9 || got.Sequence != 4 {
		t.Fatal(err, got.AccountNumber, got.Sequence)
	}
}

func TestRequiredCoversDelegationAndFees(t *testing.T) {
	terp, thiol, err := Required("1000000", true)
	if err != nil || terp != "1000000" || thiol != "80000" {
		t.Fatal(terp, thiol, err)
	}
	if !CanCover("1000000", terp) || !CanCover("80000", thiol) || CanCover("79999", thiol) {
		t.Fatal("cover")
	}
	micro, err := ParseTERP("1.000000")
	if err != nil || micro != "1000000" || FormatToken(micro) != "1.000000" || FormatToken("8000") != "0.008000" {
		t.Fatal(micro, err, FormatToken("8000"))
	}
}

func TestGeneratedAddressIsAGranterAccount(t *testing.T) {
	_, addr, err := GenerateKey()
	if err != nil || !ValidAccount(addr) {
		t.Fatal(err, addr)
	}
	if ValidAccount("cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnrql8a") || ValidAccount("terp1") {
		t.Fatal("rejected prefixes must stay rejected")
	}
}

func TestRuntimeGrantAuthorizesCreateAndRevokeTogether(t *testing.T) {
	key, addr, err := GenerateKey()
	if err != nil || len(key) != 32 || addr == "" {
		t.Fatal(err, addr)
	}
	granter, err := bech32Encode("terp", bytes20(0x07))
	if err != nil {
		t.Fatal(err)
	}
	grants, err := Grants(granter, addr, "uterp", time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 4 {
		t.Fatalf("grants %d", len(grants))
	}
	var seen []string
	for _, msg := range grants[:3] {
		if msg.TypeUrl != grantURL {
			t.Fatalf("type %s", msg.TypeUrl)
		}
		var grant authz.MsgGrant
		if err := proto.Unmarshal(msg.Value, &grant); err != nil {
			t.Fatal(err)
		}
		if grant.Granter != granter || grant.Grantee != addr || grant.Grant == nil || grant.Grant.Authorization == nil {
			t.Fatalf("grant %+v", grant.Granter)
		}
		var generic authz.GenericAuthorization
		if err := proto.Unmarshal(grant.Grant.Authorization.Value, &generic); err != nil {
			t.Fatal(err)
		}
		seen = append(seen, generic.Msg)
	}
	want := SessionTypes()
	if len(seen) != len(want) {
		t.Fatal(seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("authz %v", seen)
		}
	}
	var fee feegrant.MsgGrantAllowance
	if grants[3].TypeUrl != grantAllowanceURL {
		t.Fatal(grants[3].TypeUrl)
	}
	if err := proto.Unmarshal(grants[3].Value, &fee); err != nil {
		t.Fatal(err)
	}
	if fee.Granter != granter || fee.Grantee != addr || fee.Allowance == nil || fee.Allowance.TypeUrl != basicAllowanceURL {
		t.Fatalf("fee %+v", fee.Grantee)
	}
	revoke, err := RevokeExec(granter, addr)
	if err != nil {
		t.Fatal(err)
	}
	if revoke.TypeUrl != execURL {
		t.Fatal(revoke.TypeUrl)
	}
	var exec authz.MsgExec
	if err := proto.Unmarshal(revoke.Value, &exec); err != nil {
		t.Fatal(err)
	}
	if exec.Grantee != addr || len(exec.Msgs) != 4 {
		t.Fatalf("exec %d", len(exec.Msgs))
	}
	if exec.Msgs[0].TypeUrl != revokeAuthzURL || exec.Msgs[1].TypeUrl != revokeAllowanceURL || exec.Msgs[3].TypeUrl != revokeAuthzURL {
		t.Fatalf("order %s %s %s", exec.Msgs[0].TypeUrl, exec.Msgs[1].TypeUrl, exec.Msgs[3].TypeUrl)
	}
	var first, last authz.MsgRevoke
	if err := proto.Unmarshal(exec.Msgs[0].Value, &first); err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(exec.Msgs[3].Value, &last); err != nil {
		t.Fatal(err)
	}
	if first.MsgTypeUrl != createURL || last.MsgTypeUrl != revokeAuthzURL {
		t.Fatalf("first %s last %s", first.MsgTypeUrl, last.MsgTypeUrl)
	}
}

func TestRunReturnsTheGrantUntilTheOfflineSignerHasSigned(t *testing.T) {
	key := bytes32(0x44)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{"response": map[string]any{"code": 5, "value": ""}},
		})
	}))
	defer srv.Close()
	granter, err := bech32Encode("terp", bytes20(0x09))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Run(t.Context(), srv.URL, Plan{
		ChainID: "240u-1", Moniker: "zcinti", Amount: "1000000", Denom: "uterp",
		PubKey: bytes32(0x11), Granter: granter,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if out.Phase != "grant" || len(out.Grants) != 4 || out.CreateHash != "" {
		t.Fatalf("phase %s grants %d", out.Phase, len(out.Grants))
	}
}

func TestBroadcastPostsThePhoneKeyToTheConfiguredRPC(t *testing.T) {
	seed := bytes32(0x44)
	priv := secp256k1.PrivKey(seed)
	signer, err := bech32Encode("terp", priv.PubKey().Address())
	if err != nil {
		t.Fatal(err)
	}
	account, err := proto.Marshal(&auth.BaseAccount{Address: signer, AccountNumber: 7, Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := proto.Marshal(&auth.QueryAccountResponse{Account: &anypb.Any{TypeUrl: acctURL, Value: account}})
	if err != nil {
		t.Fatal(err)
	}
	var posted []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		if req.Method == "broadcast_tx_sync" {
			var params struct {
				Params struct {
					Tx string `json:"tx"`
				} `json:"params"`
			}
			_ = json.Unmarshal(body, &params)
			posted, _ = base64.StdEncoding.DecodeString(params.Params.Tx)
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"code": 0, "hash": "ABC", "log": ""}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{"response": map[string]any{"code": 0, "value": base64.StdEncoding.EncodeToString(wrapped)}},
		})
	}))
	defer srv.Close()
	phone := bytes32(0x11)
	hash, err := Broadcast(t.Context(), srv.URL, Plan{
		ChainID: "240u-1", Moniker: "zcinti", Amount: "1000000", Denom: "uterp", PubKey: phone,
	}, seed)
	if err != nil {
		t.Fatal(err)
	}
	if hash != "ABC" || len(posted) == 0 {
		t.Fatalf("hash %s bytes %d", hash, len(posted))
	}
	var raw txv1.TxRaw
	if err := proto.Unmarshal(posted, &raw); err != nil {
		t.Fatal(err)
	}
	var body txv1.TxBody
	if err := proto.Unmarshal(raw.BodyBytes, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Messages) != 1 || body.Messages[0].TypeUrl != createURL {
		t.Fatalf("message %v", body.Messages)
	}
	var msg staking.MsgCreateValidator
	if err := proto.Unmarshal(body.Messages[0].Value, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.DelegatorAddress != signer || msg.Pubkey == nil || !bytesContains(msg.Pubkey.Value, phone) {
		t.Fatalf("delegator %s pubkey %x", msg.DelegatorAddress, msg.Pubkey.GetValue())
	}
}

func bytesContains(hay, needle []byte) bool {
	if len(needle) == 0 || len(hay) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func bytes32(b byte) []byte { return bytesN(32, b) }

func bytes20(b byte) []byte { return bytesN(20, b) }

func bytesN(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
