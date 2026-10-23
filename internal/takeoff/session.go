package takeoff

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	authz "cosmossdk.io/api/cosmos/authz/v1beta1"
	base "cosmossdk.io/api/cosmos/base/v1beta1"
	feegrant "cosmossdk.io/api/cosmos/feegrant/v1beta1"
	"github.com/cometbft/cometbft/crypto/secp256k1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	revokeAuthzURL     = "/cosmos.authz.v1beta1.MsgRevoke"
	revokeAllowanceURL = "/cosmos.feegrant.v1beta1.MsgRevokeAllowance"
	genericURL         = "/cosmos.authz.v1beta1.GenericAuthorization"
	grantURL           = "/cosmos.authz.v1beta1.MsgGrant"
	grantAllowanceURL  = "/cosmos.feegrant.v1beta1.MsgGrantAllowance"
	basicAllowanceURL  = "/cosmos.feegrant.v1beta1.BasicAllowance"
	// House peers require 0.05 uthiol per gas. 400000 gas is 20000 uthiol.
	// 800000 gas is 40000 uthiol. The feegrant covers two action fees.
	actionFee         = "20000"
	grantTxFee        = "40000"
	sessionSpendLimit = "40000"
	feeDenom          = "uthiol"
	stakeDenom        = "uterp"
	sessionDuration   = 2 * time.Hour
)

// AminoFee is the fee on the grant the phone signs. The broadcast uses the
// same amount, or the chain rejects the signature.
func AminoFee() string { return grantTxFee }

// SessionTypes are the authz grants in one offline signature.
// Create-validator, revoke, and revoke-allowance are the same step.
func SessionTypes() []string {
	return []string{createURL, revokeAuthzURL, revokeAllowanceURL}
}

// GenerateKey mints the ephemeral account for this runtime.
// The bytes stay in memory. The address is what the offline signer grants.
func GenerateKey() ([]byte, string, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, "", err
	}
	priv := secp256k1.PrivKey(seed)
	addr, err := bech32Encode("terp", priv.PubKey().Address())
	if err != nil {
		return nil, "", err
	}
	return seed, addr, nil
}

// ValidAccount reports a terp bech32 account address.
func ValidAccount(address string) bool {
	hrp, raw, err := bech32Decode(strings.TrimSpace(address))
	return err == nil && hrp == "terp" && len(raw) == 20
}

// AddressOf is the terp account for an ephemeral key.
func AddressOf(key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("takeoff: ephemeral key is not configured")
	}
	priv := secp256k1.PrivKey(key)
	return bech32Encode("terp", priv.PubKey().Address())
}

// Missing is the authz types and the feegrant that are not already registered.
func Missing(ctx context.Context, rpc, granter, grantee string) (types []string, fee bool, err error) {
	for _, typeURL := range SessionTypes() {
		ok, err := hasGrant(ctx, rpc, granter, grantee, typeURL)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			types = append(types, typeURL)
		}
	}
	ok, err := allowanceCoversBoth(ctx, rpc, granter, grantee)
	if err != nil {
		return nil, false, err
	}
	return types, !ok, nil
}

// Grants is the one signature the offline granter signs.
// It allows this ephemeral account to create the validator and to revoke
// that authz and the feegrant afterwards.
func Grants(granter, grantee, denom string, now time.Time) ([]*anypb.Any, error) {
	if granter == "" || grantee == "" {
		return nil, fmt.Errorf("takeoff: granter and ephemeral account are required")
	}
	exp := timestamppb.New(now.Add(sessionDuration))
	out := make([]*anypb.Any, 0, 4)
	for _, typeURL := range SessionTypes() {
		msg, err := grantMsg(granter, grantee, typeURL, exp)
		if err != nil {
			return nil, err
		}
		out = append(out, msg)
	}
	fee, err := allowanceMsg(granter, grantee, denom, exp)
	if err != nil {
		return nil, err
	}
	out = append(out, fee)
	return out, nil
}

func grantsFor(granter, grantee, denom string, now time.Time, types []string, fee bool) ([]*anypb.Any, error) {
	exp := timestamppb.New(now.Add(sessionDuration))
	out := make([]*anypb.Any, 0, len(types)+1)
	for _, typeURL := range types {
		msg, err := grantMsg(granter, grantee, typeURL, exp)
		if err != nil {
			return nil, err
		}
		out = append(out, msg)
	}
	if fee {
		msg, err := allowanceMsg(granter, grantee, denom, exp)
		if err != nil {
			return nil, err
		}
		out = append(out, msg)
	}
	return out, nil
}

// RevokeExec is the ephemeral transaction that drops the session.
// MsgRevoke of the revoke authority is last, matching the cw-orch order,
// so the feegrant can pay this transaction before the allowance is removed.
func RevokeExec(granter, grantee string) (*anypb.Any, error) {
	var msgs []*anypb.Any
	for _, typeURL := range []string{createURL} {
		msg, err := revokeMsg(granter, grantee, typeURL)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
	}
	allowance, err := revokeAllowanceMsg(granter, grantee)
	if err != nil {
		return nil, err
	}
	msgs = append(msgs, allowance)
	for _, typeURL := range []string{revokeAllowanceURL, revokeAuthzURL} {
		msg, err := revokeMsg(granter, grantee, typeURL)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
	}
	return execAny(grantee, msgs)
}

// Ready reports whether the offline grant and feegrant are already on the node.
func Ready(ctx context.Context, rpc, granter, grantee string) (bool, error) {
	for _, typeURL := range SessionTypes() {
		ok, err := hasGrant(ctx, rpc, granter, grantee, typeURL)
		if err != nil || !ok {
			return false, err
		}
	}
	return hasAllowance(ctx, rpc, granter, grantee)
}

// Outcome is one use of takeoff.
type Outcome struct {
	Phase      string
	Address    string
	Types      []string
	Grants     []*anypb.Any
	CreateHash string
	RevokeHash string
}

// Run generates nothing itself. The caller passes the runtime key.
// Without the offline grant it returns the messages to sign.
// With the grant it broadcasts create-validator, then the revoke.
func Run(ctx context.Context, rpc string, p Plan, key []byte) (Outcome, error) {
	addr, err := AddressOf(key)
	if err != nil {
		return Outcome{}, err
	}
	if p.Granter == "" {
		return Outcome{}, fmt.Errorf("takeoff: the offline granter account is required")
	}
	out := Outcome{Address: addr, Types: SessionTypes()}
	ready, err := Ready(ctx, rpc, p.Granter, addr)
	if err != nil {
		return Outcome{}, err
	}
	if !ready {
		grants, err := Grants(p.Granter, addr, p.Denom, time.Now())
		if err != nil {
			return Outcome{}, err
		}
		out.Phase = "grant"
		out.Grants = grants
		return out, nil
	}
	createHash, err := Broadcast(ctx, rpc, p, key)
	if err != nil {
		return Outcome{}, err
	}
	revoke, err := RevokeExec(p.Granter, addr)
	if err != nil {
		return Outcome{}, err
	}
	revokeHash, err := broadcastMessages(ctx, rpc, p.ChainID, p.Denom, p.Granter, key, []*anypb.Any{revoke}, "zcinti takeoff revoke")
	if err != nil {
		return Outcome{}, fmt.Errorf("takeoff: create %s, revoke: %w", createHash, err)
	}
	out.Phase = "done"
	out.CreateHash = createHash
	out.RevokeHash = revokeHash
	return out, nil
}

func grantMsg(granter, grantee, typeURL string, exp *timestamppb.Timestamp) (*anypb.Any, error) {
	auth, err := anypb.New(&authz.GenericAuthorization{Msg: typeURL})
	if err != nil {
		return nil, err
	}
	auth.TypeUrl = genericURL
	raw, err := proto.Marshal(&authz.MsgGrant{
		Granter: granter,
		Grantee: grantee,
		Grant:   &authz.Grant{Authorization: auth, Expiration: exp},
	})
	if err != nil {
		return nil, err
	}
	return &anypb.Any{TypeUrl: grantURL, Value: raw}, nil
}

func allowanceMsg(granter, grantee, denom string, exp *timestamppb.Timestamp) (*anypb.Any, error) {
	allow, err := anypb.New(&feegrant.BasicAllowance{
		SpendLimit: []*base.Coin{{Denom: denom, Amount: sessionSpendLimit}},
		Expiration: exp,
	})
	if err != nil {
		return nil, err
	}
	allow.TypeUrl = basicAllowanceURL
	raw, err := proto.Marshal(&feegrant.MsgGrantAllowance{
		Granter:   granter,
		Grantee:   grantee,
		Allowance: allow,
	})
	if err != nil {
		return nil, err
	}
	return &anypb.Any{TypeUrl: grantAllowanceURL, Value: raw}, nil
}

func revokeMsg(granter, grantee, typeURL string) (*anypb.Any, error) {
	raw, err := proto.Marshal(&authz.MsgRevoke{
		Granter:    granter,
		Grantee:    grantee,
		MsgTypeUrl: typeURL,
	})
	if err != nil {
		return nil, err
	}
	return &anypb.Any{TypeUrl: revokeAuthzURL, Value: raw}, nil
}

func revokeAllowanceMsg(granter, grantee string) (*anypb.Any, error) {
	raw, err := proto.Marshal(&feegrant.MsgRevokeAllowance{Granter: granter, Grantee: grantee})
	if err != nil {
		return nil, err
	}
	return &anypb.Any{TypeUrl: revokeAllowanceURL, Value: raw}, nil
}

func execAny(grantee string, msgs []*anypb.Any) (*anypb.Any, error) {
	raw, err := proto.Marshal(&authz.MsgExec{Grantee: grantee, Msgs: msgs})
	if err != nil {
		return nil, err
	}
	return &anypb.Any{TypeUrl: execURL, Value: raw}, nil
}

func hasGrant(ctx context.Context, rpc, granter, grantee, typeURL string) (bool, error) {
	raw, err := proto.Marshal(&authz.QueryGrantsRequest{Granter: granter, Grantee: grantee, MsgTypeUrl: typeURL})
	if err != nil {
		return false, err
	}
	val, code, err := abci(ctx, rpc, "/cosmos.authz.v1beta1.Query/Grants", raw)
	if err != nil || code != 0 || len(val) == 0 {
		return false, err
	}
	var resp authz.QueryGrantsResponse
	if err := proto.Unmarshal(val, &resp); err != nil {
		return false, err
	}
	return len(resp.Grants) > 0, nil
}

func hasAllowance(ctx context.Context, rpc, granter, grantee string) (bool, error) {
	ok, _, err := allowanceUthiol(ctx, rpc, granter, grantee)
	return ok, err
}

// allowanceCoversBoth is true when the uthiol spend limit can pay create and the revoke.
// A limit equal to one fee is deleted when create pays it, and the revoke then has no grant.
func allowanceCoversBoth(ctx context.Context, rpc, granter, grantee string) (bool, error) {
	ok, amount, err := allowanceUthiol(ctx, rpc, granter, grantee)
	if err != nil || !ok {
		return false, err
	}
	if amount == "" {
		return true, nil
	}
	need, _ := new(big.Int).SetString(sessionSpendLimit, 10)
	have, good := new(big.Int).SetString(amount, 10)
	return good && have.Cmp(need) >= 0, nil
}

func allowanceUthiol(ctx context.Context, rpc, granter, grantee string) (bool, string, error) {
	raw, err := proto.Marshal(&feegrant.QueryAllowanceRequest{Granter: granter, Grantee: grantee})
	if err != nil {
		return false, "", err
	}
	val, code, err := abci(ctx, rpc, "/cosmos.feegrant.v1beta1.Query/Allowance", raw)
	if err != nil || code != 0 || len(val) == 0 {
		return false, "", err
	}
	var resp feegrant.QueryAllowanceResponse
	if err := proto.Unmarshal(val, &resp); err != nil || resp.Allowance == nil || resp.Allowance.Allowance == nil {
		return false, "", err
	}
	if resp.Allowance.Allowance.TypeUrl != basicAllowanceURL && resp.Allowance.Allowance.TypeUrl != "cosmos-sdk/BasicAllowance" {
		return true, "", nil
	}
	var basic feegrant.BasicAllowance
	if err := proto.Unmarshal(resp.Allowance.Allowance.Value, &basic); err != nil {
		return false, "", err
	}
	if len(basic.SpendLimit) == 0 {
		return true, "", nil
	}
	for _, coin := range basic.SpendLimit {
		if coin.Denom == feeDenom {
			return true, coin.Amount, nil
		}
	}
	return true, "0", nil
}
