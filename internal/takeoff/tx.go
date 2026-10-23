// Package takeoff builds and broadcasts a create-validator transaction.
// The consensus key stays on the phone. An ephemeral account signs.
// Messages are the proto API terp-core already pins, cosmossdk.io/api.
package takeoff

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	auth "cosmossdk.io/api/cosmos/auth/v1beta1"
	bank "cosmossdk.io/api/cosmos/bank/v1beta1"
	base "cosmossdk.io/api/cosmos/base/v1beta1"
	ed25519 "cosmossdk.io/api/cosmos/crypto/ed25519"
	secp "cosmossdk.io/api/cosmos/crypto/secp256k1"
	staking "cosmossdk.io/api/cosmos/staking/v1beta1"
	signing "cosmossdk.io/api/cosmos/tx/signing/v1beta1"
	tx "cosmossdk.io/api/cosmos/tx/v1beta1"
	vesting "cosmossdk.io/api/cosmos/vesting/v1beta1"
	"github.com/cometbft/cometbft/crypto/secp256k1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// ErrAccountMissing is an auth query for an address the chain has not created.
var ErrAccountMissing = errors.New("takeoff: account is not on chain yet")

const (
	createURL = "/cosmos.staking.v1beta1.MsgCreateValidator"
	execURL   = "/cosmos.authz.v1beta1.MsgExec"
	edURL     = "/cosmos.crypto.ed25519.PubKey"
	secpURL   = "/cosmos.crypto.secp256k1.PubKey"
	acctURL   = "/cosmos.auth.v1beta1.BaseAccount"
)

// Plan is the public part of a create-validator transaction.
type Plan struct {
	ChainID   string
	Moniker   string
	Amount    string
	Denom     string
	PubKey    []byte
	Granter   string
	Delegator string
}

// CreateAny is the staking message. The pubkey is the phone's consensus key.
func CreateAny(p Plan) (*anypb.Any, error) {
	if len(p.PubKey) != 32 {
		return nil, fmt.Errorf("takeoff: consensus key is %d bytes", len(p.PubKey))
	}
	pk, err := anypb.New(&ed25519.PubKey{Key: p.PubKey})
	if err != nil {
		return nil, err
	}
	pk.TypeUrl = edURL
	msg := &staking.MsgCreateValidator{
		Description:       &staking.Description{Moniker: p.Moniker, Details: "zcinti"},
		Commission:        &staking.CommissionRates{Rate: "100000000000000000", MaxRate: "200000000000000000", MaxChangeRate: "10000000000000000"},
		MinSelfDelegation: "1",
		DelegatorAddress:  p.Delegator,
		ValidatorAddress:  valoper(p.Delegator),
		Pubkey:            pk,
		Value:             &base.Coin{Denom: p.Denom, Amount: p.Amount},
	}
	raw, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}
	return &anypb.Any{TypeUrl: createURL, Value: raw}, nil
}

// Message is the transaction body message.
// signer is the ephemeral account. With a granter, the validator account is
// the granter and the message is an authz MsgExec. The phone key is only the
// consensus pubkey inside MsgCreateValidator.
func Message(p Plan, signer string) (*anypb.Any, error) {
	if p.Granter != "" {
		p.Delegator = p.Granter
	} else if p.Delegator == "" {
		p.Delegator = signer
	}
	inner, err := CreateAny(p)
	if err != nil {
		return nil, err
	}
	if p.Granter == "" {
		return inner, nil
	}
	return execAny(signer, []*anypb.Any{inner})
}

// Broadcast signs with the ephemeral key and posts the tx to the configured RPC.
// When granter is set, the message is an authz MsgExec and the fee names that granter.
func Broadcast(ctx context.Context, rpc string, p Plan, ephemeral []byte) (string, error) {
	if len(ephemeral) != 32 {
		return "", fmt.Errorf("takeoff: ephemeral key is not configured")
	}
	priv := secp256k1.PrivKey(ephemeral)
	signer, err := bech32Encode("terp", priv.PubKey().Address())
	if err != nil {
		return "", err
	}
	msgAny, err := Message(p, signer)
	if err != nil {
		return "", err
	}
	return broadcastMessages(ctx, rpc, p.ChainID, p.Denom, p.Granter, ephemeral, []*anypb.Any{msgAny}, "zcinti takeoff")
}

// BroadcastRevoke sends the session revoke from the ephemeral account.
func BroadcastRevoke(ctx context.Context, rpc, chainID, denom, granter string, key []byte) (string, error) {
	grantee, err := AddressOf(key)
	if err != nil {
		return "", err
	}
	revoke, err := RevokeExec(granter, grantee)
	if err != nil {
		return "", err
	}
	return broadcastMessages(ctx, rpc, chainID, denom, granter, key, []*anypb.Any{revoke}, "zcinti takeoff revoke")
}

func broadcastMessages(ctx context.Context, rpc, chainID, denom, granter string, ephemeral []byte, msgs []*anypb.Any, memo string) (string, error) {
	if len(ephemeral) != 32 {
		return "", fmt.Errorf("takeoff: ephemeral key is not configured")
	}
	priv := secp256k1.PrivKey(ephemeral)
	signer, err := bech32Encode("terp", priv.PubKey().Address())
	if err != nil {
		return "", err
	}
	acct, seq, err := account(ctx, rpc, signer)
	if err != nil {
		return "", err
	}
	body := &tx.TxBody{Messages: msgs, Memo: memo}
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		return "", err
	}
	secpAny, err := anypb.New(&secp.PubKey{Key: priv.PubKey().Bytes()})
	if err != nil {
		return "", err
	}
	secpAny.TypeUrl = secpURL
	authInfo := &tx.AuthInfo{
		SignerInfos: []*tx.SignerInfo{{
			PublicKey: secpAny,
			ModeInfo:  &tx.ModeInfo{Sum: &tx.ModeInfo_Single_{Single: &tx.ModeInfo_Single{Mode: signing.SignMode_SIGN_MODE_DIRECT}}},
			Sequence:  seq,
		}},
		Fee: &tx.Fee{
			Amount:   []*base.Coin{{Denom: feeDenom, Amount: actionFee}},
			GasLimit: 400000,
			Granter:  granter,
		},
	}
	authBytes, err := proto.Marshal(authInfo)
	if err != nil {
		return "", err
	}
	doc := &tx.SignDoc{BodyBytes: bodyBytes, AuthInfoBytes: authBytes, ChainId: chainID, AccountNumber: acct}
	docBytes, err := proto.Marshal(doc)
	if err != nil {
		return "", err
	}
	sig, err := priv.Sign(docBytes)
	if err != nil {
		return "", err
	}
	raw := &tx.TxRaw{BodyBytes: bodyBytes, AuthInfoBytes: authBytes, Signatures: [][]byte{sig}}
	wire, err := proto.Marshal(raw)
	if err != nil {
		return "", err
	}
	return broadcast(ctx, rpc, wire)
}

// BroadcastAmino posts the grant the phone signed in Zigner's account scan.
// The signature is over the amino JSON, not a proto sign doc.
func BroadcastAmino(ctx context.Context, rpc, chainID string, account, sequence uint64, pub, sig, amino []byte, msgs []*anypb.Any) (string, error) {
	normalized, _, err := MatchAuthorization(pub, sig, amino)
	if err != nil {
		return "", err
	}
	sig = normalized
	body := &tx.TxBody{Messages: msgs, Memo: "cw-orch-session:v1"}
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		return "", err
	}
	secpAny, err := anypb.New(&secp.PubKey{Key: pub})
	if err != nil {
		return "", err
	}
	secpAny.TypeUrl = secpURL
	authInfo := &tx.AuthInfo{
		SignerInfos: []*tx.SignerInfo{{
			PublicKey: secpAny,
			ModeInfo:  &tx.ModeInfo{Sum: &tx.ModeInfo_Single_{Single: &tx.ModeInfo_Single{Mode: signing.SignMode_SIGN_MODE_LEGACY_AMINO_JSON}}},
			Sequence:  sequence,
		}},
		Fee: &tx.Fee{
			Amount:   []*base.Coin{{Denom: feeDenom, Amount: AminoFee()}},
			GasLimit: 800000,
		},
	}
	authBytes, err := proto.Marshal(authInfo)
	if err != nil {
		return "", err
	}
	raw := &tx.TxRaw{BodyBytes: bodyBytes, AuthInfoBytes: authBytes, Signatures: [][]byte{sig}}
	wire, err := proto.Marshal(raw)
	if err != nil {
		return "", err
	}
	_ = account
	_ = chainID
	return broadcast(ctx, rpc, wire)
}

// ConsensusAddr is the comet address of an ed25519 consensus key.
func ConsensusAddr(pub []byte) string {
	sum := sha256.Sum256(pub)
	return strings.ToUpper(hex.EncodeToString(sum[:20]))
}

// InValidatorSet reports whether pub is in the comet validator set at the node RPC.
func InValidatorSet(ctx context.Context, rpc string, pub []byte) (bool, error) {
	want := ConsensusAddr(pub)
	client := &http.Client{Timeout: 2 * time.Second}
	for page := 1; page <= 20; page++ {
		endpoint := fmt.Sprintf("%s/validators?page=%d&per_page=100", strings.TrimRight(rpc, "/"), page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return false, err
		}
		var body struct {
			Result struct {
				Validators []struct {
					Address string `json:"address"`
				} `json:"validators"`
			} `json:"result"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if err != nil {
			return false, err
		}
		if len(body.Result.Validators) == 0 {
			return false, nil
		}
		for _, v := range body.Result.Validators {
			if strings.EqualFold(v.Address, want) {
				return true, nil
			}
		}
		if len(body.Result.Validators) < 100 {
			return false, nil
		}
	}
	return false, nil
}

// Spendable is the granter's spendable balance for denom. A missing coin is zero.
func Spendable(ctx context.Context, rpc, addr, denom string) (string, error) {
	raw, err := proto.Marshal(&bank.QuerySpendableBalancesRequest{Address: addr})
	if err != nil {
		return "", err
	}
	val, code, err := abci(ctx, rpc, "/cosmos.bank.v1beta1.Query/SpendableBalances", raw)
	if err != nil {
		return "", err
	}
	if code != 0 || len(val) == 0 {
		return "0", nil
	}
	var resp bank.QuerySpendableBalancesResponse
	if err := proto.Unmarshal(val, &resp); err != nil {
		return "", err
	}
	for _, coin := range resp.GetBalances() {
		if coin.GetDenom() == denom {
			if coin.GetAmount() == "" {
				return "0", nil
			}
			return coin.GetAmount(), nil
		}
	}
	return "0", nil
}

// Required splits the cost. Self-delegation is TERP. Gas is THIOL.
// Both strings are micro units, six decimals on the page.
func Required(delegation string, includeGrant bool) (terp, thiol string, err error) {
	del, ok := new(big.Int).SetString(delegation, 10)
	if !ok {
		return "", "", fmt.Errorf("takeoff: self-delegation is not a whole number")
	}
	grant, run := Fees(includeGrant)
	fee, ok := new(big.Int).SetString(grant, 10)
	if !ok {
		return "", "", fmt.Errorf("takeoff: fee")
	}
	rest, ok := new(big.Int).SetString(run, 10)
	if !ok {
		return "", "", fmt.Errorf("takeoff: fee")
	}
	return del.String(), fee.Add(fee, rest).String(), nil
}

// ParseTERP reads a 6-decimal TERP amount into micro units.
func ParseTERP(text string) (string, error) {
	text = strings.TrimSpace(text)
	text = strings.TrimSuffix(text, "uterp")
	text = strings.TrimSuffix(text, "TERP")
	text = strings.TrimSpace(text)
	whole, frac, found := strings.Cut(text, ".")
	if whole == "" || strings.Contains(frac, ".") {
		return "", fmt.Errorf("takeoff: self-delegation must be TERP with up to 6 decimals")
	}
	for _, c := range whole + frac {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("takeoff: self-delegation must be TERP with up to 6 decimals")
		}
	}
	if len(frac) > 6 {
		return "", fmt.Errorf("takeoff: self-delegation must be TERP with up to 6 decimals")
	}
	for len(frac) < 6 {
		frac += "0"
	}
	micro := strings.TrimLeft(whole+frac, "0")
	if micro == "" {
		micro = "0"
	}
	_ = found
	return micro, nil
}

// FormatToken prints micro units as a 6-decimal token amount.
func FormatToken(micro string) string {
	n, ok := new(big.Int).SetString(micro, 10)
	if !ok {
		return micro
	}
	neg := n.Sign() < 0
	if neg {
		n.Abs(n)
	}
	scale := big.NewInt(1_000_000)
	whole, frac := new(big.Int).QuoRem(n, scale, new(big.Int))
	out := fmt.Sprintf("%s.%06d", whole.String(), frac.Int64())
	if neg {
		return "-" + out
	}
	return out
}

// Fees is the granter fee for a new authorization and for create plus revoke.
func Fees(includeGrant bool) (grant, run string) {
	runFees, _ := new(big.Int).SetString(actionFee, 10)
	runFees.Mul(runFees, big.NewInt(2))
	oneGrant := "0"
	if includeGrant {
		oneGrant = grantTxFee
	}
	return oneGrant, runFees.String()
}

// CanCover reports whether spendable balance covers the required amount.
func CanCover(balance, required string) bool {
	have, ok1 := new(big.Int).SetString(balance, 10)
	need, ok2 := new(big.Int).SetString(required, 10)
	return ok1 && ok2 && have.Cmp(need) >= 0
}

// AccountNumbers is the granter's account number and sequence.
func AccountNumbers(ctx context.Context, rpc, addr string) (uint64, uint64, error) {
	return account(ctx, rpc, addr)
}

func account(ctx context.Context, rpc, addr string) (uint64, uint64, error) {
	q := &auth.QueryAccountRequest{Address: addr}
	data, err := proto.Marshal(q)
	if err != nil {
		return 0, 0, err
	}
	val, code, err := abci(ctx, rpc, "/cosmos.auth.v1beta1.Query/Account", data)
	if err != nil {
		return 0, 0, err
	}
	if code == 22 {
		return 0, 0, fmt.Errorf("%w: %s (sdk key not found). The feegrant creates this account when the grant is in a block", ErrAccountMissing, addr)
	}
	if code != 0 {
		return 0, 0, fmt.Errorf("takeoff: account query code %d", code)
	}
	if len(val) == 0 {
		return 0, 0, fmt.Errorf("takeoff: account %s is not on this chain", addr)
	}
	var qr auth.QueryAccountResponse
	if err := proto.Unmarshal(val, &qr); err != nil || qr.Account == nil {
		return 0, 0, fmt.Errorf("takeoff: account response")
	}
	baseAcct, err := baseAccountFromAny(qr.Account)
	if err != nil {
		return 0, 0, err
	}
	return baseAcct.AccountNumber, baseAcct.Sequence, nil
}

func baseAccountFromAny(msg *anypb.Any) (auth.BaseAccount, error) {
	var nested *auth.BaseAccount
	switch msg.GetTypeUrl() {
	case acctURL:
		var account auth.BaseAccount
		if err := proto.Unmarshal(msg.GetValue(), &account); err != nil {
			return auth.BaseAccount{}, err
		}
		return account, nil
	case "/cosmos.vesting.v1beta1.DelayedVestingAccount":
		var account vesting.DelayedVestingAccount
		if err := proto.Unmarshal(msg.GetValue(), &account); err != nil {
			return auth.BaseAccount{}, err
		}
		nested = vestingBase(account.GetBaseVestingAccount())
	case "/cosmos.vesting.v1beta1.ContinuousVestingAccount":
		var account vesting.ContinuousVestingAccount
		if err := proto.Unmarshal(msg.GetValue(), &account); err != nil {
			return auth.BaseAccount{}, err
		}
		nested = vestingBase(account.GetBaseVestingAccount())
	case "/cosmos.vesting.v1beta1.PeriodicVestingAccount":
		var account vesting.PeriodicVestingAccount
		if err := proto.Unmarshal(msg.GetValue(), &account); err != nil {
			return auth.BaseAccount{}, err
		}
		nested = vestingBase(account.GetBaseVestingAccount())
	case "/cosmos.vesting.v1beta1.PermanentLockedAccount":
		var account vesting.PermanentLockedAccount
		if err := proto.Unmarshal(msg.GetValue(), &account); err != nil {
			return auth.BaseAccount{}, err
		}
		nested = vestingBase(account.GetBaseVestingAccount())
	default:
		return auth.BaseAccount{}, fmt.Errorf("takeoff: unexpected account %s", msg.GetTypeUrl())
	}
	if nested == nil {
		return auth.BaseAccount{}, fmt.Errorf("takeoff: vesting account has no base account")
	}
	return *nested, nil
}

func vestingBase(account *vesting.BaseVestingAccount) *auth.BaseAccount {
	if account == nil {
		return nil
	}
	return account.GetBaseAccount()
}

func abci(ctx context.Context, rpc, path string, data []byte) ([]byte, int, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "abci_query",
		"params": map[string]any{
			"path":  path,
			"data":  hex.EncodeToString(data),
			"prove": false,
		},
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(rpc, "/"), bytes.NewReader(raw))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var out struct {
		Result struct {
			Response struct {
				Value string `json:"value"`
				Code  int    `json:"code"`
			} `json:"response"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, 0, err
	}
	if out.Result.Response.Value == "" {
		return nil, out.Result.Response.Code, nil
	}
	val, err := base64.StdEncoding.DecodeString(out.Result.Response.Value)
	if err != nil {
		return nil, out.Result.Response.Code, err
	}
	return val, out.Result.Response.Code, nil
}

func broadcast(ctx context.Context, rpc string, txBytes []byte) (string, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "broadcast_tx_sync",
		"params":  map[string]any{"tx": base64.StdEncoding.EncodeToString(txBytes)},
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(rpc, "/"), bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		Result struct {
			Code int    `json:"code"`
			Log  string `json:"log"`
			Hash string `json:"hash"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.Error != nil {
		return "", fmt.Errorf("takeoff: %s", out.Error.Message)
	}
	if out.Result.Code != 0 {
		return "", fmt.Errorf("takeoff: %s", out.Result.Log)
	}
	if err := waitTx(ctx, rpc, out.Result.Hash); err != nil {
		return out.Result.Hash, err
	}
	return out.Result.Hash, nil
}

// waitTx blocks until the mempool acceptance is in a block.
// The feegrant creates the ephemeral account at that moment, and the fee is paid by the granter.
func waitTx(ctx context.Context, rpc, hash string) error {
	deadline := time.Now().Add(2 * time.Minute)
	endpoint := strings.TrimRight(rpc, "/") + "/tx?hash=0x" + hash
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var out struct {
				Result *struct {
					TxResult struct {
						Code int    `json:"code"`
						Log  string `json:"log"`
					} `json:"tx_result"`
				} `json:"result"`
				Error *struct {
					Data string `json:"data"`
				} `json:"error"`
			}
			_ = json.Unmarshal(body, &out)
			if out.Result != nil && resp.StatusCode == http.StatusOK {
				if out.Result.TxResult.Code != 0 {
					return fmt.Errorf("takeoff: tx %s code %d %s", hash, out.Result.TxResult.Code, out.Result.TxResult.Log)
				}
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("takeoff: tx %s was accepted into the mempool and is not in a block yet", hash)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func valoper(account string) string {
	hrp, raw, err := bech32Decode(account)
	if err != nil || hrp != "terp" {
		return ""
	}
	out, err := bech32Encode("terpvaloper", raw)
	if err != nil {
		return ""
	}
	return out
}

// SplitAmount splits 1000000uterp into amount and denom.
func SplitAmount(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	i := strings.IndexFunc(raw, func(r rune) bool { return r < '0' || r > '9' })
	if i <= 0 {
		return "", "", fmt.Errorf("takeoff: amount needs a denom")
	}
	return raw[:i], raw[i:], nil
}
