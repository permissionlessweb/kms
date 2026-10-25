package takeoff

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	base "cosmossdk.io/api/cosmos/base/v1beta1"
	secp "cosmossdk.io/api/cosmos/crypto/secp256k1"
	distr "cosmossdk.io/api/cosmos/distribution/v1beta1"
	slashing "cosmossdk.io/api/cosmos/slashing/v1beta1"
	staking "cosmossdk.io/api/cosmos/staking/v1beta1"
	signing "cosmossdk.io/api/cosmos/tx/signing/v1beta1"
	tx "cosmossdk.io/api/cosmos/tx/v1beta1"
	"github.com/skip2/go-qrcode"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Direct signing: the owner account signs ONE legacy-amino tx that carries
// the action messages themselves and pays the THIOL fee. No authz, no
// feegrant, no session key, nothing left behind to revoke.
const (
	// DirectMemo starts with cw-orch- so zigner answers with ur:cworch-sig
	// (pubkey + signature); a plain hex signature is accepted too.
	DirectMemo = "cw-orch-action:v1"
	// gas price matches the grant tx: 0.05 uthiol per gas.
	directGasBase   = 250000
	directGasPerMsg = 150000
)

// DirectFee is the gas limit and uthiol fee for n action messages.
func DirectFee(n int) (gas uint64, fee string) {
	if n < 1 {
		n = 1
	}
	gas = uint64(directGasBase + directGasPerMsg*n)
	return gas, fmt.Sprintf("%d", gas/20)
}

// PrepareDirect builds the owner-signed sign doc, its zigner QR and the
// matching proto messages for the inner action messages.
func PrepareDirect(owner, chainID string, acct, seq uint64, inner []*anypb.Any) (Prepared, error) {
	if !ValidAccount(owner) {
		return Prepared{}, fmt.Errorf("takeoff: owner account is required")
	}
	if len(inner) == 0 {
		return Prepared{}, fmt.Errorf("takeoff: nothing to sign")
	}
	var msgs []string
	for _, a := range inner {
		js, err := aminoMsg(a)
		if err != nil {
			return Prepared{}, err
		}
		msgs = append(msgs, js)
	}
	gas, fee := DirectFee(len(inner))
	doc := fmt.Sprintf(
		`{"account_number":%s,"chain_id":%s,"fee":{"amount":[{"amount":%s,"denom":%s}],"gas":%s},"memo":%s,"msgs":[%s],"sequence":%s}`,
		js(fmt.Sprintf("%d", acct)), js(chainID), js(fee), js(feeDenom), js(fmt.Sprintf("%d", gas)), js(DirectMemo),
		strings.Join(msgs, ","), js(fmt.Sprintf("%d", seq)),
	)
	png, err := qrcode.Encode(string(cosmosQR([]byte(doc))), qrcode.Low, 640)
	if err != nil {
		return Prepared{}, err
	}
	return Prepared{
		Amino: []byte(doc), Msgs: inner, PNG: png, Kind: "direct",
		Granter: owner, Account: acct, Sequence: seq,
		Memo: DirectMemo, Fee: fee, Gas: gas,
	}, nil
}

// js is a JSON string exactly as the SDK's sorted amino JSON writes it
// (Go encoding/json, which also escapes <, > and &).
func js(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func coinJSON(c *base.Coin) string {
	return fmt.Sprintf(`{"amount":%s,"denom":%s}`, js(c.GetAmount()), js(c.GetDenom()))
}

// obj writes sorted keys, dropping empty values like amino JSON omitempty.
func obj(kv ...string) string {
	var parts []string
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" || kv[i+1] == `""` {
			continue
		}
		parts = append(parts, js(kv[i])+":"+kv[i+1])
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func strOrEmpty(s string) string {
	if s == "" {
		return ""
	}
	return js(s)
}

// decAmino turns a 1e18-scaled LegacyDec wire string into amino's "0.050000000000000000".
func decAmino(wire string) (string, error) {
	if wire == "" {
		return "", nil
	}
	for _, c := range wire {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("takeoff: bad dec %q", wire)
		}
	}
	for len(wire) < 19 {
		wire = "0" + wire
	}
	return wire[:len(wire)-18] + "." + wire[len(wire)-18:], nil
}

// aminoMsg is the legacy amino JSON of one supported action message.
func aminoMsg(a *anypb.Any) (string, error) {
	wrap := func(t, v string) string { return `{"type":` + js(t) + `,"value":` + v + `}` }
	switch a.TypeUrl {
	case delegateURL, undelegateURL:
		var m staking.MsgDelegate // same wire shape as MsgUndelegate
		if err := proto.Unmarshal(a.Value, &m); err != nil {
			return "", err
		}
		t := "cosmos-sdk/MsgDelegate"
		if a.TypeUrl == undelegateURL {
			t = "cosmos-sdk/MsgUndelegate"
		}
		return wrap(t, obj("amount", coinJSON(m.Amount), "delegator_address", strOrEmpty(m.DelegatorAddress), "validator_address", strOrEmpty(m.ValidatorAddress))), nil
	case withdrawURL:
		var m distr.MsgWithdrawDelegatorReward
		if err := proto.Unmarshal(a.Value, &m); err != nil {
			return "", err
		}
		return wrap("cosmos-sdk/MsgWithdrawDelegationReward", obj("delegator_address", strOrEmpty(m.DelegatorAddress), "validator_address", strOrEmpty(m.ValidatorAddress))), nil
	case commissionURL:
		var m distr.MsgWithdrawValidatorCommission
		if err := proto.Unmarshal(a.Value, &m); err != nil {
			return "", err
		}
		return wrap("cosmos-sdk/MsgWithdrawValCommission", obj("validator_address", strOrEmpty(m.ValidatorAddress))), nil
	case unjailURL:
		var m slashing.MsgUnjail
		if err := proto.Unmarshal(a.Value, &m); err != nil {
			return "", err
		}
		return wrap("cosmos-sdk/MsgUnjail", obj("address", strOrEmpty(m.ValidatorAddr))), nil
	case createURL:
		return aminoCreate(a)
	case editURL:
		var m staking.MsgEditValidator
		if err := proto.Unmarshal(a.Value, &m); err != nil {
			return "", err
		}
		d := m.Description
		if d == nil {
			d = &staking.Description{}
		}
		desc := obj("details", strOrEmpty(d.Details), "identity", strOrEmpty(d.Identity), "moniker", strOrEmpty(d.Moniker), "security_contact", strOrEmpty(d.SecurityContact), "website", strOrEmpty(d.Website))
		rate, err := decAmino(m.CommissionRate)
		if err != nil {
			return "", err
		}
		return wrap("cosmos-sdk/MsgEditValidator", obj("commission_rate", strOrEmpty(rate), "description", desc, "min_self_delegation", strOrEmpty(m.MinSelfDelegation), "validator_address", strOrEmpty(m.ValidatorAddress))), nil
	}
	return "", fmt.Errorf("takeoff: %s cannot be signed directly", a.TypeUrl)
}

// SignedTx is the TxRaw for a Prepared sign doc and its signature.
func SignedTx(p Prepared, pub, sig []byte) ([]byte, error) {
	normalized, _, err := MatchAuthorization(pub, sig, p.Amino)
	if err != nil {
		return nil, err
	}
	memo, fee, gas := p.Memo, p.Fee, p.Gas
	if memo == "" && fee == "" {
		memo, fee, gas = "cw-orch-session:v1", AminoFee(), 800000
	}
	bodyBytes, err := proto.Marshal(&tx.TxBody{Messages: p.Msgs, Memo: memo})
	if err != nil {
		return nil, err
	}
	secpAny, err := anypb.New(&secp.PubKey{Key: pub})
	if err != nil {
		return nil, err
	}
	secpAny.TypeUrl = secpURL
	authBytes, err := proto.Marshal(&tx.AuthInfo{
		SignerInfos: []*tx.SignerInfo{{
			PublicKey: secpAny,
			ModeInfo:  &tx.ModeInfo{Sum: &tx.ModeInfo_Single_{Single: &tx.ModeInfo_Single{Mode: signing.SignMode_SIGN_MODE_LEGACY_AMINO_JSON}}},
			Sequence:  p.Sequence,
		}},
		Fee: &tx.Fee{Amount: []*base.Coin{{Denom: feeDenom, Amount: fee}}, GasLimit: gas},
	})
	if err != nil {
		return nil, err
	}
	return proto.Marshal(&tx.TxRaw{BodyBytes: bodyBytes, AuthInfoBytes: authBytes, Signatures: [][]byte{normalized}})
}

// TxOutcome is what the chain did with one broadcast.
type TxOutcome struct {
	Hash   string `json:"hash"`
	Height int64  `json:"height,omitempty"`
	Code   int    `json:"code"`
	Log    string `json:"log,omitempty"`
	Stage  string `json:"stage"` // "rejected" (CheckTx), "pending", "failed" (DeliverTx), "committed"
}

// BroadcastSigned sends the one signed tx and waits for it to land.
func BroadcastSigned(ctx context.Context, rpc string, p Prepared, pub, sig []byte) (TxOutcome, error) {
	wire, err := SignedTx(p, pub, sig)
	if err != nil {
		return TxOutcome{Stage: "rejected", Log: err.Error()}, err
	}
	return broadcastOutcome(ctx, rpc, wire)
}

func broadcastOutcome(ctx context.Context, rpc string, wire []byte) (TxOutcome, error) {
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "broadcast_tx_sync",
		"params": map[string]any{"tx": base64.StdEncoding.EncodeToString(wire)},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(rpc, "/"), bytes.NewReader(payload))
	if err != nil {
		return TxOutcome{Stage: "rejected", Log: err.Error()}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return TxOutcome{Stage: "rejected", Log: err.Error()}, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out struct {
		Result struct {
			Code int    `json:"code"`
			Log  string `json:"log"`
			Hash string `json:"hash"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
			Data    string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return TxOutcome{Stage: "rejected", Log: err.Error()}, err
	}
	if out.Error != nil {
		o := TxOutcome{Stage: "rejected", Log: strings.TrimSpace(out.Error.Message + " " + out.Error.Data)}
		return o, fmt.Errorf("takeoff: %s", o.Log)
	}
	o := TxOutcome{Hash: out.Result.Hash, Code: out.Result.Code, Log: out.Result.Log}
	if o.Code != 0 {
		o.Stage = "rejected"
		return o, fmt.Errorf("takeoff: rejected (code %d): %s", o.Code, o.Log)
	}
	return WaitOutcome(ctx, rpc, o.Hash)
}

// WaitOutcome polls the node until the tx is in a block (up to 60s).
func WaitOutcome(ctx context.Context, rpc, hash string) (TxOutcome, error) {
	o := TxOutcome{Hash: hash, Stage: "pending"}
	deadline := time.Now().Add(60 * time.Second)
	endpoint := strings.TrimRight(rpc, "/") + "/tx?hash=0x" + hash
	for {
		if req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil); err == nil {
			if resp, err := http.DefaultClient.Do(req); err == nil {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				var out struct {
					Result *struct {
						Height   string `json:"height"`
						TxResult struct {
							Code int    `json:"code"`
							Log  string `json:"log"`
						} `json:"tx_result"`
					} `json:"result"`
				}
				if json.Unmarshal(body, &out) == nil && out.Result != nil && resp.StatusCode == http.StatusOK {
					o.Height, _ = strconv.ParseInt(out.Result.Height, 10, 64)
					o.Code, o.Log = out.Result.TxResult.Code, out.Result.TxResult.Log
					if o.Code != 0 {
						o.Stage = "failed"
						return o, fmt.Errorf("takeoff: tx failed in block %d (code %d): %s", o.Height, o.Code, o.Log)
					}
					o.Stage = "committed"
					return o, nil
				}
			}
		}
		if time.Now().After(deadline) {
			o.Log = "accepted into the mempool, not in a block yet"
			return o, nil
		}
		select {
		case <-ctx.Done():
			return o, nil
		case <-time.After(time.Second):
		}
	}
}
