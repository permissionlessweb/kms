package takeoff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	auth "cosmossdk.io/api/cosmos/auth/v1beta1"
	query "cosmossdk.io/api/cosmos/base/query/v1beta1"
	ed25519 "cosmossdk.io/api/cosmos/crypto/ed25519"
	secp "cosmossdk.io/api/cosmos/crypto/secp256k1"
	slashing "cosmossdk.io/api/cosmos/slashing/v1beta1"
	staking "cosmossdk.io/api/cosmos/staking/v1beta1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const unjailURL = "/cosmos.slashing.v1beta1.MsgUnjail"

// JailInfo is a validator's slashing state, read from staking (jailed),
// slashing signing-info (jailed_until, tombstoned, missed blocks) and the
// slashing params (window and the missed-block limit before jailing).
type JailInfo struct {
	Operator    string    `json:"operator"`
	ConsAddr    string    `json:"consensus_addr"` // terpvalcons1…
	Found       bool      `json:"found"`          // signing info exists
	Jailed      bool      `json:"jailed"`
	JailedUntil time.Time `json:"jailed_until"`
	Tombstoned  bool      `json:"tombstoned"`
	Missed      int64     `json:"missed_blocks"`
	Window      int64     `json:"signed_blocks_window"`
	MaxMissed   int64     `json:"max_missed"` // jailed once missed exceeds this
	// Warn is true when an unjailed validator has used half its allowance.
	Warn bool `json:"warn"`
	// CanUnjail and Reason say whether MsgUnjail would pass now.
	CanUnjail bool   `json:"can_unjail"`
	Reason    string `json:"reason"`
}

// Evaluate fills Warn, CanUnjail and Reason for time now.
func (j *JailInfo) Evaluate(now time.Time) {
	j.Warn = !j.Jailed && j.MaxMissed > 0 && j.Missed*2 >= j.MaxMissed
	j.CanUnjail, j.Reason = false, ""
	switch {
	case !j.Jailed:
		j.Reason = "validator is not jailed"
	case j.Tombstoned:
		j.Reason = "tombstoned for double signing: it can never be unjailed"
	case now.Before(j.JailedUntil):
		j.Reason = "jailed until " + j.JailedUntil.UTC().Format("2006-01-02 15:04 UTC")
	default:
		j.CanUnjail = true
	}
}

// ConsAddrFromHex turns a node /status validator address (hex) into terpvalcons1….
func ConsAddrFromHex(h string) (string, error) {
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != 20 {
		return "", fmt.Errorf("takeoff: bad consensus address %q", h)
	}
	return bech32Encode("terpvalcons", raw)
}

func consAddrOf(pk *anypb.Any) []byte {
	if pk == nil {
		return nil
	}
	var k ed25519.PubKey
	if proto.Unmarshal(pk.Value, &k) != nil || len(k.Key) != 32 {
		return nil
	}
	h := sha256.Sum256(k.Key)
	return h[:20]
}

// maxMissed is window - ceil(window*minSigned), minSigned scaled 1e18.
func maxMissed(window int64, minSigned []byte) int64 {
	m, ok := new(big.Int).SetString(strings.TrimSpace(string(minSigned)), 10)
	if !ok {
		return 0
	}
	need := new(big.Int).Mul(big.NewInt(window), m)
	scale, _ := new(big.Int).SetString(decScale, 10)
	q, r := new(big.Int).QuoRem(need, scale, new(big.Int))
	if r.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	return window - q.Int64()
}

// QueryJail reads the slashing state of the validator whose consensus
// address is consHex (20-byte hex, as in node /status).
func QueryJail(ctx context.Context, rpc, consHex string) (JailInfo, error) {
	var j JailInfo
	cons, err := ConsAddrFromHex(consHex)
	if err != nil {
		return j, err
	}
	j.ConsAddr = cons
	want, _ := hex.DecodeString(consHex)
	if raw, err := proto.Marshal(&slashing.QueryParamsRequest{}); err == nil {
		v, code, err := abci(ctx, rpc, "/cosmos.slashing.v1beta1.Query/Params", raw)
		if err != nil {
			return j, err
		}
		var resp slashing.QueryParamsResponse
		if code == 0 && proto.Unmarshal(v, &resp) == nil && resp.Params != nil {
			j.Window = resp.Params.SignedBlocksWindow
			j.MaxMissed = maxMissed(j.Window, resp.Params.MinSignedPerWindow)
		}
	}
	raw, _ := proto.Marshal(&slashing.QuerySigningInfoRequest{ConsAddress: cons})
	v, code, err := abci(ctx, rpc, "/cosmos.slashing.v1beta1.Query/SigningInfo", raw)
	if err != nil {
		return j, err
	}
	var si slashing.QuerySigningInfoResponse
	if code == 0 && proto.Unmarshal(v, &si) == nil && si.ValSigningInfo != nil {
		j.Found = true
		j.Tombstoned = si.ValSigningInfo.Tombstoned
		j.Missed = si.ValSigningInfo.MissedBlocksCounter
		if t := si.ValSigningInfo.JailedUntil; t != nil && t.Seconds > 0 {
			j.JailedUntil = t.AsTime()
		}
	}
	// staking holds the jailed flag; find the validator by consensus key.
	var key []byte
	for page := 0; page < 20; page++ {
		raw, _ := proto.Marshal(&staking.QueryValidatorsRequest{Pagination: &query.PageRequest{Key: key, Limit: 200}})
		v, code, err := abci(ctx, rpc, "/cosmos.staking.v1beta1.Query/Validators", raw)
		if err != nil {
			return j, err
		}
		var resp staking.QueryValidatorsResponse
		if code != 0 || proto.Unmarshal(v, &resp) != nil {
			break
		}
		for _, val := range resp.Validators {
			if a := consAddrOf(val.ConsensusPubkey); a != nil && string(a) == string(want) {
				j.Operator, j.Jailed = val.OperatorAddress, val.Jailed
				return j, nil
			}
		}
		if resp.Pagination == nil || len(resp.Pagination.NextKey) == 0 {
			break
		}
		key = resp.Pagination.NextKey
	}
	return j, nil
}

// AccountPubKey returns the secp256k1 pubkey the chain has stored for addr.
// It is empty until the account has signed a transaction.
func AccountPubKey(ctx context.Context, rpc, addr string) ([]byte, error) {
	data, _ := proto.Marshal(&auth.QueryAccountRequest{Address: addr})
	v, code, err := abci(ctx, rpc, "/cosmos.auth.v1beta1.Query/Account", data)
	if err != nil {
		return nil, err
	}
	if code == 22 || (code == 0 && len(v) == 0) {
		return nil, ErrAccountMissing
	}
	if code != 0 {
		return nil, fmt.Errorf("takeoff: account query code %d", code)
	}
	var qr auth.QueryAccountResponse
	if err := proto.Unmarshal(v, &qr); err != nil || qr.Account == nil {
		return nil, fmt.Errorf("takeoff: account response")
	}
	acct, err := baseAccountFromAny(qr.Account)
	if err != nil {
		return nil, err
	}
	if acct.PubKey == nil {
		return nil, nil
	}
	var pk secp.PubKey
	if acct.PubKey.TypeUrl != "/cosmos.crypto.secp256k1.PubKey" || proto.Unmarshal(acct.PubKey.Value, &pk) != nil {
		return nil, fmt.Errorf("takeoff: account key type %s is not secp256k1", acct.PubKey.TypeUrl)
	}
	return pk.Key, nil
}
