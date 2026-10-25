package takeoff

import (
	"context"
	"encoding/hex"
	"strings"

	query "cosmossdk.io/api/cosmos/base/query/v1beta1"
	staking "cosmossdk.io/api/cosmos/staking/v1beta1"
	"google.golang.org/protobuf/proto"
)

// ValidatorByConsensus finds the on-chain validator (any status: bonded,
// unbonding or unbonded) whose consensus key hashes to consHex. found is
// false when no validator was ever created for that key.
func ValidatorByConsensus(ctx context.Context, rpc, consHex string) (ValidatorInfo, bool, error) {
	want := strings.ToUpper(consHex)
	var next []byte
	for page := 0; page < 50; page++ {
		raw, err := proto.Marshal(&staking.QueryValidatorsRequest{Pagination: &query.PageRequest{Key: next, Limit: 200}})
		if err != nil {
			return ValidatorInfo{}, false, err
		}
		v, code, err := abci(ctx, rpc, "/cosmos.staking.v1beta1.Query/Validators", raw)
		if err != nil {
			return ValidatorInfo{}, false, err
		}
		if code != 0 {
			return ValidatorInfo{}, false, nil
		}
		var resp staking.QueryValidatorsResponse
		if err := proto.Unmarshal(v, &resp); err != nil {
			return ValidatorInfo{}, false, err
		}
		for _, val := range resp.Validators {
			if a := consAddrOf(val.ConsensusPubkey); a != nil && strings.ToUpper(hex.EncodeToString(a)) == want {
				return QueryValidator(ctx, rpc, val.OperatorAddress)
			}
		}
		if resp.Pagination == nil || len(resp.Pagination.NextKey) == 0 {
			return ValidatorInfo{}, false, nil
		}
		next = resp.Pagination.NextKey
	}
	return ValidatorInfo{}, false, nil
}
