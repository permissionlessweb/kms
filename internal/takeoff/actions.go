package takeoff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	base "cosmossdk.io/api/cosmos/base/v1beta1"
	distr "cosmossdk.io/api/cosmos/distribution/v1beta1"
	slashing "cosmossdk.io/api/cosmos/slashing/v1beta1"
	staking "cosmossdk.io/api/cosmos/staking/v1beta1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Validator actions run through the same session as takeoff: the offline
// granter signs one amino MsgGrant batch (authz for the action's message
// types, revoke rights, and a THIOL feegrant); the in-memory ephemeral
// account then sends MsgExec{action msgs} and a final MsgExec{revokes}.
const (
	delegateURL   = "/cosmos.staking.v1beta1.MsgDelegate"
	undelegateURL = "/cosmos.staking.v1beta1.MsgUndelegate"
	editURL       = "/cosmos.staking.v1beta1.MsgEditValidator"
	withdrawURL   = "/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward"
	commissionURL = "/cosmos.distribution.v1beta1.MsgWithdrawValidatorCommission"
	doNotModify   = "[do-not-modify]"
	decScale      = "1000000000000000000"
)

// Action is a validator operation the console can run for the granter.
type Action string

const (
	ActionDelegate   Action = "delegate"
	ActionUndelegate Action = "undelegate"
	ActionRewards    Action = "rewards"
	ActionEdit       Action = "edit"
	ActionUnjail     Action = "unjail"
)

// Actions in tab order.
func Actions() []Action {
	return []Action{ActionDelegate, ActionUndelegate, ActionRewards, ActionEdit, ActionUnjail, ActionCreate}
}

// ParseAction validates an action name.
func ParseAction(s string) (Action, error) {
	for _, a := range Actions() {
		if string(a) == s {
			return a, nil
		}
	}
	return "", fmt.Errorf("takeoff: unknown action %q", s)
}

// MsgTypes are the message types the action executes.
func (a Action) MsgTypes() []string {
	switch a {
	case ActionDelegate:
		return []string{delegateURL}
	case ActionUndelegate:
		return []string{undelegateURL}
	case ActionRewards:
		return []string{withdrawURL, commissionURL}
	case ActionEdit:
		return []string{editURL}
	case ActionUnjail:
		return []string{unjailURL}
	case ActionCreate:
		return []string{createURL}
	}
	return nil
}

// EditFields are the MsgEditValidator inputs. A nil pointer means "leave as
// is" and is sent as [do-not-modify]. CommissionPercent "" leaves the rate.
type EditFields struct {
	Moniker           *string `json:"moniker,omitempty"`
	Identity          *string `json:"identity,omitempty"`
	Website           *string `json:"website,omitempty"`
	SecurityContact   *string `json:"security_contact,omitempty"`
	Details           *string `json:"details,omitempty"`
	CommissionPercent string  `json:"commission_percent,omitempty"`
}

// ActionRequest is the form the page posts.
type ActionRequest struct {
	Action    Action       `json:"action"`
	Granter   string       `json:"granter"`
	Validator string       `json:"validator,omitempty"` // valoper; defaults to the granter's own
	Amount    string       `json:"amount,omitempty"`    // TERP, six decimals
	Edit      EditFields   `json:"edit,omitempty"`
	Create    CreateFields `json:"create,omitempty"`
}

// FieldError is inline validation for one form field.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e FieldError) Error() string { return e.Field + ": " + e.Message }

// ValidatorInfo is what the forms show next to their inputs.
type ValidatorInfo struct {
	Operator          string    `json:"operator"`
	Moniker           string    `json:"moniker"`
	Identity          string    `json:"identity"`
	Website           string    `json:"website"`
	SecurityContact   string    `json:"security_contact"`
	Details           string    `json:"details"`
	Jailed            bool      `json:"jailed"`
	Status            string    `json:"status"`
	Tokens            string    `json:"tokens"`          // uterp bonded to the validator
	ConsHex           string    `json:"consensus_hex"`   // sha256(ed25519)[:20]
	Rate              string    `json:"rate"`            // scaled 1e18
	MaxRate           string    `json:"max_rate"`        // scaled 1e18
	MaxChangeRate     string    `json:"max_change_rate"` // scaled 1e18
	CommissionUpdated time.Time `json:"commission_updated"`
}

// Holdings are the granter's numbers for one validator, micro units.
type Holdings struct {
	Spendable  string        `json:"spendable_uterp"`
	Thiol      string        `json:"spendable_uthiol"`
	Delegated  string        `json:"delegated_uterp"`
	Rewards    string        `json:"rewards_uterp"`
	Commission string        `json:"commission_uterp"`
	Validator  ValidatorInfo `json:"validator"`
	Found      bool          `json:"validator_found"`
	Jail       *JailInfo     `json:"jail,omitempty"`
}

// QueryHoldings reads balances, delegation, rewards, commission and the
// validator record. Missing records read as zero, not errors.
func QueryHoldings(ctx context.Context, rpc, granter, val string) (Holdings, error) {
	var h Holdings
	var err error
	if h.Spendable, err = Spendable(ctx, rpc, granter, stakeDenom); err != nil {
		return h, err
	}
	if h.Thiol, err = Spendable(ctx, rpc, granter, feeDenom); err != nil {
		return h, err
	}
	h.Delegated, h.Rewards, h.Commission = "0", "0", "0"
	if raw, err := proto.Marshal(&staking.QueryDelegationRequest{DelegatorAddr: granter, ValidatorAddr: val}); err == nil {
		if v, code, err := abci(ctx, rpc, "/cosmos.staking.v1beta1.Query/Delegation", raw); err == nil && code == 0 && len(v) > 0 {
			var resp staking.QueryDelegationResponse
			if proto.Unmarshal(v, &resp) == nil && resp.DelegationResponse != nil && resp.DelegationResponse.Balance != nil {
				h.Delegated = resp.DelegationResponse.Balance.Amount
			}
		}
	}
	if raw, err := proto.Marshal(&distr.QueryDelegationRewardsRequest{DelegatorAddress: granter, ValidatorAddress: val}); err == nil {
		if v, code, err := abci(ctx, rpc, "/cosmos.distribution.v1beta1.Query/DelegationRewards", raw); err == nil && code == 0 && len(v) > 0 {
			var resp distr.QueryDelegationRewardsResponse
			if proto.Unmarshal(v, &resp) == nil {
				h.Rewards = decCoins(resp.Rewards, stakeDenom)
			}
		}
	}
	if raw, err := proto.Marshal(&distr.QueryValidatorCommissionRequest{ValidatorAddress: val}); err == nil {
		if v, code, err := abci(ctx, rpc, "/cosmos.distribution.v1beta1.Query/ValidatorCommission", raw); err == nil && code == 0 && len(v) > 0 {
			var resp distr.QueryValidatorCommissionResponse
			if proto.Unmarshal(v, &resp) == nil && resp.Commission != nil {
				h.Commission = decCoins(resp.Commission.Commission, stakeDenom)
			}
		}
	}
	info, found, err := QueryValidator(ctx, rpc, val)
	if err != nil {
		return h, err
	}
	h.Validator, h.Found = info, found
	if found && info.ConsHex != "" {
		if j, err := QueryJail(ctx, rpc, info.ConsHex); err == nil {
			j.Jailed = j.Jailed || info.Jailed
			j.Evaluate(time.Now())
			h.Jail = &j
		}
	}
	return h, nil
}

// QueryValidator reads one validator record.
func QueryValidator(ctx context.Context, rpc, val string) (ValidatorInfo, bool, error) {
	raw, err := proto.Marshal(&staking.QueryValidatorRequest{ValidatorAddr: val})
	if err != nil {
		return ValidatorInfo{}, false, err
	}
	v, code, err := abci(ctx, rpc, "/cosmos.staking.v1beta1.Query/Validator", raw)
	if err != nil {
		return ValidatorInfo{}, false, err
	}
	if code != 0 || len(v) == 0 {
		return ValidatorInfo{Operator: val}, false, nil
	}
	var resp staking.QueryValidatorResponse
	if err := proto.Unmarshal(v, &resp); err != nil || resp.Validator == nil {
		return ValidatorInfo{Operator: val}, false, err
	}
	out := ValidatorInfo{Operator: val, Jailed: resp.Validator.Jailed, Status: resp.Validator.Status.String(), Tokens: resp.Validator.Tokens}
	if a := consAddrOf(resp.Validator.ConsensusPubkey); a != nil {
		out.ConsHex = strings.ToUpper(hex.EncodeToString(a))
	}
	if d := resp.Validator.Description; d != nil {
		out.Moniker, out.Identity, out.Website, out.SecurityContact, out.Details = d.Moniker, d.Identity, d.Website, d.SecurityContact, d.Details
	}
	if c := resp.Validator.Commission; c != nil {
		if r := c.CommissionRates; r != nil {
			out.Rate, out.MaxRate, out.MaxChangeRate = r.Rate, r.MaxRate, r.MaxChangeRate
		}
		if c.UpdateTime != nil {
			out.CommissionUpdated = c.UpdateTime.AsTime()
		}
	}
	return out, true, nil
}

// decCoins returns the whole micro amount of denom in a DecCoin list (scaled 1e18).
func decCoins(coins []*base.DecCoin, denom string) string {
	for _, c := range coins {
		if c.GetDenom() == denom {
			n, ok := new(big.Int).SetString(c.GetAmount(), 10)
			if !ok {
				return "0"
			}
			scale, _ := new(big.Int).SetString(decScale, 10)
			return n.Quo(n, scale).String()
		}
	}
	return "0"
}

// PercentToDec turns "5" or "5.25" (percent) into a 1e18-scaled LegacyDec.
func PercentToDec(text string) (string, error) {
	text = strings.TrimSuffix(strings.TrimSpace(text), "%")
	r, ok := new(big.Rat).SetString(text)
	if !ok || r.Sign() < 0 {
		return "", fmt.Errorf("enter a percentage like 5 or 5.25")
	}
	scale, _ := new(big.Int).SetString("10000000000000000", 10) // 1e18 / 100
	r.Mul(r, new(big.Rat).SetInt(scale))
	if !r.IsInt() {
		return "", fmt.Errorf("at most 16 decimal places")
	}
	if r.Num().Cmp(mustInt(decScale)) > 0 {
		return "", fmt.Errorf("commission cannot exceed 100%%")
	}
	return r.Num().String(), nil
}

// DecPercent renders a 1e18-scaled LegacyDec as a percent.
func DecPercent(dec string) string {
	n, ok := new(big.Int).SetString(dec, 10)
	if !ok {
		return ""
	}
	r := new(big.Rat).SetFrac(n, mustInt("10000000000000000"))
	s := r.FloatString(4)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	return s + "%"
}

func mustInt(s string) *big.Int { n, _ := new(big.Int).SetString(s, 10); return n }

// CheckCommission applies the staking module's rules: rate <= max_rate,
// |rate - current| <= max_change_rate, and at most one change per 24h.
func CheckCommission(info ValidatorInfo, newRate string, now time.Time) error {
	nr, cur, max, chg := mustInt(newRate), mustInt(info.Rate), mustInt(info.MaxRate), mustInt(info.MaxChangeRate)
	if nr == nil || cur == nil || max == nil || chg == nil {
		return fmt.Errorf("validator commission is not readable")
	}
	if nr.Cmp(max) > 0 {
		return fmt.Errorf("above the max rate %s", DecPercent(info.MaxRate))
	}
	diff := new(big.Int).Sub(nr, cur)
	if diff.Abs(diff).Cmp(chg) > 0 {
		return fmt.Errorf("changes by more than the max daily change %s (current %s)", DecPercent(info.MaxChangeRate), DecPercent(info.Rate))
	}
	if nr.Cmp(cur) != 0 && !info.CommissionUpdated.IsZero() && now.Sub(info.CommissionUpdated) < 24*time.Hour {
		return fmt.Errorf("commission changed %s ago; wait until %s", now.Sub(info.CommissionUpdated).Round(time.Minute), info.CommissionUpdated.Add(24*time.Hour).UTC().Format("2006-01-02 15:04 UTC"))
	}
	return nil
}

// ReviewLine is one human row on the review step.
type ReviewLine struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// ReviewMsg is one message exactly as it will be signed (proto JSON).
type ReviewMsg struct {
	TypeURL string          `json:"type_url"`
	JSON    json.RawMessage `json:"json"`
}

// Review is everything the operator confirms before anything is signed.
type Review struct {
	Action      Action       `json:"action"`
	Title       string       `json:"title"`
	Lines       []ReviewLine `json:"lines"`
	Messages    []ReviewMsg  `json:"messages"`
	Granter     string       `json:"granter"`
	TotalThiol  string       `json:"total_uthiol"`
	ExecFee     string       `json:"exec_fee_uthiol"`
	Gas         uint64       `json:"gas"`
	FeePayer    string       `json:"fee_payer"`
	Memo        string       `json:"memo"`
	Fingerprint string       `json:"fingerprint"`
}

// BuildAction validates the request against the chain numbers and returns
// the action messages the owner signs directly, and the review.
func BuildAction(req ActionRequest, h Holdings, now time.Time) ([]*anypb.Any, Review, []FieldError) {
	var errs []FieldError
	if !ValidAccount(req.Granter) {
		errs = append(errs, FieldError{"granter", "enter the terp1… account that owns the validator"})
		return nil, Review{}, errs
	}
	val := req.Validator
	if val == "" {
		val = valoper(req.Granter)
	}
	if hrp, _, err := bech32Decode(val); err != nil || hrp != "terpvaloper" {
		errs = append(errs, FieldError{"validator", "enter a terpvaloper1… address"})
		return nil, Review{}, errs
	}
	rv := Review{Action: req.Action, Granter: req.Granter}
	var msgs []proto.Message
	var urls []string
	switch req.Action {
	case ActionDelegate, ActionUndelegate:
		amt, err := ParseTERP(req.Amount)
		if err != nil || amt == "0" {
			errs = append(errs, FieldError{"amount", "enter a TERP amount above zero, up to 6 decimals"})
			break
		}
		if req.Action == ActionDelegate {
			if !CanCover(h.Spendable, amt) {
				errs = append(errs, FieldError{"amount", "only " + FormatToken(h.Spendable) + " TERP is spendable"})
				break
			}
			if !h.Found {
				errs = append(errs, FieldError{"validator", "this validator is not on chain yet; run takeoff first"})
				break
			}
			msgs, urls = append(msgs, &staking.MsgDelegate{DelegatorAddress: req.Granter, ValidatorAddress: val, Amount: &base.Coin{Denom: stakeDenom, Amount: amt}}), append(urls, delegateURL)
			rv.Title = "Delegate " + FormatToken(amt) + " TERP"
		} else {
			if !CanCover(h.Delegated, amt) {
				errs = append(errs, FieldError{"amount", "only " + FormatToken(h.Delegated) + " TERP is delegated"})
				break
			}
			msgs, urls = append(msgs, &staking.MsgUndelegate{DelegatorAddress: req.Granter, ValidatorAddress: val, Amount: &base.Coin{Denom: stakeDenom, Amount: amt}}), append(urls, undelegateURL)
			rv.Title = "Undelegate " + FormatToken(amt) + " TERP"
			rv.Lines = append(rv.Lines, ReviewLine{"Unbonding", "funds stay locked for the chain's unbonding period"})
		}
		rv.Lines = append([]ReviewLine{{"Amount", FormatToken(amt) + " TERP (" + amt + " uterp)"}}, rv.Lines...)
	case ActionRewards:
		if h.Rewards == "0" && h.Commission == "0" {
			errs = append(errs, FieldError{"action", "nothing to claim yet"})
			break
		}
		msgs, urls = append(msgs, &distr.MsgWithdrawDelegatorReward{DelegatorAddress: req.Granter, ValidatorAddress: val}), append(urls, withdrawURL)
		rv.Lines = append(rv.Lines, ReviewLine{"Rewards", "≈ " + FormatToken(h.Rewards) + " TERP"})
		if h.Commission != "0" && valoper(req.Granter) == val {
			msgs, urls = append(msgs, &distr.MsgWithdrawValidatorCommission{ValidatorAddress: val}), append(urls, commissionURL)
			rv.Lines = append(rv.Lines, ReviewLine{"Commission", "≈ " + FormatToken(h.Commission) + " TERP"})
		}
		rv.Title = "Claim rewards"
	case ActionEdit:
		if !h.Found {
			errs = append(errs, FieldError{"validator", "this validator is not on chain yet"})
			break
		}
		if valoper(req.Granter) != val {
			errs = append(errs, FieldError{"validator", "only the operator account can edit its validator"})
			break
		}
		e := req.Edit
		d := &staking.Description{Moniker: keep(e.Moniker), Identity: keep(e.Identity), Website: keep(e.Website), SecurityContact: keep(e.SecurityContact), Details: keep(e.Details)}
		lim := []struct {
			f    string
			v    *string
			max  int
			name string
		}{{"moniker", e.Moniker, 70, "Moniker"}, {"identity", e.Identity, 3000, "Identity"}, {"website", e.Website, 140, "Website"}, {"security_contact", e.SecurityContact, 140, "Security contact"}, {"details", e.Details, 280, "Details"}}
		changed := 0
		for _, l := range lim {
			if l.v == nil {
				continue
			}
			if len(*l.v) > l.max {
				errs = append(errs, FieldError{l.f, fmt.Sprintf("at most %d characters", l.max)})
				continue
			}
			changed++
			rv.Lines = append(rv.Lines, ReviewLine{l.name, quoteOrEmpty(*l.v)})
		}
		if e.Moniker != nil && strings.TrimSpace(*e.Moniker) == "" {
			errs = append(errs, FieldError{"moniker", "moniker cannot be empty"})
		}
		if e.Website != nil && *e.Website != "" && !strings.HasPrefix(*e.Website, "https://") && !strings.HasPrefix(*e.Website, "http://") {
			errs = append(errs, FieldError{"website", "start with https://"})
		}
		msg := &staking.MsgEditValidator{Description: d, ValidatorAddress: val}
		if e.CommissionPercent != "" {
			rate, err := PercentToDec(e.CommissionPercent)
			if err != nil {
				errs = append(errs, FieldError{"commission_percent", err.Error()})
			} else if rate != h.Validator.Rate {
				if err := CheckCommission(h.Validator, rate, now); err != nil {
					errs = append(errs, FieldError{"commission_percent", err.Error()})
				} else {
					msg.CommissionRate = rate
					changed++
					rv.Lines = append(rv.Lines, ReviewLine{"Commission", DecPercent(h.Validator.Rate) + " → " + DecPercent(rate)})
				}
			}
		}
		if changed == 0 && len(errs) == 0 {
			errs = append(errs, FieldError{"action", "nothing changed"})
		}
		msgs, urls = append(msgs, msg), append(urls, editURL)
		rv.Title = "Update validator info"
	case ActionUnjail:
		if !h.Found {
			errs = append(errs, FieldError{"validator", "this validator is not on chain"})
			break
		}
		if valoper(req.Granter) != val {
			errs = append(errs, FieldError{"validator", "only the operator account can unjail its validator"})
			break
		}
		j := h.Jail
		if j == nil {
			j = &JailInfo{Jailed: h.Validator.Jailed}
		}
		j.Evaluate(now)
		if !j.CanUnjail {
			errs = append(errs, FieldError{"action", "cannot unjail: " + j.Reason})
			break
		}
		msgs, urls = append(msgs, &slashing.MsgUnjail{ValidatorAddr: val}), append(urls, unjailURL)
		rv.Title = "Unjail validator"
		if !j.JailedUntil.IsZero() {
			rv.Lines = append(rv.Lines, ReviewLine{"Jailed until", j.JailedUntil.UTC().Format("2006-01-02 15:04:05 UTC") + " (passed)"})
		}
		rv.Lines = append(rv.Lines, ReviewLine{"Missed blocks", fmt.Sprintf("%d of %d allowed in a %d-block window", j.Missed, j.MaxMissed, j.Window)})
		rv.Lines = append(rv.Lines, ReviewLine{"Before you submit", "make sure the node is signing again, or it will be jailed again"})
	case ActionCreate:
		if val != valoper(req.Granter) {
			errs = append(errs, FieldError{"validator", "the owner account becomes the operator; leave the validator empty"})
			break
		}
		m, title, lines, ferrs := buildCreate(req, h)
		if ferrs != nil {
			errs = append(errs, ferrs...)
			break
		}
		msgs, urls = append(msgs, m), append(urls, createURL)
		rv.Title, rv.Lines = title, lines
	default:
		errs = append(errs, FieldError{"action", "unknown action"})
	}
	if len(errs) > 0 {
		return nil, Review{}, errs
	}
	rv.Lines = append([]ReviewLine{{"Validator", val}, {"Signed by", req.Granter + " (owner, on the phone)"}}, rv.Lines...)
	out := make([]*anypb.Any, 0, len(msgs))
	for i, m := range msgs {
		raw, err := proto.Marshal(m)
		if err != nil {
			return nil, Review{}, []FieldError{{"action", err.Error()}}
		}
		out = append(out, &anypb.Any{TypeUrl: urls[i], Value: raw})
		js, _ := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: false}.Marshal(m)
		rv.Messages = append(rv.Messages, ReviewMsg{TypeURL: urls[i], JSON: js})
	}
	h256 := sha256.New()
	for _, a := range out {
		h256.Write([]byte(a.TypeUrl))
		h256.Write(a.Value)
	}
	rv.Fingerprint = hex.EncodeToString(h256.Sum(nil)[:4])
	// One tx, signed by the owner on the phone, owner pays the THIOL fee.
	gas, fee := DirectFee(len(out))
	rv.Gas, rv.ExecFee, rv.TotalThiol, rv.FeePayer, rv.Memo = gas, fee, fee, req.Granter, DirectMemo
	if h.Thiol != "" && !CanCover(h.Thiol, fee) {
		return nil, Review{}, []FieldError{{"action", "the owner needs " + FormatToken(fee) + " THIOL for the fee and has " + FormatToken(h.Thiol)}}
	}
	return out, rv, nil
}

// PowerNote explains why a bonded-looking validator has no voting power:
// consensus power is tokens / 1e6, so under 1 TERP it is 0 and the chain
// keeps it out of the active set.
func PowerNote(tokens string) string {
	n, ok := new(big.Int).SetString(tokens, 10)
	if !ok {
		return ""
	}
	if n.Cmp(big.NewInt(1000000)) < 0 {
		short := new(big.Int).Sub(big.NewInt(1000000), n)
		return fmt.Sprintf("stake %s TERP is below 1 TERP, so consensus power is 0 and it cannot enter the active set; delegate at least %s TERP more", FormatToken(n.String()), FormatToken(short.String()))
	}
	return ""
}

func keep(v *string) string {
	if v == nil {
		return doNotModify
	}
	return *v
}

func quoteOrEmpty(s string) string {
	if s == "" {
		return "(cleared)"
	}
	return "\u201c" + s + "\u201d"
}

func prepareFrom(granter, grantee, chainID string, acct, seq uint64, missing []string, fee bool, now time.Time) ([]byte, Prepared, error) {
	if len(missing) == 0 && !fee {
		return nil, Prepared{Kind: "ready", Granter: granter, Grantee: grantee, Account: acct, Sequence: seq}, nil
	}
	now = now.UTC().Truncate(time.Second)
	if missing == nil {
		missing = []string{}
	}
	png, doc, err := grantQR(granter, grantee, chainID, acct, seq, now, missing, fee)
	if err != nil {
		return nil, Prepared{}, err
	}
	msgs, err := grantsFor(granter, grantee, feeDenom, now, missing, fee)
	if err != nil {
		return nil, Prepared{}, err
	}
	kind := "grant"
	if !fee {
		kind = "omit-fee"
	}
	return png, Prepared{Amino: doc, Msgs: msgs, PNG: png, Kind: kind, Granter: granter, Grantee: grantee, Account: acct, Sequence: seq}, nil
}

// ValoperOf is the operator address of a terp account.
func ValoperOf(account string) string { return valoper(account) }
