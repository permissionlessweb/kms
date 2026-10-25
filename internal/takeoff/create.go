package takeoff

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	base "cosmossdk.io/api/cosmos/base/v1beta1"
	ed25519 "cosmossdk.io/api/cosmos/crypto/ed25519"
	staking "cosmossdk.io/api/cosmos/staking/v1beta1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// ActionCreate registers the slot's phone key as a new validator. The owner
// signs one MsgCreateValidator (it is both operator and self-delegator) and
// pays the fee: no session key, authz or feegrant.
const ActionCreate Action = "create"

// CreateFields is the full create-validator form.
type CreateFields struct {
	Moniker           string `json:"moniker"`
	Identity          string `json:"identity,omitempty"`
	Website           string `json:"website,omitempty"`
	SecurityContact   string `json:"security_contact,omitempty"`
	Details           string `json:"details,omitempty"`
	RatePercent       string `json:"rate_percent"`
	MaxRatePercent    string `json:"max_rate_percent"`
	MaxChangePercent  string `json:"max_change_percent"`
	MinSelfDelegation string `json:"min_self_delegation"` // uterp integer, chain units
	ConsPubHex        string `json:"consensus_pubkey_hex"`
}

func decLE(a, b string) bool { return mustInt(a).Cmp(mustInt(b)) <= 0 }

// buildCreate validates the form and returns the message plus review lines.
func buildCreate(req ActionRequest, h Holdings) (proto.Message, string, []ReviewLine, []FieldError) {
	var errs []FieldError
	c := req.Create
	if h.Found {
		return nil, "", nil, []FieldError{{"action", "this owner already operates validator " + valoper(req.Granter) + "; one account runs one validator"}}
	}
	pub, err := hex.DecodeString(strings.TrimSpace(c.ConsPubHex))
	if err != nil || len(pub) != 32 {
		errs = append(errs, FieldError{"consensus_pubkey_hex", "the slot's phone key is a 32-byte ed25519 key (64 hex)"})
	}
	if strings.TrimSpace(c.Moniker) == "" {
		errs = append(errs, FieldError{"moniker", "moniker is required"})
	}
	for _, l := range []struct {
		f, v string
		max  int
	}{{"moniker", c.Moniker, 70}, {"identity", c.Identity, 3000}, {"website", c.Website, 140}, {"security_contact", c.SecurityContact, 140}, {"details", c.Details, 280}} {
		if len(l.v) > l.max {
			errs = append(errs, FieldError{l.f, fmt.Sprintf("at most %d characters", l.max)})
		}
	}
	if c.Website != "" && !strings.HasPrefix(c.Website, "https://") && !strings.HasPrefix(c.Website, "http://") {
		errs = append(errs, FieldError{"website", "start with https://"})
	}
	rate, e1 := PercentToDec(c.RatePercent)
	maxRate, e2 := PercentToDec(c.MaxRatePercent)
	maxChange, e3 := PercentToDec(c.MaxChangePercent)
	for _, x := range []struct {
		f string
		e error
	}{{"rate_percent", e1}, {"max_rate_percent", e2}, {"max_change_percent", e3}} {
		if x.e != nil {
			errs = append(errs, FieldError{x.f, x.e.Error()})
		}
	}
	if e1 == nil && e2 == nil && !decLE(rate, maxRate) {
		errs = append(errs, FieldError{"rate_percent", "cannot exceed the max rate"})
	}
	if e2 == nil && e3 == nil && !decLE(maxChange, maxRate) {
		errs = append(errs, FieldError{"max_change_percent", "cannot exceed the max rate"})
	}
	minSelf := strings.TrimSpace(c.MinSelfDelegation)
	if minSelf == "" {
		minSelf = "1"
	}
	ms, ok := new(big.Int).SetString(minSelf, 10)
	if !ok || ms.Sign() <= 0 {
		errs = append(errs, FieldError{"min_self_delegation", "a whole number of uterp above zero"})
	}
	amt, err := ParseTERP(req.Amount)
	switch {
	case err != nil || amt == "0":
		errs = append(errs, FieldError{"amount", "enter a TERP amount above zero, up to 6 decimals"})
	case !CanCover(h.Spendable, amt):
		errs = append(errs, FieldError{"amount", "only " + FormatToken(h.Spendable) + " TERP is spendable"})
	case ok && ms.Sign() > 0 && !CanCover(amt, minSelf):
		errs = append(errs, FieldError{"amount", "self-delegation must be at least the min self delegation (" + minSelf + " uterp)"})
	}
	if len(errs) > 0 {
		return nil, "", nil, errs
	}
	pk, _ := anypb.New(&ed25519.PubKey{Key: pub})
	pk.TypeUrl = edURL
	msg := &staking.MsgCreateValidator{
		Description:       &staking.Description{Moniker: c.Moniker, Identity: c.Identity, Website: c.Website, SecurityContact: c.SecurityContact, Details: c.Details},
		Commission:        &staking.CommissionRates{Rate: rate, MaxRate: maxRate, MaxChangeRate: maxChange},
		MinSelfDelegation: minSelf,
		ValidatorAddress:  valoper(req.Granter),
		Pubkey:            pk,
		Value:             &base.Coin{Denom: stakeDenom, Amount: amt},
	}
	lines := []ReviewLine{
		{"Moniker", quoteOrEmpty(c.Moniker)},
		{"Consensus key", hex.EncodeToString(pub) + " (" + ConsensusAddr(pub) + ")"},
		{"Self-delegation", FormatToken(amt) + " TERP (" + amt + " uterp)"},
		{"Commission", DecPercent(rate) + " (max " + DecPercent(maxRate) + ", max change " + DecPercent(maxChange) + "/day)"},
		{"Min self delegation", minSelf + " uterp"},
	}
	for _, l := range []ReviewLine{{"Identity", c.Identity}, {"Website", c.Website}, {"Security contact", c.SecurityContact}, {"Details", c.Details}} {
		if l.Value != "" {
			lines = append(lines, ReviewLine{l.Label, quoteOrEmpty(l.Value)})
		}
	}
	if note := PowerNote(amt); note != "" {
		lines = append(lines, ReviewLine{"Voting power", note})
	}
	lines = append(lines, ReviewLine{"Commission is fixed", "max rate and max change can never be edited after creation"})
	return msg, "Create validator " + c.Moniker, lines, nil
}

// aminoCreate is cosmos-sdk/MsgCreateValidator as terpd signs it.
func aminoCreate(a *anypb.Any) (string, error) {
	var m staking.MsgCreateValidator
	if err := proto.Unmarshal(a.Value, &m); err != nil {
		return "", err
	}
	if m.Pubkey == nil || m.Pubkey.TypeUrl != edURL {
		return "", fmt.Errorf("takeoff: create-validator needs an ed25519 consensus key")
	}
	var pk ed25519.PubKey
	if err := proto.Unmarshal(m.Pubkey.Value, &pk); err != nil {
		return "", err
	}
	d := m.Description
	if d == nil {
		d = &staking.Description{}
	}
	c := m.Commission
	if c == nil {
		c = &staking.CommissionRates{}
	}
	var rates [3]string
	for i, w := range []string{c.MaxChangeRate, c.MaxRate, c.Rate} {
		v, err := decAmino(w)
		if err != nil {
			return "", err
		}
		rates[i] = v
	}
	desc := obj("details", strOrEmpty(d.Details), "identity", strOrEmpty(d.Identity), "moniker", strOrEmpty(d.Moniker), "security_contact", strOrEmpty(d.SecurityContact), "website", strOrEmpty(d.Website))
	pkJSON := `{"type":"tendermint/PubKeyEd25519","value":` + js(base64.StdEncoding.EncodeToString(pk.Key)) + `}`
	v := obj("commission", obj("max_change_rate", js(rates[0]), "max_rate", js(rates[1]), "rate", js(rates[2])),
		"delegator_address", strOrEmpty(m.DelegatorAddress), "description", desc,
		"min_self_delegation", strOrEmpty(m.MinSelfDelegation), "pubkey", pkJSON,
		"validator_address", strOrEmpty(m.ValidatorAddress), "value", coinJSON(m.Value))
	return `{"type":"cosmos-sdk/MsgCreateValidator","value":` + v + `}`, nil
}
