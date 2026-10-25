package takeoff

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	bank "cosmossdk.io/api/cosmos/bank/v1beta1"
	base "cosmossdk.io/api/cosmos/base/v1beta1"
	distr "cosmossdk.io/api/cosmos/distribution/v1beta1"
	staking "cosmossdk.io/api/cosmos/staking/v1beta1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeChain answers abci_query by path. It never accepts broadcast_tx.
func fakeChain(t *testing.T, answers map[string]proto.Message) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
			Params struct {
				Path string `json:"path"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		if req.Method != "abci_query" {
			t.Errorf("fake chain got %s; actions must not broadcast in tests", req.Method)
			http.Error(w, "no", 500)
			return
		}
		m, ok := answers[req.Params.Path]
		val, code := "", 1
		if ok {
			raw, _ := proto.Marshal(m)
			val, code = base64.StdEncoding.EncodeToString(raw), 0
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"response": map[string]any{"value": val, "code": code}}})
	}))
}

const testGranter = "terp1qyqszqgpqyqszqgpqyqszqgpqyqszqgpjh3rcj"

func testChain(t *testing.T, updated time.Time) *httptest.Server {
	val := valoper(testGranter)
	return fakeChain(t, map[string]proto.Message{
		"/cosmos.bank.v1beta1.Query/SpendableBalances":           &bank.QuerySpendableBalancesResponse{Balances: []*base.Coin{{Denom: "uterp", Amount: "5000000"}, {Denom: "uthiol", Amount: "900000"}}},
		"/cosmos.staking.v1beta1.Query/Delegation":               &staking.QueryDelegationResponse{DelegationResponse: &staking.DelegationResponse{Balance: &base.Coin{Denom: "uterp", Amount: "2000000"}}},
		"/cosmos.distribution.v1beta1.Query/DelegationRewards":   &distr.QueryDelegationRewardsResponse{Rewards: []*base.DecCoin{{Denom: "uterp", Amount: "1500000000000000000000"}}},
		"/cosmos.distribution.v1beta1.Query/ValidatorCommission": &distr.QueryValidatorCommissionResponse{Commission: &distr.ValidatorAccumulatedCommission{Commission: []*base.DecCoin{{Denom: "uterp", Amount: "250000000000000000000"}}}},
		"/cosmos.staking.v1beta1.Query/Validator": &staking.QueryValidatorResponse{Validator: &staking.Validator{
			OperatorAddress: val, Description: &staking.Description{Moniker: "zcinti"},
			Commission: &staking.Commission{CommissionRates: &staking.CommissionRates{Rate: "100000000000000000", MaxRate: "200000000000000000", MaxChangeRate: "10000000000000000"}, UpdateTime: timestamppb.New(updated)},
		}},
	})
}

func holdings(t *testing.T, updated time.Time) Holdings {
	srv := testChain(t, updated)
	defer srv.Close()
	h, err := QueryHoldings(context.Background(), srv.URL, testGranter, valoper(testGranter))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestQueryHoldingsReadsChainNumbers(t *testing.T) {
	h := holdings(t, time.Now().Add(-48*time.Hour))
	if h.Spendable != "5000000" || h.Thiol != "900000" || h.Delegated != "2000000" || h.Rewards != "1500" || h.Commission != "250" || !h.Found || h.Validator.Moniker != "zcinti" {
		t.Fatalf("%+v", h)
	}
}

func unwrap(t *testing.T, a *anypb.Any, m proto.Message) {
	t.Helper()
	if err := proto.Unmarshal(a.Value, m); err != nil {
		t.Fatal(err)
	}
}

func TestDelegateAndUndelegateValidateAmounts(t *testing.T) {
	h := holdings(t, time.Now().Add(-48*time.Hour))
	msgs, rv, errs := BuildAction(ActionRequest{Action: ActionDelegate, Granter: testGranter, Amount: "1.5"}, h, time.Now())
	if errs != nil || len(msgs) != 1 || msgs[0].TypeUrl != delegateURL {
		t.Fatal(errs)
	}
	var d staking.MsgDelegate
	unwrap(t, msgs[0], &d)
	if d.Amount.Amount != "1500000" || d.DelegatorAddress != testGranter || d.ValidatorAddress != valoper(testGranter) {
		t.Fatalf("%+v", &d)
	}
	if rv.Fingerprint == "" || len(rv.Messages) != 1 || !strings.Contains(string(rv.Messages[0].JSON), "1500000") {
		t.Fatalf("%+v", rv)
	}
	if rv.TotalThiol != "20000" || rv.Gas != 400000 || rv.FeePayer != testGranter || rv.Memo != DirectMemo {
		t.Fatalf("budget %+v", rv)
	}
	if _, _, errs := BuildAction(ActionRequest{Action: ActionDelegate, Granter: testGranter, Amount: "6"}, h, time.Now()); len(errs) != 1 || errs[0].Field != "amount" {
		t.Fatalf("over-spend accepted: %v", errs)
	}
	if _, _, errs := BuildAction(ActionRequest{Action: ActionDelegate, Granter: testGranter, Amount: "0"}, h, time.Now()); errs == nil {
		t.Fatal("zero accepted")
	}
	if _, _, errs := BuildAction(ActionRequest{Action: ActionUndelegate, Granter: testGranter, Amount: "2.000001"}, h, time.Now()); errs == nil {
		t.Fatal("undelegate above delegation accepted")
	}
	msgs, _, errs = BuildAction(ActionRequest{Action: ActionUndelegate, Granter: testGranter, Amount: "2"}, h, time.Now())
	if errs != nil || msgs[0].TypeUrl != undelegateURL {
		t.Fatal(errs)
	}
	if _, _, errs := BuildAction(ActionRequest{Action: ActionDelegate, Granter: "cosmos1abc", Amount: "1"}, h, time.Now()); errs[0].Field != "granter" {
		t.Fatal(errs)
	}
}

func TestClaimRewardsWithdrawsRewardsAndCommission(t *testing.T) {
	h := holdings(t, time.Now())
	msgs, rv, errs := BuildAction(ActionRequest{Action: ActionRewards, Granter: testGranter}, h, time.Now())
	if errs != nil || len(msgs) != 2 || msgs[0].TypeUrl != withdrawURL || msgs[1].TypeUrl != commissionURL {
		t.Fatal(errs, msgs)
	}
	if rv.ExecFee != "27500" || rv.Gas != 550000 {
		t.Fatal(rv.ExecFee, rv.Gas)
	}
	h.Rewards, h.Commission = "0", "0"
	if _, _, errs := BuildAction(ActionRequest{Action: ActionRewards, Granter: testGranter}, h, time.Now()); errs == nil {
		t.Fatal("empty claim accepted")
	}
}

func str(s string) *string { return &s }

func TestEditValidatorKeepsUnchangedFieldsAndChecksCommission(t *testing.T) {
	now := time.Now()
	h := holdings(t, now.Add(-48*time.Hour))
	msgs, rv, errs := BuildAction(ActionRequest{Action: ActionEdit, Granter: testGranter, Edit: EditFields{Website: str("https://terp.network"), CommissionPercent: "11"}}, h, now)
	if errs != nil {
		t.Fatal(errs)
	}
	var e staking.MsgEditValidator
	unwrap(t, msgs[0], &e)
	if e.Description.Moniker != doNotModify || e.Description.Website != "https://terp.network" || e.CommissionRate != "110000000000000000" {
		t.Fatalf("%+v", &e)
	}
	if len(rv.Lines) < 4 {
		t.Fatal(rv.Lines)
	}
	for _, c := range []struct{ pct, want string }{{"12", "max daily change"}, {"25", "max rate"}, {"abc", "percentage"}} {
		_, _, errs := BuildAction(ActionRequest{Action: ActionEdit, Granter: testGranter, Edit: EditFields{CommissionPercent: c.pct}}, h, now)
		if len(errs) == 0 || errs[0].Field != "commission_percent" || !strings.Contains(errs[0].Message, c.want) {
			t.Fatalf("%s: %v", c.pct, errs)
		}
	}
	recent := holdings(t, now.Add(-time.Hour))
	if _, _, errs := BuildAction(ActionRequest{Action: ActionEdit, Granter: testGranter, Edit: EditFields{CommissionPercent: "10.5"}}, recent, now); len(errs) == 0 || !strings.Contains(errs[0].Message, "wait until") {
		t.Fatalf("24h rule: %v", errs)
	}
	if _, _, errs := BuildAction(ActionRequest{Action: ActionEdit, Granter: testGranter}, h, now); len(errs) == 0 || errs[0].Message != "nothing changed" {
		t.Fatal(errs)
	}
	if _, _, errs := BuildAction(ActionRequest{Action: ActionEdit, Granter: testGranter, Edit: EditFields{Moniker: str(" ")}}, h, now); len(errs) == 0 {
		t.Fatal("blank moniker accepted")
	}
}

func TestDirectReviewNeedsOwnerThiol(t *testing.T) {
	h := holdings(t, time.Now())
	h.Thiol = "19999"
	if _, _, errs := BuildAction(ActionRequest{Action: ActionDelegate, Granter: testGranter, Amount: "1"}, h, time.Now()); len(errs) != 1 || !strings.Contains(errs[0].Message, "THIOL") {
		t.Fatal(errs)
	}
}

func TestPowerNote(t *testing.T) {
	if n := PowerNote("999000"); !strings.Contains(n, "below 1 TERP") || !strings.Contains(n, "0.001") {
		t.Fatal(n)
	}
	if PowerNote("1000000") != "" {
		t.Fatal("1 TERP has power 1")
	}
}

func TestPercentHelpers(t *testing.T) {
	if v, _ := PercentToDec("5.25"); v != "52500000000000000" || DecPercent(v) != "5.25%" {
		t.Fatal(v)
	}
	if _, err := PercentToDec("101"); err == nil {
		t.Fatal("over 100")
	}
}
