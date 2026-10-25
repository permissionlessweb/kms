package uiserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cosmos/kms/internal/takeoff"
)

func TestJailForCachesAndReevaluates(t *testing.T) {
	forgetJail()
	calls := 0
	until := time.Now().Add(150 * time.Millisecond)
	queryJail = func(_ context.Context, rpc, cons string) (takeoff.JailInfo, error) {
		calls++
		return takeoff.JailInfo{Jailed: true, JailedUntil: until, Missed: 9501, MaxMissed: 9500, Window: 10000, Operator: "terpvaloper1x"}, nil
	}
	t.Cleanup(func() { queryJail = takeoff.QueryJail; forgetJail() })
	j := jailFor("http://rpc", "E7353DEE98FFE8D7A3ABA2D8641A060879D1DD05")
	if j == nil || !j.Jailed || j.CanUnjail || !strings.Contains(j.Reason, "jailed until") {
		t.Fatalf("%+v", j)
	}
	time.Sleep(200 * time.Millisecond)
	j = jailFor("http://rpc", "E7353DEE98FFE8D7A3ABA2D8641A060879D1DD05")
	if !j.CanUnjail || calls != 1 {
		t.Fatal(j.Reason, calls)
	}
	if jailFor("", "x") != nil || jailFor("http://rpc", "") != nil {
		t.Fatal("no rpc or cons should be nil")
	}
}

func TestUIHasJailAndUnjail(t *testing.T) {
	for _, want := range []string{"function jailPill", "function jailBanner", `["unjail","Unjail"]`, "unjailWhy(v)", "Liveness warning", "id:S.tab,granter:g"} {
		if !strings.Contains(shellPage, want) {
			t.Fatalf("ui misses %s", want)
		}
	}
}
