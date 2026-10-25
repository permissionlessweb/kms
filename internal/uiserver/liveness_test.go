package uiserver

import (
	"encoding/json"
	"testing"
	"time"
)

func TestLiveStatus(t *testing.T) {
	now := time.Now()
	if got := liveStatus(time.Time{}, now); got != "in set, not signing" {
		t.Fatal(got)
	}
	if got := liveStatus(now.Add(-10*time.Second), now); got != "signing" {
		t.Fatal(got)
	}
	if got := liveStatus(now.Add(-2*time.Minute), now); got != "in set, not signing" {
		t.Fatal(got)
	}
}

func TestSignedBy(t *testing.T) {
	raw := `{"result":{"block":{"last_commit":{"height":"24068440","signatures":[
	 {"block_id_flag":2,"validator_address":"AAAA"},
	 {"block_id_flag":1,"validator_address":"E7353DEE98FFE8D7A3ABA2D8641A060879D1DD05"}]}}}}`
	var b blockResp
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		t.Fatal(err)
	}
	if _, ok := signedBy(b, "e7353dee98ffe8d7a3aba2d8641a060879d1dd05"); ok {
		t.Fatal("absent (flag 1) must not count")
	}
	if h, ok := signedBy(b, "aaaa"); !ok || h != 24068440 {
		t.Fatal(h, ok)
	}
}
