package bluetooth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A slow phone answers the request it was handed. A short window gives up
// and its reply lands under an abandoned id; the handshake window must
// outlast the scanner's in-flight hold so the same reply is accepted.
func TestHandshakeOutlastsSlowReply(t *testing.T) {
	if handshakeWait <= 8*time.Second || exchangeWait >= handshakeWait {
		t.Fatalf("handshake window %v must exceed the scanner's 8s hold", handshakeWait)
	}
	dir := t.TempDir()
	l := Open(dir)
	answer := func(delay time.Duration) {
		go func() {
			time.Sleep(delay)
			raw, err := os.ReadFile(filepath.Join(dir, "req.json"))
			if err != nil {
				return
			}
			var req signReq
			_ = json.Unmarshal(raw, &req)
			b, _ := json.Marshal(signResp{ID: req.ID, Sig: base64.StdEncoding.EncodeToString([]byte{7})})
			_ = os.WriteFile(filepath.Join(dir, "resp.json"), b, 0o600)
		}()
	}
	answer(200 * time.Millisecond)
	if _, err := l.exchangeWithin(context.Background(), []byte{1}, 50*time.Millisecond); err == nil {
		t.Fatal("short window should time out")
	}
	answer(200 * time.Millisecond)
	got, err := l.exchangeWithin(context.Background(), []byte{2}, time.Second)
	if err != nil || len(got) != 1 || got[0] != 7 {
		t.Fatalf("long window: %v %v", got, err)
	}
}
