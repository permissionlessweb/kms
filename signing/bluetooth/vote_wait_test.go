package bluetooth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// waitUp starts the background handshake and waits for the session.
func waitUp(t *testing.T, l *Link) {
	t.Helper()
	_ = l.readySession()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if l.SessionUp() {
			return
		}
	}
	t.Fatal("session did not come up")
}

// With no phone the vote is refused at once instead of waiting on the 9s
// handshake, and the handshake keeps running in the background.
func TestVoteRefusedFastWhenPhoneDown(t *testing.T) {
	l := Open(t.TempDir())
	pub, _, _ := ed25519.GenerateKey(nil)
	k, _ := l.ForKey("k", pub)
	k.SetHRS(10, 0, 2)
	for i := 0; i < 3; i++ {
		start := time.Now()
		_, err := k.Sign(context.Background(), []byte("vote"))
		if !errors.Is(err, ErrPhoneNotReady) {
			t.Fatalf("want ErrPhoneNotReady, got %v", err)
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Fatalf("refusal took %v", d)
		}
	}
	if !l.handshaking.Load() {
		t.Fatal("no background handshake started")
	}
	if voteWait > 2*time.Second || voteWait >= handshakeWait {
		t.Fatalf("vote wait %v must stay short and below the handshake window", voteWait)
	}
}
