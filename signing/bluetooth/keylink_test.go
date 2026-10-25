package bluetooth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignForFrameRoundTrip(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	id := KeyID(pub)
	f := encodeSignFor(id, 12, 3, 2, []byte("doc"))
	gid, h, r, s, msg, err := decodeSignFor(f)
	if err != nil || gid != id || h != 12 || r != 3 || s != 2 || string(msg) != "doc" {
		t.Fatalf("%v %x %d %d %d %q", err, gid, h, r, s, msg)
	}
	if len(KeyIDHex(pub)) != 16 {
		t.Fatal("id hex")
	}
}

// serveMultiKeyPhone is a phone holding several keys with one HWM each.
func serveMultiKeyPhone(t *testing.T, dir string, keys map[[8]byte]*softwareZafu, done <-chan struct{}) {
	var hs *Responder
	var sess *Session
	var last uint64
	static := bytes.Repeat([]byte{0x22}, 32)
	for {
		select {
		case <-done:
			return
		default:
		}
		raw, err := os.ReadFile(filepath.Join(dir, "req.json"))
		var req signReq
		if err != nil || json.Unmarshal(raw, &req) != nil || req.ID == 0 || req.ID == last {
			time.Sleep(3 * time.Millisecond)
			continue
		}
		frame, _ := base64.StdEncoding.DecodeString(req.Frame)
		last = req.ID
		reply := []byte{wireRefuse}
		switch Admit(sess != nil, false, frame) {
		case "hello":
			hs, _ = BeginResponder(static, frame[1:])
			eph := make([]byte, 32)
			_, _ = rand.Read(eph)
			msg2, _ := hs.Message2(eph)
			reply = append([]byte{wireReply}, msg2...)
		case "finish":
			sess, _ = hs.ReadMessage3(frame[1:])
			reply = []byte{wireReady}
		case "vote":
			pt, err := sess.Open(frame[1:])
			if err != nil {
				break
			}
			id, h, r, s, msg, err := decodeSignFor(pt)
			dev := keys[id]
			if err != nil || dev == nil {
				break
			}
			sig, err := dev.Sign(h, r, s, msg)
			if err != nil {
				break
			}
			box, _ := sess.Seal(append([]byte{msgSig}, sig...))
			reply = append([]byte{wireSig}, box...)
		}
		body, _ := json.Marshal(signResp{ID: req.ID, Sig: base64.StdEncoding.EncodeToString(reply)})
		_ = os.WriteFile(filepath.Join(dir, "resp.json"), body, 0o600)
	}
}

func TestKeyLinksShareOnePhone(t *testing.T) {
	dir := t.TempDir()
	link := Open(dir)
	phoneNoise, _ := StaticPublic(bytes.Repeat([]byte{0x22}, 32))
	if err := os.WriteFile(filepath.Join(dir, "phone.peer"), phoneNoise, 0o600); err != nil {
		t.Fatal(err)
	}
	pa, ka, _ := ed25519.GenerateKey(nil)
	pb, kb, _ := ed25519.GenerateKey(nil)
	pc, _, _ := ed25519.GenerateKey(nil)
	keys := map[[8]byte]*softwareZafu{KeyID(pa): {priv: ka, pub: pa}, KeyID(pb): {priv: kb, pub: pb}}
	done := make(chan struct{})
	defer close(done)
	go serveMultiKeyPhone(t, dir, keys, done)
	a, _ := link.ForKey("a", pa)
	b, _ := link.ForKey("b", pb)
	c, _ := link.ForKey("c", pc)
	ctx := context.Background()
	waitUp(t, link)
	a.SetHRS(100, 0, 2)
	sa, err := a.Sign(ctx, []byte("a-100"))
	if err != nil || !ed25519.Verify(pa, []byte("a-100"), sa) {
		t.Fatal(err)
	}
	// Key b has its own floor: a lower height than a's is fine for b.
	b.SetHRS(5, 0, 2)
	sb, err := b.Sign(ctx, []byte("b-5"))
	if err != nil || !ed25519.Verify(pb, []byte("b-5"), sb) {
		t.Fatal(err)
	}
	// Each key still refuses its own lower height.
	a.SetHRS(99, 0, 2)
	if _, err := a.Sign(ctx, []byte("a-99")); err == nil {
		t.Fatal("key a signed below its floor")
	}
	if _, err := c.Sign(ctx, []byte("c")); err == nil {
		t.Fatal("phone signed for a key it does not hold")
	}
	if len(a.Recent()) != 1 || len(b.Recent()) != 1 || a.ID() == b.ID() {
		t.Fatal("records are not per key")
	}
	if _, err := link.ForKey("bad", []byte{1}); err == nil {
		t.Fatal("short key accepted")
	}
}
