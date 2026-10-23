package bluetooth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLinkWaitsForPhone(t *testing.T) {
	dir := t.TempDir()
	link := Open(dir)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pub.hex"), []byte(hex.EncodeToString(pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	phoneNoise, err := StaticPublic(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "phone.peer"), phoneNoise, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	defer close(done)
	go serveSealedPhone(t, dir, priv, pub, done)
	link.SetHRS(9, 1, 3)
	sig, err := link.Sign(context.Background(), []byte("block-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte("block-bytes"), sig) {
		t.Fatal("signature did not verify")
	}
	got := link.Recent()
	if len(got) != 1 || got[0].Height != 9 || got[0].Step != 3 {
		t.Fatalf("log %+v", got)
	}
	again, err := link.Sign(context.Background(), []byte("block-bytes"))
	if err != nil || !bytes.Equal(again, sig) {
		t.Fatal(err)
	}
	link.SetHRS(9, 1, 3)
	if _, err := link.Sign(context.Background(), []byte("other-bytes")); err == nil {
		t.Fatal("same height signed a different message")
	}
	link.SetHRS(8, 1, 3)
	if _, err := link.Sign(context.Background(), []byte("older")); err == nil {
		t.Fatal("lower height was signed")
	}
}

func serveSealedPhone(t *testing.T, dir string, priv ed25519.PrivateKey, pub ed25519.PublicKey, done <-chan struct{}) {
	t.Helper()
	dev := &softwareZafu{priv: priv, pub: pub}
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
		if err != nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		var req signReq
		if json.Unmarshal(raw, &req) != nil || req.ID == 0 || req.ID == last {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		frame, err := base64.StdEncoding.DecodeString(req.Frame)
		if err != nil || len(frame) == 0 {
			t.Errorf("frame: %v", err)
			return
		}
		last = req.ID
		var reply []byte
		switch Admit(sess != nil, false, frame) {
		case "hello":
			hs, err = BeginResponder(static, frame[1:])
			if err != nil {
				t.Errorf("hello: %v", err)
				return
			}
			eph := make([]byte, 32)
			if _, err = rand.Read(eph); err != nil {
				t.Errorf("eph: %v", err)
				return
			}
			msg2, err := hs.Message2(eph)
			if err != nil {
				t.Errorf("msg2: %v", err)
				return
			}
			reply = append([]byte{wireReply}, msg2...)
		case "finish":
			sess, err = hs.ReadMessage3(frame[1:])
			if err != nil {
				t.Errorf("finish: %v", err)
				return
			}
			reply = []byte{wireReady}
		case "vote":
			pt, err := sess.Open(frame[1:])
			if err != nil {
				t.Errorf("open vote: %v", err)
				return
			}
			h, r, s, msg, err := decodeSign(pt)
			if err != nil {
				t.Errorf("decode: %v", err)
				return
			}
			sig, err := dev.Sign(h, r, s, msg)
			if err != nil {
				reply = []byte{wireRefuse}
				break
			}
			box, err := sess.Seal(append([]byte{msgSig}, sig...))
			if err != nil {
				t.Errorf("seal: %v", err)
				return
			}
			reply = append([]byte{wireSig}, box...)
		default:
			reply = []byte{wireRefuse}
		}
		body, _ := json.Marshal(signResp{ID: req.ID, Sig: base64.StdEncoding.EncodeToString(reply)})
		_ = os.WriteFile(filepath.Join(dir, "resp.json"), body, 0o600)
	}
}
