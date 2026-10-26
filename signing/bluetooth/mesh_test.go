package bluetooth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakePhone is one Zigner on its own scanner drop, with its own Noise static.
type fakePhone struct {
	seed  byte
	keys  map[[8]byte]*softwareZafu
	votes atomic.Int32
	hello atomic.Int32
	done  chan struct{}
}

func (p *fakePhone) noise(t *testing.T) []byte {
	pub, err := StaticPublic(bytes.Repeat([]byte{p.seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func (p *fakePhone) serve(dir string) {
	_ = os.MkdirAll(dir, 0o700)
	var hs *Responder
	var sess *Session
	var last uint64
	static := bytes.Repeat([]byte{p.seed}, 32)
	for {
		select {
		case <-p.done:
			return
		default:
		}
		raw, err := os.ReadFile(filepath.Join(dir, "req.json"))
		var req signReq
		if err != nil || json.Unmarshal(raw, &req) != nil || req.ID == 0 || req.ID == last {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		frame, _ := base64.StdEncoding.DecodeString(req.Frame)
		last = req.ID
		reply := []byte{wireRefuse}
		switch Admit(sess != nil, false, frame) {
		case "hello":
			p.hello.Add(1)
			hs, _ = BeginResponder(static, frame[1:])
			eph := make([]byte, 32)
			_, _ = rand.Read(eph)
			msg2, _ := hs.Message2(eph)
			reply = append([]byte{wireReply}, msg2...)
		case "finish":
			sess, _ = hs.ReadMessage3(frame[1:])
			reply = []byte{wireReady}
		case "vote":
			p.votes.Add(1)
			pt, err := sess.Open(frame[1:])
			if err != nil {
				break
			}
			id, h, r, s, msg, err := decodeSignFor(pt)
			dev := p.keys[id]
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

func newFakePhone(seed byte) (*fakePhone, ed25519.PublicKey) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return &fakePhone{seed: seed, keys: map[[8]byte]*softwareZafu{KeyID(pub): {priv: priv, pub: pub}}, done: make(chan struct{})}, pub
}

func meshHome(t *testing.T, codes ...string) string {
	home := t.TempDir()
	for _, c := range codes {
		if err := os.MkdirAll(filepath.Join(home, "links", c), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteChosen(home, codes); err != nil {
		t.Fatal(err)
	}
	return home
}

func waitMeshUp(t *testing.T, l *Link) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if l.SessionUp() {
			return
		}
	}
	t.Fatalf("link %s did not come up", l.Code())
}

// Two phones, one slot each, sign at the same time over their own links.
func TestMeshSignsTwoSlotsConcurrently(t *testing.T) {
	home := meshHome(t, "aaaa0001", "bbbb0002")
	pa, ka := newFakePhone(0x22)
	pb, kb := newFakePhone(0x33)
	defer close(pa.done)
	defer close(pb.done)
	go pa.serve(filepath.Join(home, "links", "aaaa0001"))
	go pb.serve(filepath.Join(home, "links", "bbbb0002"))
	if err := pinSlot(home, "zcinti", pa.noise(t)); err != nil {
		t.Fatal(err)
	}
	if err := pinSlot(home, "zcinti2", pb.noise(t)); err != nil {
		t.Fatal(err)
	}
	m := NewMesh(home)
	m.Start()
	defer m.Stop()
	waitMeshUp(t, m.Link("aaaa0001"))
	waitMeshUp(t, m.Link("bbbb0002"))
	a, _ := m.ForKey("zcinti", ka)
	b, _ := m.ForKey("zcinti2", kb)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for h := uint64(10); h < 20; h++ {
		wg.Add(2)
		go func(h uint64) {
			defer wg.Done()
			a.SetHRS(h, 0, 2)
			msg := []byte{byte(h), 'a'}
			sig, err := a.Sign(context.Background(), msg)
			if err == nil && !ed25519.Verify(ka, msg, sig) {
				err = errors.New("bad sig a")
			}
			if err != nil {
				errs[0] = err
			}
		}(h)
		go func(h uint64) {
			defer wg.Done()
			b.SetHRS(h, 0, 2)
			msg := []byte{byte(h), 'b'}
			sig, err := b.Sign(context.Background(), msg)
			if err == nil && !ed25519.Verify(kb, msg, sig) {
				err = errors.New("bad sig b")
			}
			if err != nil {
				errs[1] = err
			}
		}(h)
		wg.Wait()
	}
	if errs[0] != nil || errs[1] != nil {
		t.Fatal(errs)
	}
	if pa.votes.Load() != 10 || pb.votes.Load() != 10 {
		t.Fatalf("votes went to the wrong phone: a=%d b=%d", pa.votes.Load(), pb.votes.Load())
	}
}

// A phone with no pin never finishes a handshake and never sees a vote,
// even when it holds the key for a slot.
func TestMeshRefusesUnauthorizedPhone(t *testing.T) {
	home := meshHome(t, "aaaa0001", "cccc0003")
	pa, ka := newFakePhone(0x22)
	rogue, _ := newFakePhone(0x44)
	rogue.keys = pa.keys // even holding the right key
	defer close(rogue.done)
	go rogue.serve(filepath.Join(home, "links", "cccc0003"))
	if err := pinSlot(home, "zcinti", pa.noise(t)); err != nil {
		t.Fatal(err)
	}
	m := NewMesh(home)
	m.Start()
	defer m.Stop()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end) && PendingPubAt(home) == nil; time.Sleep(10 * time.Millisecond) {
	}
	if p := PendingPubAt(home); !bytes.Equal(p, rogue.noise(t)) {
		t.Fatal("unpinned phone was not left pending for the operator")
	}
	a, _ := m.ForKey("zcinti", ka)
	for h := uint64(1); h <= 5; h++ {
		a.SetHRS(h, 0, 2)
		if _, err := a.Sign(context.Background(), []byte{byte(h)}); !errors.Is(err, ErrPhoneNotReady) {
			t.Fatalf("vote without the pinned phone: %v", err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if m.Link("cccc0003").SessionUp() || rogue.votes.Load() != 0 {
		t.Fatalf("unauthorized phone got a session or a vote (votes=%d)", rogue.votes.Load())
	}
	// Redial to an unpinned phone is slow, not a hot loop.
	if n := rogue.hello.Load(); n > 2 {
		t.Fatalf("unpinned phone was dialed %d times", n)
	}
}

// One phone going away does not slow the other; it comes back on its own.
func TestMeshOneLinkDropDoesNotStallAnother(t *testing.T) {
	home := meshHome(t, "aaaa0001", "bbbb0002")
	pa, ka := newFakePhone(0x22)
	pb, kb := newFakePhone(0x33)
	defer close(pa.done)
	go pa.serve(filepath.Join(home, "links", "aaaa0001"))
	go pb.serve(filepath.Join(home, "links", "bbbb0002"))
	_ = pinSlot(home, "zcinti", pa.noise(t))
	_ = pinSlot(home, "zcinti2", pb.noise(t))
	m := NewMesh(home)
	m.Start()
	defer m.Stop()
	la, lb := m.Link("aaaa0001"), m.Link("bbbb0002")
	waitMeshUp(t, la)
	waitMeshUp(t, lb)
	a, _ := m.ForKey("zcinti", ka)
	b, _ := m.ForKey("zcinti2", kb)

	close(pb.done) // phone B walks out of range
	lb.Drop()
	for h := uint64(1); h <= 10; h++ {
		a.SetHRS(h, 0, 2)
		start := time.Now()
		if _, err := a.Sign(context.Background(), []byte{byte(h)}); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Fatalf("slot a waited %v on phone b", d)
		}
		b.SetHRS(h, 0, 2)
		start = time.Now()
		if _, err := b.Sign(context.Background(), []byte{byte(h)}); !errors.Is(err, ErrPhoneNotReady) {
			t.Fatalf("slot b: %v", err)
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Fatalf("slot b vote blocked %v", d)
		}
	}
	// Phone B comes back: its own redial loop brings the link up.
	pb2 := &fakePhone{seed: 0x33, keys: pb.keys, done: make(chan struct{})}
	defer close(pb2.done)
	go pb2.serve(filepath.Join(home, "links", "bbbb0002"))
	waitMeshUp(t, lb)
	b.SetHRS(50, 0, 2)
	if sig, err := b.Sign(context.Background(), []byte("b50")); err != nil || !ed25519.Verify(kb, []byte("b50"), sig) {
		t.Fatal(err)
	}
}

func TestChosenCodesCapAndDedup(t *testing.T) {
	home := t.TempDir()
	in := []string{"aaaa0001", "AAAA0001", "nothex!!", "bbbb0002", "c1", "00000003", "00000004", "00000005", "00000006", "00000007", "00000008"}
	_ = os.WriteFile(filepath.Join(home, "chosen"), []byte(string(bytes.Join(func() [][]byte {
		var o [][]byte
		for _, s := range in {
			o = append(o, []byte(s))
		}
		return o
	}(), []byte("\n")))), 0o600)
	got := ChosenCodes(home)
	if len(got) != MaxLinks || got[0] != "aaaa0001" || got[1] != "bbbb0002" {
		t.Fatal(got)
	}
}

func TestRegistrySlotsComeFromPins(t *testing.T) {
	home := t.TempDir()
	a := bytes.Repeat([]byte{1}, 32)
	b := bytes.Repeat([]byte{2}, 32)
	if err := registerDevice(home, b, "new phone", "bbbb0002"); err != nil {
		t.Fatal(err)
	}
	gp, _ := globalPinPath(home)
	_ = writeAtomic(gp, a)
	_ = pinSlot(home, "zcinti2", b)
	ds := devices(home)
	if len(ds) != 2 {
		t.Fatal(ds)
	}
	for _, d := range ds {
		switch d.ID {
		case DeviceID(a):
			if len(d.Slots) != 1 || d.Slots[0] != "*" {
				t.Fatal(d)
			}
		case DeviceID(b):
			if len(d.Slots) != 1 || d.Slots[0] != "zcinti2" || d.Label != "new phone" || len(d.NS) == 0 {
				t.Fatal(d)
			}
		}
	}
	// A registered device without a pin is a member, not authorized.
	c := bytes.Repeat([]byte{3}, 32)
	_ = registerDevice(home, c, "", "")
	if authorized(home, c) {
		t.Fatal("registry alone authorized a phone")
	}
}

func TestConfirmSecondPhoneDoesNotMoveGlobalPin(t *testing.T) {
	home := t.TempDir()
	a := bytes.Repeat([]byte{1}, 32)
	b := bytes.Repeat([]byte{2}, 32)
	_ = os.WriteFile(filepath.Join(home, "phone.pending"), a, 0o600)
	if _, err := confirmPhone(home); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(home, "phone.pending"), b, 0o600)
	if _, err := confirmPhone(home); err != nil {
		t.Fatal(err)
	}
	gp, _ := globalPinPath(home)
	if !bytes.Equal(read32(gp), a) {
		t.Fatal("second phone took the global pin")
	}
	if len(devices(home)) != 2 {
		t.Fatal("second phone not registered")
	}
}
