package bluetooth

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestAdvertisementAndFirstMessageHideIdentity(t *testing.T) {
	static := bytes.Repeat([]byte{0x11}, 32)
	eph := bytes.Repeat([]byte{0x22}, 32)
	ad := bytes.Repeat([]byte{0x33}, AdvertisementLen)
	got, err := Advertisement(bytes.NewReader(ad))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, static) || bytes.Equal(got, static[:AdvertisementLen]) {
		t.Fatal("advertisement contains the static key")
	}
	init, msg1, err := BeginInitiator(static, eph)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg1) != 32 {
		t.Fatalf("message 1 length %d", len(msg1))
	}
	if bytes.Equal(msg1, init.hs.s.pub) || bytes.Contains(msg1, init.hs.s.pub) {
		t.Fatal("handshake message 1 contains the static key")
	}
}

func TestNoiseXXRoundTrip(t *testing.T) {
	iStatic := bytes.Repeat([]byte{0x01}, 32)
	rStatic := bytes.Repeat([]byte{0x02}, 32)
	iEph := bytes.Repeat([]byte{0x03}, 32)
	rEph := bytes.Repeat([]byte{0x04}, 32)

	init, msg1, err := BeginInitiator(iStatic, iEph)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := BeginResponder(rStatic, msg1)
	if err != nil {
		t.Fatal(err)
	}
	msg2, err := resp.Message2(rEph)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(msg2, resp.hs.s.pub) {
		t.Fatal("handshake message 2 contains the responder static key in the clear")
	}
	if err := init.ReadMessage2(msg2); err != nil {
		t.Fatal(err)
	}
	msg3, iSess, err := init.Message3()
	if err != nil {
		t.Fatal(err)
	}
	rSess, err := resp.ReadMessage3(msg3)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := iSess.Seal([]byte("vote"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := rSess.Open(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("vote")) {
		t.Fatalf("opened %q", pt)
	}
	back, err := rSess.Seal([]byte("sig"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := iSess.Open(back)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("sig")) {
		t.Fatalf("opened %q", got)
	}
}

func TestColdSignerRefusesRegression(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	dev := &softwareZafu{priv: priv, pub: pub}
	if _, err := dev.Sign(2, 0, 1, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := dev.Sign(2, 0, 1, []byte("b")); err == nil {
		t.Fatal("same height signed twice")
	}
	again, err := dev.Sign(2, 0, 1, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := dev.Sign(2, 0, 1, []byte("a"))
	if err != nil || !bytes.Equal(first, again) {
		t.Fatal("replay of the same bytes must return the same signature", err)
	}
	if _, err := dev.Sign(1, 0, 1, []byte("c")); err == nil {
		t.Fatal("lower height signed")
	}
	sig, err := dev.Sign(3, 0, 1, []byte("d"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte("d"), sig) {
		t.Fatal("bad signature")
	}
	ext := append([]byte{0x09, 0x11}, []byte{4, 0, 0, 0, 0, 0, 0, 0}...)
	vote := []byte{0x20, 0x08, 0x02}
	if _, err := dev.Sign(4, 0, 3, ext); err != nil {
		t.Fatal(err)
	}
	if _, err := dev.Sign(4, 0, 3, vote); err != nil {
		t.Fatal("vote after its extension", err)
	}
	if _, err := dev.Sign(4, 0, 3, []byte{0x20, 0x08, 0x03}); err == nil {
		t.Fatal("second vote at the same step")
	}
}
