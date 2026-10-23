package bluetooth

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestVector(t *testing.T) {
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
	if err := init.ReadMessage2(msg2); err != nil {
		t.Fatal(err)
	}
	msg3, _, err := init.Message3()
	if err != nil {
		t.Fatal(err)
	}
	const (
		want1 = "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"
		want2 = "ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b0301d5221716fa2be9baa96416f4d480bd33b2af1f61bf699ff92b480b35f8603b07d5505ca312ace28713717b14f279"
		want3 = "e4993edffbf9facd0797dfc1c2b500eef7f017292f184e032d0a5fac1e3214013703e7bf6768fd4936de656c673fdf98"
	)
	if hex.EncodeToString(msg1) != want1 || hex.EncodeToString(msg2) != want2 || hex.EncodeToString(msg3) != want3 {
		t.Fatalf("handshake bytes drifted\n%s\n%s\n%s", hex.EncodeToString(msg1), hex.EncodeToString(msg2), hex.EncodeToString(msg3))
	}
}
