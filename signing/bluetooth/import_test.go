package bluetooth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestImportIsSealedUnderAFreshHandshake(t *testing.T) {
	kmsStatic := bytes.Repeat([]byte{0x11}, 32)
	phoneStatic := bytes.Repeat([]byte{0x22}, 32)
	flight, msg1, err := BeginImport(kmsStatic)
	if err != nil {
		t.Fatal(err)
	}
	if msg1[0] != importMsg1 || len(msg1) != 33 {
		t.Fatalf("msg1 %d", len(msg1))
	}
	phone, err := BeginResponder(phoneStatic, msg1[1:])
	if err != nil {
		t.Fatal(err)
	}
	eph := bytes.Repeat([]byte{0x33}, 32)
	msg2, err := phone.Message2(eph)
	if err != nil {
		t.Fatal(err)
	}
	msg3, err := flight.AcceptReply(append([]byte{importMsg2}, msg2...))
	if err != nil {
		t.Fatal(err)
	}
	sess, err := phone.ReadMessage3(msg3[1:])
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	pub := secret[32:]
	box, err := flight.SealKey("test-1", secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(box, secret) || bytes.Contains(box, pub) {
		t.Fatal("sealed import still contains the key")
	}
	opened, err := sess.Open(box[1:])
	if err != nil {
		t.Fatal(err)
	}
	if int(opened[0]) != len("test-1") || string(opened[1:1+len("test-1")]) != "test-1" {
		t.Fatal("chain id")
	}
	got := opened[1+len("test-1"):]
	if !bytes.Equal(got, secret) {
		t.Fatal("opened secret does not match")
	}
	if !ed25519.PublicKey(pub).Equal(ed25519.PublicKey(got[32:])) {
		t.Fatal("public half")
	}
	if _, _, err := CometSecret("/Users/someone/.kms-terp/keys/priv_validator_key.json"); err == nil {
		t.Fatal("live key path was accepted")
	}
}
