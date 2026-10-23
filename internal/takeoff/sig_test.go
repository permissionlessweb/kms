package takeoff

import (
	"testing"

	"github.com/cometbft/cometbft/crypto/secp256k1"
	dcrsecp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestHighSSignatureMatchesAfterNormalize(t *testing.T) {
	priv := secp256k1.PrivKey(bytes32(0x44))
	msg := []byte(`{"memo":"cw-orch-session:v1"}`)
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	var r, s dcrsecp.ModNScalar
	if r.SetByteSlice(sig[:32]) || s.SetByteSlice(sig[32:]) {
		t.Fatal("scalar")
	}
	s.Negate()
	rb, sb := r.Bytes(), s.Bytes()
	high := append(rb[:], sb[:]...)
	if priv.PubKey().VerifySignature(msg, high) {
		t.Fatal("high-S must be rejected before normalize")
	}
	normalized, note, err := MatchAuthorization(priv.PubKey().Bytes(), high, msg)
	if err != nil {
		t.Fatal(err, note)
	}
	if !priv.PubKey().VerifySignature(msg, normalized) {
		t.Fatal("normalized signature was rejected")
	}
}
