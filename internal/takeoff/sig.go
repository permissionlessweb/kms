package takeoff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/cometbft/cometbft/crypto/secp256k1"
	dcrsecp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// NormalizeSig returns the low-S form Comet accepts.
// The bool is true when the phone's signature used the high-S form.
func NormalizeSig(sig []byte) ([]byte, bool, error) {
	if len(sig) != 64 {
		return nil, false, fmt.Errorf("takeoff: signature is %d bytes", len(sig))
	}
	var r, s dcrsecp.ModNScalar
	if r.SetByteSlice(sig[:32]) || s.SetByteSlice(sig[32:]) {
		return nil, false, fmt.Errorf("takeoff: signature scalar is out of range")
	}
	original := dcrecdsa.NewSignature(&r, &s)
	parsed, err := dcrecdsa.ParseDERSignature(original.Serialize())
	if err != nil {
		return nil, false, fmt.Errorf("takeoff: signature parse: %w", err)
	}
	rv, sv := parsed.R(), parsed.S()
	rb, sb := rv.Bytes(), sv.Bytes()
	out := append(rb[:], sb[:]...)
	return out, !bytesEqual(out, sig), nil
}

// MatchAuthorization reports whether sig signs amino under pub.
// It accepts the low-S form the chain requires.
func MatchAuthorization(pub, sig, amino []byte) (normalized []byte, detail string, err error) {
	if len(pub) != 33 {
		return nil, "", fmt.Errorf("takeoff: public key is %d bytes", len(pub))
	}
	normalized, changed, err := NormalizeSig(sig)
	if err != nil {
		return nil, "", err
	}
	key := secp256k1.PubKey(pub)
	sum := sha256.Sum256(amino)
	addr, addrErr := bech32Encode("terp", key.Address())
	if addrErr != nil {
		addr = "unreadable"
	}
	note := fmt.Sprintf("signer %s, authorization %s, %d bytes", addr, hex.EncodeToString(sum[:4]), len(amino))
	if changed {
		note += ", signature was high-S and was normalized"
	}
	if !key.VerifySignature(amino, normalized) {
		return nil, note, fmt.Errorf("takeoff: signature does not match this authorization (%s)", note)
	}
	return normalized, note, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
