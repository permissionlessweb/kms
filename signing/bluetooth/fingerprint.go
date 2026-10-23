package bluetooth

import (
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint is the eight-byte identity the phone user types from the KMS
// page before a signer key is sealed. It is sha256(static public key).
func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	raw := hex.EncodeToString(sum[:8])
	var out []byte
	for i := 0; i < len(raw); i += 2 {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, raw[i], raw[i+1])
	}
	return string(out)
}
