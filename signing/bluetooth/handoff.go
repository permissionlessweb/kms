package bluetooth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// Key moves between phones, KMS side.
//
//	KMS       --zcinti-move:2 (start: chain, slot, nonce, floor, KMS id)--> old phone
//	new phone --zcinti-recv:1--> old phone --zcinti-p2p:1 (sealed key)--> new phone
//	new phone --zcinti-imported:1--> old phone
//	old phone --zcinti-retired:2 (signed by the consensus key, names the
//	            new phone's identity)--> KMS
//
// Every hop is a QR code between screens and cameras. The consensus key
// never reaches this KMS, Bluetooth, or any network; the KMS only checks
// the retire proof and pins the named new phone.

const (
	MoveStartPrefix = "zcinti-move:2:"
	RetiredPrefixV2 = "zcinti-retired:2:"
	retireDomainV2  = "zcinti-retire:2"
	NonceSize       = 16
)

// RetireMessageV2 is what the old phone signs with the consensus key after
// the new phone acknowledged the import and before it wipes the key.
func RetireMessageV2(chain, slot string, pub []byte, floor uint64, nonce [NonceSize]byte, target []byte) []byte {
	return []byte(retireDomainV2 + "|" + chain + "|" + slot + "|" + KeyIDHex(pub) + "|" +
		strconv.FormatUint(floor, 10) + "|" + hex.EncodeToString(nonce[:]) + "|" + hex.EncodeToString(target))
}

// VerifyRetireV2 checks a zcinti-retired:2 QR against the slot's consensus
// key, floor and nonce. It returns the new phone's identity and the signature.
func VerifyRetireV2(payload, chain, slot string, pub []byte, floor uint64, nonce [NonceSize]byte) ([]byte, []byte, error) {
	payload = strings.TrimSpace(payload)
	if !strings.HasPrefix(payload, RetiredPrefixV2) {
		return nil, nil, errors.New("bluetooth: not a retire proof (scan the old phone's Retired QR)")
	}
	parts := strings.Split(payload[len(RetiredPrefixV2):], ":")
	if len(parts) != 2 {
		return nil, nil, errors.New("bluetooth: damaged retire proof")
	}
	target, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil || len(target) != 32 {
		return nil, nil, errors.New("bluetooth: retire proof does not name a phone")
	}
	sig, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, errors.New("bluetooth: retire proof is not a signature")
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, RetireMessageV2(chain, slot, pub, floor, nonce, target), sig) {
		return nil, nil, errors.New("bluetooth: retire proof does not verify for this key, floor and move")
	}
	return target, sig, nil
}
