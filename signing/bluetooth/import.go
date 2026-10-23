package bluetooth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	importMsg1 = 0x20
	importMsg2 = 0x21
	importMsg3 = 0x22
	importAck  = 0x23
	importBox  = 0x24
	importPub  = 0x25
)

// ImportFlight is one Noise XX transfer of a consensus key.
// The static keys bind the two identities. The ephemeral keys are new for
// this transfer, so the box is not sealed under the long-term Bluetooth key.
type ImportFlight struct {
	init *Initiator
	sess *Session
}

// BeginImport starts the KMS side. msg1 is only the ephemeral public key.
func BeginImport(staticSeed []byte) (*ImportFlight, []byte, error) {
	eph := make([]byte, 32)
	if _, err := rand.Read(eph); err != nil {
		return nil, nil, err
	}
	init, msg1, err := BeginInitiator(staticSeed, eph)
	if err != nil {
		return nil, nil, err
	}
	for i := range eph {
		eph[i] = 0
	}
	out := append([]byte{importMsg1}, msg1...)
	return &ImportFlight{init: init}, out, nil
}

// AcceptReply reads the phone's message 2 and returns message 3.
func (f *ImportFlight) AcceptReply(msg2 []byte) ([]byte, error) {
	if len(msg2) == 0 || msg2[0] != importMsg2 {
		return nil, errors.New("bluetooth: import reply is not message 2")
	}
	if err := f.init.ReadMessage2(msg2[1:]); err != nil {
		return nil, err
	}
	msg3, sess, err := f.init.Message3()
	if err != nil {
		return nil, err
	}
	f.sess = sess
	return append([]byte{importMsg3}, msg3...), nil
}

// SealKey seals the 64-byte CometBFT secret for the phone.
// chain is the Terp chain id, not a file path.
func (f *ImportFlight) SealKey(chain string, secret []byte) ([]byte, error) {
	if f.sess == nil {
		return nil, errors.New("bluetooth: import handshake is not finished")
	}
	if len(secret) != 64 {
		return nil, errors.New("bluetooth: consensus secret must be 64 bytes")
	}
	if chain == "" || len(chain) > 64 {
		return nil, errors.New("bluetooth: chain id is missing")
	}
	plain := make([]byte, 0, 1+len(chain)+64)
	plain = append(plain, byte(len(chain)))
	plain = append(plain, chain...)
	plain = append(plain, secret...)
	box, err := f.sess.Seal(plain)
	for i := range plain {
		plain[i] = 0
	}
	if err != nil {
		return nil, err
	}
	return append([]byte{importBox}, box...), nil
}

// ReadImportPub checks the phone stored the key. It returns the public key only.
func ReadImportPub(msg []byte) ([]byte, error) {
	if len(msg) != 33 || msg[0] != importPub {
		return nil, errors.New("bluetooth: phone did not confirm the import")
	}
	return append([]byte(nil), msg[1:]...), nil
}

// CometSecret reads the 64-byte private field. The caller must wipe it.
// Paths for the live Morocco or Penumbra signers are refused.
func CometSecret(path string) (secret []byte, pub []byte, err error) {
	if path == "" {
		return nil, nil, errors.New("bluetooth: no key file configured")
	}
	if containsForbiddenKeyPath(path) {
		return nil, nil, errors.New("bluetooth: that key file is not for this drill")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var doc struct {
		PubKey struct {
			Value string `json:"value"`
		} `json:"pub_key"`
		PrivKey struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"priv_key"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	if doc.PrivKey.Type != "tendermint/PrivKeyEd25519" {
		return nil, nil, errors.New("bluetooth: key file is not ed25519")
	}
	secret, err = base64.StdEncoding.DecodeString(doc.PrivKey.Value)
	if err != nil || len(secret) != 64 {
		return nil, nil, errors.New("bluetooth: private key field is not 64 bytes")
	}
	pub, err = base64.StdEncoding.DecodeString(doc.PubKey.Value)
	if err != nil || len(pub) != 32 {
		for i := range secret {
			secret[i] = 0
		}
		return nil, nil, errors.New("bluetooth: public key field is not 32 bytes")
	}
	return secret, pub, nil
}

// StaticPublic is the KMS identity a phone seals an export to.
func StaticPublic(seed []byte) ([]byte, error) {
	key, err := newKey(seed)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), key.pub...), nil
}

// OpenExport opens a phone recovery QR. The ephemeral public key is in the
// payload. The static seed is this KMS identity, so a different KMS cannot open it.
func OpenExport(staticSeed, payload []byte) (chain string, secret []byte, err error) {
	const prefix = "zcinti-recover:1:"
	text := string(payload)
	if len(text) < len(prefix) || text[:len(prefix)] != prefix {
		return "", nil, errors.New("bluetooth: recovery QR is not a zcinti export")
	}
	raw, err := base64.StdEncoding.DecodeString(text[len(prefix):])
	if err != nil || len(raw) < 32+16 {
		return "", nil, errors.New("bluetooth: recovery QR is truncated")
	}
	ephPub := raw[:32]
	box := raw[32:]
	static, err := newKey(staticSeed)
	if err != nil {
		return "", nil, err
	}
	shared, err := dh(static.priv, ephPub)
	if err != nil {
		return "", nil, err
	}
	sum := sha256Sum(shared)
	plain, err := openChaCha(sum[:], box)
	if err != nil {
		return "", nil, err
	}
	if len(plain) < 1 {
		return "", nil, errors.New("bluetooth: empty recovery")
	}
	n := int(plain[0])
	if len(plain) < 1+n+64 {
		return "", nil, errors.New("bluetooth: recovery is short")
	}
	chain = string(plain[1 : 1+n])
	secret = append([]byte(nil), plain[1+n:1+n+64]...)
	for i := range plain {
		plain[i] = 0
	}
	return chain, secret, nil
}

func sha256Sum(in []byte) [32]byte { return sha256.Sum256(in) }

func openChaCha(key, box []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	return aead.Open(nil, nonce[:], box, []byte("zcinti-export-v1"))
}

func containsForbiddenKeyPath(path string) bool {
	for _, part := range []string{".kms-terp", ".kms-penumbra", "kms-penumbra"} {
		if strings.Contains(path, part) {
			return true
		}
	}
	return false
}
