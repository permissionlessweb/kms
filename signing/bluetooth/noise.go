// Package bluetooth speaks to the zafu cold signer.
//
// The validator link is unchanged. This session is a separate
// Noise_XX_25519_ChaChaPoly_SHA256 handshake over the radio. Static keys are
// encrypted under the ephemeral ECDH. They are not placed in the advertisement
// or in the first handshake message.
package bluetooth

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const protocolName = "Noise_XX_25519_ChaChaPoly_SHA256"

// AdvertisementLen is the BLE advertisement payload. It is random and carries
// no peer id, service name, or key.
const AdvertisementLen = 16

// Advertisement returns bytes safe to put on the air before a connection.
func Advertisement(r io.Reader) ([]byte, error) {
	out := make([]byte, AdvertisementLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

type keyPair struct {
	priv *ecdh.PrivateKey
	pub  []byte
}

func newKey(seed []byte) (keyPair, error) {
	if len(seed) != 32 {
		return keyPair{}, fmt.Errorf("bluetooth: x25519 seed must be 32 bytes")
	}
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return keyPair{}, err
	}
	return keyPair{priv: priv, pub: priv.PublicKey().Bytes()}, nil
}

func dh(priv *ecdh.PrivateKey, pub []byte) ([]byte, error) {
	rp, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(rp)
}

type sym struct {
	k   [32]byte
	n   uint64
	set bool
}

func (c *sym) encrypt(ad, plaintext []byte) ([]byte, error) {
	if !c.set {
		return append([]byte(nil), plaintext...), nil
	}
	aead, err := chacha20poly1305.New(c.k[:])
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], c.n)
	c.n++
	return aead.Seal(nil, nonce[:], plaintext, ad), nil
}

func (c *sym) decrypt(ad, ciphertext []byte) ([]byte, error) {
	if !c.set {
		return append([]byte(nil), ciphertext...), nil
	}
	aead, err := chacha20poly1305.New(c.k[:])
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], c.n)
	c.n++
	return aead.Open(nil, nonce[:], ciphertext, ad)
}

// handshake is one side of Noise XX.
// Token names are initiator-key then responder-key: ee, es, se.
type handshake struct {
	ck, h  []byte
	cs     sym
	s, e   keyPair
	rs, re []byte
	init   bool
}

func newHandshake(static keyPair, initiator bool) *handshake {
	sum := sha256.Sum256([]byte(protocolName))
	return &handshake{
		ck:   append([]byte(nil), sum[:]...),
		h:    append([]byte(nil), sum[:]...),
		s:    static,
		init: initiator,
	}
}

func (hs *handshake) mixHash(data []byte) {
	mac := sha256.New()
	_, _ = mac.Write(hs.h)
	_, _ = mac.Write(data)
	hs.h = mac.Sum(nil)
}

func (hs *handshake) mixKey(ikm []byte) {
	ck, temp := hkdf2(hs.ck, ikm)
	hs.ck = ck
	copy(hs.cs.k[:], temp)
	hs.cs.set = true
	hs.cs.n = 0
}

func (hs *handshake) encryptAndHash(plaintext []byte) ([]byte, error) {
	ct, err := hs.cs.encrypt(hs.h, plaintext)
	if err != nil {
		return nil, err
	}
	hs.mixHash(ct)
	return ct, nil
}

func (hs *handshake) decryptAndHash(ciphertext []byte) ([]byte, error) {
	ad := append([]byte(nil), hs.h...)
	pt, err := hs.cs.decrypt(ad, ciphertext)
	if err != nil {
		return nil, err
	}
	hs.mixHash(ciphertext)
	return pt, nil
}

func hkdf2(ck, ikm []byte) ([]byte, []byte) {
	mac := hmac.New(sha256.New, ck)
	_, _ = mac.Write(ikm)
	temp := mac.Sum(nil)
	one := hmacSHA(temp, []byte{0x01})
	two := hmacSHA(temp, append(append([]byte{}, one...), 0x02))
	return one, two
}

func hmacSHA(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func (hs *handshake) dh(token string) ([]byte, error) {
	// ee = initiator ephemeral × responder ephemeral
	// es = initiator ephemeral × responder static
	// se = initiator static × responder ephemeral
	var priv *ecdh.PrivateKey
	var pub []byte
	switch token {
	case "ee":
		priv, pub = hs.e.priv, hs.re
	case "es":
		if hs.init {
			priv, pub = hs.e.priv, hs.rs
		} else {
			priv, pub = hs.s.priv, hs.re
		}
	case "se":
		if hs.init {
			priv, pub = hs.s.priv, hs.re
		} else {
			priv, pub = hs.e.priv, hs.rs
		}
	default:
		return nil, fmt.Errorf("bluetooth: unknown dh token %s", token)
	}
	return dh(priv, pub)
}

// Session is one direction of transport messages after the handshake.
type Session struct {
	send, recv   cipher.AEAD
	sendN, recvN uint64
	RemoteStatic []byte
}

func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], s.sendN)
	s.sendN++
	return s.send.Seal(nil, nonce[:], plaintext, nil), nil
}

func (s *Session) Open(ciphertext []byte) ([]byte, error) {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], s.recvN)
	s.recvN++
	return s.recv.Open(nil, nonce[:], ciphertext, nil)
}

func (hs *handshake) split(swap bool) (*Session, error) {
	k1, k2 := hkdf2(hs.ck, nil)
	a, err := chacha20poly1305.New(k1)
	if err != nil {
		return nil, err
	}
	b, err := chacha20poly1305.New(k2)
	if err != nil {
		return nil, err
	}
	sess := &Session{send: a, recv: b, RemoteStatic: append([]byte(nil), hs.rs...)}
	if swap {
		sess.send, sess.recv = b, a
	}
	return sess, nil
}

// Initiator holds the KMS side of the handshake.
type Initiator struct{ hs *handshake }

// Responder holds the zafu side of the handshake.
type Responder struct{ hs *handshake }

// BeginInitiator starts Noise XX. msg is only the ephemeral public key.
func BeginInitiator(staticSeed, ephemeralSeed []byte) (*Initiator, []byte, error) {
	s, err := newKey(staticSeed)
	if err != nil {
		return nil, nil, err
	}
	e, err := newKey(ephemeralSeed)
	if err != nil {
		return nil, nil, err
	}
	hs := newHandshake(s, true)
	hs.e = e
	hs.mixHash(e.pub)
	return &Initiator{hs: hs}, append([]byte(nil), e.pub...), nil
}

// BeginResponder reads message 1. It rejects anything but a 32-byte ephemeral key.
func BeginResponder(staticSeed, msg []byte) (*Responder, error) {
	if len(msg) != 32 {
		return nil, errors.New("bluetooth: handshake message 1 must be 32 bytes")
	}
	s, err := newKey(staticSeed)
	if err != nil {
		return nil, err
	}
	hs := newHandshake(s, false)
	hs.re = append([]byte(nil), msg...)
	hs.mixHash(hs.re)
	return &Responder{hs: hs}, nil
}

// Message2 is ephemeral || encrypted static.
func (r *Responder) Message2(ephemeralSeed []byte) ([]byte, error) {
	hs := r.hs
	e, err := newKey(ephemeralSeed)
	if err != nil {
		return nil, err
	}
	hs.e = e
	out := append([]byte(nil), e.pub...)
	hs.mixHash(e.pub)
	ee, err := hs.dh("ee")
	if err != nil {
		return nil, err
	}
	hs.mixKey(ee)
	encS, err := hs.encryptAndHash(hs.s.pub)
	if err != nil {
		return nil, err
	}
	out = append(out, encS...)
	es, err := hs.dh("es")
	if err != nil {
		return nil, err
	}
	hs.mixKey(es)
	return out, nil
}

// ReadMessage2 checks the responder and returns the encrypted flight unchanged
// only after the static key decrypts. The returned session is not finished
// until Message3.
func (n *Initiator) ReadMessage2(msg []byte) error {
	if len(msg) < 32+48 {
		return errors.New("bluetooth: handshake message 2 too short")
	}
	hs := n.hs
	hs.re = append([]byte(nil), msg[:32]...)
	hs.mixHash(hs.re)
	ee, err := hs.dh("ee")
	if err != nil {
		return err
	}
	hs.mixKey(ee)
	static, err := hs.decryptAndHash(msg[32:])
	if err != nil {
		return err
	}
	if len(static) != 32 {
		return errors.New("bluetooth: responder static key length")
	}
	hs.rs = static
	es, err := hs.dh("es")
	if err != nil {
		return err
	}
	hs.mixKey(es)
	return nil
}

// Message3 sends the initiator static key, encrypted.
func (n *Initiator) Message3() ([]byte, *Session, error) {
	hs := n.hs
	encS, err := hs.encryptAndHash(hs.s.pub)
	if err != nil {
		return nil, nil, err
	}
	se, err := hs.dh("se")
	if err != nil {
		return nil, nil, err
	}
	hs.mixKey(se)
	sess, err := hs.split(false)
	if err != nil {
		return nil, nil, err
	}
	return encS, sess, nil
}

// ReadMessage3 finishes the responder side.
func (r *Responder) ReadMessage3(msg []byte) (*Session, error) {
	hs := r.hs
	static, err := hs.decryptAndHash(msg)
	if err != nil {
		return nil, err
	}
	if len(static) != 32 {
		return nil, errors.New("bluetooth: initiator static key length")
	}
	hs.rs = static
	se, err := hs.dh("se")
	if err != nil {
		return nil, err
	}
	hs.mixKey(se)
	// Responder sends with the second cipher and receives with the first.
	return hs.split(true)
}
