package bluetooth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	msgSign = byte(0x10)
	msgSig  = byte(0x11)
)

// ExerciseResult is one cold-sign round trip with no radio.
type ExerciseResult struct {
	Height    uint64
	Latency   time.Duration
	PubKey    []byte
	Signature []byte
}

// Exercise runs one Noise session against an in-process zafu and measures
// the time from sealing the request to opening the signature.
func Exercise(height uint64, round uint32, step uint8, msg []byte) (ExerciseResult, error) {
	if len(msg) == 0 {
		return ExerciseResult{}, errors.New("bluetooth: empty sign bytes")
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return ExerciseResult{}, err
	}
	pub, priv, err := ed25519.GenerateKey(bytes.NewReader(append(seed, seed...)))
	if err != nil {
		return ExerciseResult{}, err
	}
	dev := &softwareZafu{priv: priv, pub: pub}
	iStatic := bytes.Repeat([]byte{0x21}, 32)
	rStatic := bytes.Repeat([]byte{0x22}, 32)
	iEph := bytes.Repeat([]byte{0x23}, 32)
	rEph := bytes.Repeat([]byte{0x24}, 32)
	init, m1, err := BeginInitiator(iStatic, iEph)
	if err != nil {
		return ExerciseResult{}, err
	}
	resp, err := BeginResponder(rStatic, m1)
	if err != nil {
		return ExerciseResult{}, err
	}
	m2, err := resp.Message2(rEph)
	if err != nil {
		return ExerciseResult{}, err
	}
	if bytes.Contains(m2, resp.hs.s.pub) {
		return ExerciseResult{}, errors.New("bluetooth: static key leaked in handshake")
	}
	if err := init.ReadMessage2(m2); err != nil {
		return ExerciseResult{}, err
	}
	m3, iSess, err := init.Message3()
	if err != nil {
		return ExerciseResult{}, err
	}
	rSess, err := resp.ReadMessage3(m3)
	if err != nil {
		return ExerciseResult{}, err
	}
	body := encodeSign(height, round, step, msg)
	start := time.Now()
	ct, err := iSess.Seal(body)
	if err != nil {
		return ExerciseResult{}, err
	}
	pt, err := rSess.Open(ct)
	if err != nil {
		return ExerciseResult{}, err
	}
	h, rnd, st, payload, err := decodeSign(pt)
	if err != nil {
		return ExerciseResult{}, err
	}
	sig, err := dev.Sign(h, rnd, st, payload)
	if err != nil {
		return ExerciseResult{}, err
	}
	reply, err := rSess.Seal(append([]byte{msgSig}, sig...))
	if err != nil {
		return ExerciseResult{}, err
	}
	opened, err := iSess.Open(reply)
	if err != nil {
		return ExerciseResult{}, err
	}
	latency := time.Since(start)
	if len(opened) != 65 || opened[0] != msgSig {
		return ExerciseResult{}, errors.New("bluetooth: bad signature frame")
	}
	if !ed25519.Verify(pub, msg, opened[1:]) {
		return ExerciseResult{}, errors.New("bluetooth: signature did not verify")
	}
	return ExerciseResult{Height: height, Latency: latency, PubKey: pub, Signature: opened[1:]}, nil
}

func encodeSign(height uint64, round uint32, step uint8, msg []byte) []byte {
	buf := make([]byte, 1+8+4+1+2+len(msg))
	buf[0] = msgSign
	binary.BigEndian.PutUint64(buf[1:9], height)
	binary.BigEndian.PutUint32(buf[9:13], round)
	buf[13] = step
	binary.BigEndian.PutUint16(buf[14:16], uint16(len(msg)))
	copy(buf[16:], msg)
	return pad(buf, 64)
}

func decodeSign(in []byte) (uint64, uint32, uint8, []byte, error) {
	if len(in) < 16 || in[0] != msgSign {
		return 0, 0, 0, nil, errors.New("bluetooth: not a sign frame")
	}
	height := binary.BigEndian.Uint64(in[1:9])
	round := binary.BigEndian.Uint32(in[9:13])
	step := in[13]
	n := int(binary.BigEndian.Uint16(in[14:16]))
	if 16+n > len(in) {
		return 0, 0, 0, nil, fmt.Errorf("bluetooth: sign frame length %d", n)
	}
	return height, round, step, in[16 : 16+n], nil
}

func pad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out, b)
	return out
}
