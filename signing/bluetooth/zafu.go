package bluetooth

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
)

// HWM is the last consensus message a cold signer accepted.
type HWM struct {
	Height uint64
	Round  uint32
	Step   uint8
	Set    bool
}

// Allows reports whether next is strictly after h.
func (h HWM) Allows(height uint64, round uint32, step uint8) bool {
	if !h.Set {
		return true
	}
	if height != h.Height {
		return height > h.Height
	}
	if round != h.Round {
		return round > h.Round
	}
	return step > h.Step
}

func (h *HWM) Advance(height uint64, round uint32, step uint8) {
	h.Height, h.Round, h.Step, h.Set = height, round, step, true
}

// softwareZafu is the in-process cold signer used by tests. The phone
// enforces the same rule before it signs a GATT vote.
type softwareZafu struct {
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	hwm     HWM
	last    []byte
	lastSig []byte
}

func (z *softwareZafu) Sign(height uint64, round uint32, step uint8, msg []byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, errors.New("zafu: empty sign bytes")
	}
	same := z.hwm.Set && height == z.hwm.Height && round == z.hwm.Round && step == z.hwm.Step
	if !same && !z.hwm.Allows(height, round, step) {
		return nil, fmt.Errorf("zafu: refuse %d/%d/%d after %d/%d/%d", height, round, step, z.hwm.Height, z.hwm.Round, z.hwm.Step)
	}
	// A non-nil precommit signs the extension, then the vote, at one step.
	// The extension may change. The vote bytes may not.
	if isVoteExtension(msg) {
		gotH, gotR, ok := extensionHeightRound(msg)
		if !ok || gotH != height || gotR != round {
			return nil, fmt.Errorf("zafu: refuse extension %d/%d/%d", height, round, step)
		}
		z.advance(height, round, step, same)
		return ed25519.Sign(z.priv, msg), nil
	}
	if same && len(z.last) > 0 {
		if bytes.Equal(z.last, msg) {
			return append([]byte(nil), z.lastSig...), nil
		}
		return nil, fmt.Errorf("zafu: refuse equivocation %d/%d/%d", height, round, step)
	}
	sig := ed25519.Sign(z.priv, msg)
	z.advance(height, round, step, same)
	z.last = append([]byte(nil), msg...)
	z.lastSig = append([]byte(nil), sig...)
	return sig, nil
}

func (z *softwareZafu) advance(height uint64, round uint32, step uint8, same bool) {
	z.hwm.Advance(height, round, step)
	if !same {
		z.last = nil
		z.lastSig = nil
	}
}

// isVoteExtension reports a canonical vote-extension sign doc.
// Vote and proposal docs start with field 1 (tag 0x08) after the length prefix.
func isVoteExtension(msg []byte) bool {
	i := 0
	for i < len(msg) && msg[i]&0x80 != 0 {
		i++
	}
	if i >= len(msg) {
		return false
	}
	i++
	if i >= len(msg) {
		return false
	}
	// 0x0a is a non-empty extension. 0x11 is an empty one (height comes first).
	// Anything else, including a vote or proposal (0x08), is locked.
	return msg[i] == 0x0a || msg[i] == 0x11
}
