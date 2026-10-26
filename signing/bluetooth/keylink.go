package bluetooth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cosmos/kms/config"
)

// msgSignFor is a sign request that names the phone key that must sign it.
// Inside the Noise session it replaces msgSign when one phone holds several
// validator keys:
//
//	0x12 | key id (8) | height (8) | round (4) | step (1) | len (2) | sign bytes
//
// The key id is the first 8 bytes of sha256(consensus pubkey). The phone keeps
// a separate high-water mark per key and refuses (wireRefuse) a key it does
// not hold. The reply is unchanged: 0x11 | signature.
const msgSignFor = byte(0x12)

// KeyID names a consensus public key on the wire.
func KeyID(pub []byte) [8]byte {
	sum := sha256.Sum256(pub)
	var id [8]byte
	copy(id[:], sum[:8])
	return id
}

// KeyIDHex is KeyID as 16 hex characters.
func KeyIDHex(pub []byte) string {
	id := KeyID(pub)
	return hex.EncodeToString(id[:])
}

func encodeSignFor(id [8]byte, height uint64, round uint32, step uint8, msg []byte) []byte {
	buf := make([]byte, 1+8+8+4+1+2+len(msg))
	buf[0] = msgSignFor
	copy(buf[1:9], id[:])
	binary.BigEndian.PutUint64(buf[9:17], height)
	binary.BigEndian.PutUint32(buf[17:21], round)
	buf[21] = step
	binary.BigEndian.PutUint16(buf[22:24], uint16(len(msg)))
	copy(buf[24:], msg)
	return pad(buf, 64)
}

func decodeSignFor(in []byte) (id [8]byte, height uint64, round uint32, step uint8, msg []byte, err error) {
	if len(in) < 24 || in[0] != msgSignFor {
		return id, 0, 0, 0, nil, errors.New("bluetooth: not a keyed sign frame")
	}
	copy(id[:], in[1:9])
	height = binary.BigEndian.Uint64(in[9:17])
	round = binary.BigEndian.Uint32(in[17:21])
	step = in[21]
	n := int(binary.BigEndian.Uint16(in[22:24]))
	if 24+n > len(in) {
		return id, 0, 0, 0, nil, fmt.Errorf("bluetooth: keyed sign frame length %d", n)
	}
	return id, height, round, step, in[24 : 24+n], nil
}

// KeyLink is one validator key on a shared phone link. Every KeyLink on a
// Link shares its Noise session and request slot; requests are serialized.
type KeyLink struct {
	l *Link
	// m, when set, picks the link per vote: the live session of the phone
	// pinned for label. One phone dropping never blocks another's slots.
	m     *Mesh
	pub   ed25519.PublicKey
	id    [8]byte
	label string
	mu    sync.Mutex
	hrs   struct {
		h uint64
		r uint32
		s uint8
	}
	signs []SignRecord
}

var keyedMu sync.Map // *Link -> *sync.Mutex

func (l *Link) slot() *sync.Mutex {
	m, _ := keyedMu.LoadOrStore(l, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// ForKey returns the link for one phone-held consensus key.
func (l *Link) ForKey(label string, pub []byte) (*KeyLink, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bluetooth: key %q public key is %d bytes", label, len(pub))
	}
	return &KeyLink{l: l, pub: append(ed25519.PublicKey(nil), pub...), id: KeyID(pub), label: label}, nil
}

// PubKeyFor resolves the public key of a phone key named in the config. A
// 64-hex key_id is the pubkey itself; otherwise <dir>/keys/<label>/pub.hex,
// which the scanner writes when the phone publishes its key list.
func (l *Link) PubKeyFor(k config.Key, label string) ([]byte, error) {
	if b, err := hex.DecodeString(strings.TrimSpace(k.KeyID)); err == nil && len(b) == ed25519.PublicKeySize {
		return b, nil
	}
	raw, err := os.ReadFile(filepath.Join(l.home, "keys", label, "pub.hex"))
	if err != nil {
		return nil, fmt.Errorf("bluetooth: phone has not published key %q: %w", label, err)
	}
	b, err := hex.DecodeString(string(trimSpace(raw)))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bluetooth: key %q public key is not 32 bytes", label)
	}
	return b, nil
}

// ID is the 16-hex wire id.
func (k *KeyLink) ID() string { return hex.EncodeToString(k.id[:]) }

// Label is the config name of the key.
func (k *KeyLink) Label() string { return k.label }

// SetHRS records what is about to be signed for this key.
func (k *KeyLink) SetHRS(height uint64, round uint32, step uint8) {
	k.mu.Lock()
	k.hrs.h, k.hrs.r, k.hrs.s = height, round, step
	k.mu.Unlock()
}

// Recent is this key's newest signatures, oldest first.
func (k *KeyLink) Recent() []SignRecord {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]SignRecord(nil), k.signs...)
}

// PubKey implements signing.Signer.
func (k *KeyLink) PubKey() []byte { return append([]byte(nil), k.pub...) }

// Scheme implements signing.Signer.
func (k *KeyLink) Scheme() config.Algorithm { return config.AlgoED25519 }

// Close implements signing.Signer.
func (k *KeyLink) Close() error { return nil }

// Sign asks the phone to sign msg with this key only.
func (k *KeyLink) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, errors.New("bluetooth: empty sign bytes")
	}
	l := k.l
	if k.m != nil {
		var err error
		if l, err = k.m.route(k.label); err != nil {
			return nil, err
		}
	}
	slot := l.slot()
	slot.Lock()
	defer slot.Unlock()
	if err := l.readySession(); err != nil {
		return nil, err
	}
	k.mu.Lock()
	h, r, s := k.hrs.h, k.hrs.r, k.hrs.s
	k.mu.Unlock()
	if err := handoffGate(l.home, k.label, h); err != nil {
		return nil, err
	}
	l.sessMu.Lock()
	var remote []byte
	if l.sess != nil {
		remote = append([]byte(nil), l.sess.RemoteStatic...)
	}
	l.sessMu.Unlock()
	if err := slotAllows(l.home, k.label, remote); err != nil {
		return nil, err
	}
	l.mu.Lock()
	reqID := l.next
	l.next++
	l.mu.Unlock()
	l.sessMu.Lock()
	box, err := l.sess.Seal(encodeSignFor(k.id, h, r, s, msg))
	l.sessMu.Unlock()
	if err != nil {
		return nil, err
	}
	wire := append([]byte{wireVote}, box...)
	if err := writeJSON(filepath.Join(l.dir, "req.json"), signReq{ID: reqID, Frame: base64.StdEncoding.EncodeToString(wire)}); err != nil {
		return nil, err
	}
	start := time.Now()
	deadline := start.Add(voteWait)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			l.sessMu.Lock()
			l.sess = nil
			l.sessMu.Unlock()
			return nil, fmt.Errorf("bluetooth: phone did not sign for key %s in time", k.label)
		}
		raw, err := os.ReadFile(filepath.Join(l.dir, "resp.json"))
		var resp signResp
		if err != nil || json.Unmarshal(raw, &resp) != nil || resp.ID != reqID {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		rawSig, err := base64.StdEncoding.DecodeString(resp.Sig)
		if err != nil {
			return nil, err
		}
		if err := parseRefusal(rawSig, resp.Reason, k.label, h, r, s); err != nil {
			return nil, err
		}
		if len(rawSig) == 0 || rawSig[0] != wireSig {
			return nil, errors.New("bluetooth: phone signature was not sealed")
		}
		l.sessMu.Lock()
		opened, openErr := l.sess.Open(rawSig[1:])
		if openErr != nil {
			l.sess = nil
		}
		l.sessMu.Unlock()
		if openErr != nil {
			return nil, openErr
		}
		sig := opened
		if len(sig) == 65 && sig[0] == msgSig {
			sig = sig[1:]
		}
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(k.pub, msg, sig) {
			return nil, fmt.Errorf("bluetooth: signature for key %s did not verify", k.label)
		}
		k.mu.Lock()
		k.signs = append(k.signs, SignRecord{Height: h, Round: r, Step: s, LatencyMs: time.Since(start).Milliseconds(), At: time.Now().Format(time.RFC3339)})
		if len(k.signs) > 100 {
			k.signs = k.signs[len(k.signs)-100:]
		}
		k.mu.Unlock()
		return sig, nil
	}
}

// PubKeyFor resolves a configured key. The mesh scanner merges every
// phone's key list into <home>/keys, so the root link sees them all.
func (m *Mesh) PubKeyFor(k config.Key, label string) ([]byte, error) {
	return m.root.PubKeyFor(k, label)
}
