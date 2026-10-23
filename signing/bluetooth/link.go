package bluetooth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cosmos/kms/config"
)

// Dir is the laptop-side drop between the console and the Bluetooth scanner.
// It holds pairing and sign files, never a copy of the consensus private key.
const Dir = "/tmp/kms-ble"

// SignRecord is one signature the phone returned.
type SignRecord struct {
	Height    uint64 `json:"height"`
	Round     uint32 `json:"round"`
	Step      uint8  `json:"step"`
	LatencyMs int64  `json:"latency_ms"`
	At        string `json:"at"`
}

// Link asks the paired phone to sign and waits for the signature.
type Link struct {
	dir    string
	mu     sync.Mutex
	sessMu sync.Mutex
	sess   *Session
	pub    ed25519.PublicKey
	next   uint64
	hrs    struct {
		h uint64
		r uint32
		s uint8
	}
	signs []SignRecord
}

// Open prepares dir and returns a link that reads and writes files there.
func Open(dir string) *Link {
	_ = os.MkdirAll(dir, 0o700)
	return &Link{dir: dir, next: 1}
}

var (
	defaultOnce sync.Once
	defaultLink *Link
)

// DefaultLink is the console's link at Dir.
func DefaultLink() *Link {
	defaultOnce.Do(func() { defaultLink = Open(Dir) })
	return defaultLink
}

// SetHRS records the height, round, and step of the consensus message about
// to be signed. FilePV still enforces the double-sign floor.
func (l *Link) SetHRS(height uint64, round uint32, step uint8) {
	l.mu.Lock()
	l.hrs.h, l.hrs.r, l.hrs.s = height, round, step
	l.mu.Unlock()
}

// PubKey reads the 32-byte key the phone published. It is not a private key.
func (l *Link) PubKey() ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.pub) == ed25519.PublicKeySize {
		return append([]byte(nil), l.pub...), nil
	}
	raw, err := os.ReadFile(filepath.Join(l.dir, "pub.hex"))
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(string(trimSpace(raw)))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("bluetooth: phone public key is not 32 bytes")
	}
	l.pub = ed25519.PublicKey(b)
	return append([]byte(nil), b...), nil
}

// Recent returns the newest signatures, up to 100, oldest first.
func (l *Link) Recent() []SignRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]SignRecord, len(l.signs))
	copy(out, l.signs)
	return out
}

type signReq struct {
	ID    uint64 `json:"id"`
	Frame string `json:"frame"`
}

type signResp struct {
	ID  uint64 `json:"id"`
	Sig string `json:"sig"`
}

// Sign blocks until the phone returns an Ed25519 signature over msg, or four
// seconds pass. A timeout is a failed sign: the caller must not invent one.
func (l *Link) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, errors.New("bluetooth: empty sign bytes")
	}
	if err := l.ensureSession(ctx); err != nil {
		return nil, err
	}
	l.mu.Lock()
	id := l.next
	l.next++
	h, r, s := l.hrs.h, l.hrs.r, l.hrs.s
	l.mu.Unlock()
	frame := encodeSign(h, r, s, msg)
	l.sessMu.Lock()
	box, err := l.sess.Seal(frame)
	l.sessMu.Unlock()
	if err != nil {
		return nil, err
	}
	wire := append([]byte{wireVote}, box...)
	if err := writeJSON(filepath.Join(l.dir, "req.json"), signReq{ID: id, Frame: base64.StdEncoding.EncodeToString(wire)}); err != nil {
		return nil, err
	}
	start := time.Now()
	deadline := time.Now().Add(3500 * time.Millisecond)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			// The phone may have restarted and forgotten the Noise session.
			l.sessMu.Lock()
			l.sess = nil
			l.sessMu.Unlock()
			return nil, errors.New("bluetooth: phone did not sign in time")
		}
		raw, err := os.ReadFile(filepath.Join(l.dir, "resp.json"))
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		var resp signResp
		if json.Unmarshal(raw, &resp) != nil || resp.ID != id {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		rawSig, err := base64.StdEncoding.DecodeString(resp.Sig)
		if err != nil {
			return nil, err
		}
		if len(rawSig) == 1 && rawSig[0] == wireRefuse {
			return nil, errors.New("bluetooth: phone refused a repeated or lower height")
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
		pub, err := l.PubKey()
		if err != nil {
			return nil, err
		}
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, sig) {
			return nil, errors.New("bluetooth: phone signature did not verify")
		}
		l.mu.Lock()
		l.signs = append(l.signs, SignRecord{
			Height: h, Round: r, Step: s,
			LatencyMs: time.Since(start).Milliseconds(),
			At:        time.Now().Format(time.RFC3339),
		})
		if len(l.signs) > 100 {
			l.signs = l.signs[len(l.signs)-100:]
		}
		l.mu.Unlock()
		return sig, nil
	}
}

// Exchange sends one radio frame and returns the phone's notify bytes.
func (l *Link) Exchange(ctx context.Context, frame []byte) ([]byte, error) {
	l.mu.Lock()
	id := l.next
	l.next++
	l.mu.Unlock()
	if err := writeJSON(filepath.Join(l.dir, "req.json"), signReq{ID: id, Frame: base64.StdEncoding.EncodeToString(frame)}); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(3500 * time.Millisecond)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, errors.New("bluetooth: phone did not answer")
		}
		raw, err := os.ReadFile(filepath.Join(l.dir, "resp.json"))
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		var resp signResp
		if json.Unmarshal(raw, &resp) != nil || resp.ID != id {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		return base64.StdEncoding.DecodeString(resp.Sig)
	}
}

// SendKey moves a consensus secret to the phone inside a fresh Noise XX session.
func (l *Link) SendKey(ctx context.Context, chain string, secret []byte) ([]byte, error) {
	static, err := noiseStatic(l.dir)
	if err != nil {
		return nil, err
	}
	flight, msg1, err := BeginImport(static)
	if err != nil {
		return nil, err
	}
	reply, err := l.Exchange(ctx, msg1)
	if err != nil {
		return nil, err
	}
	msg3, err := flight.AcceptReply(reply)
	if err != nil {
		return nil, err
	}
	if _, err := l.Exchange(ctx, msg3); err != nil {
		return nil, err
	}
	if flight.sess == nil {
		return nil, errors.New("bluetooth: import handshake is not finished")
	}
	if err := AcceptPhone(flight.sess.RemoteStatic); err != nil {
		return nil, err
	}
	box, err := flight.SealKey(chain, secret)
	if err != nil {
		return nil, err
	}
	confirm, err := l.Exchange(ctx, box)
	if err != nil {
		return nil, err
	}
	return ReadImportPub(confirm)
}

// ensureSession finishes Noise XX with the phone before any vote is sealed.
// A lost session is rebuilt on the next call.
func (l *Link) ensureSession(ctx context.Context) error {
	l.sessMu.Lock()
	defer l.sessMu.Unlock()
	if l.sess != nil {
		return nil
	}
	static, err := noiseStatic(l.dir)
	if err != nil {
		return err
	}
	eph := make([]byte, 32)
	if _, err := rand.Read(eph); err != nil {
		return err
	}
	init, msg1, err := BeginInitiator(static, eph)
	for i := range eph {
		eph[i] = 0
	}
	if err != nil {
		return err
	}
	reply, err := l.Exchange(ctx, append([]byte{wireHello}, msg1...))
	if err != nil {
		return err
	}
	if len(reply) == 0 || reply[0] != wireReply {
		return errors.New("bluetooth: phone did not start a session")
	}
	if err := init.ReadMessage2(reply[1:]); err != nil {
		return err
	}
	if err := acceptPhone(l.dir, init.hs.rs); err != nil {
		return err
	}
	msg3, sess, err := init.Message3()
	if err != nil {
		return err
	}
	ack, err := l.Exchange(ctx, append([]byte{wireFinish}, msg3...))
	if err != nil {
		return err
	}
	if len(ack) != 1 || ack[0] != wireReady {
		return errors.New("bluetooth: phone rejected this KMS identity")
	}
	l.sess = sess
	return nil
}

// NoiseStatic is the KMS long-term identity. The production copy is sealed
// outside /tmp.
func NoiseStatic() ([]byte, error) { return sealedNoiseStatic(Dir) }

func noiseStatic(dir string) ([]byte, error) {
	if dir == Dir {
		return sealedNoiseStatic(dir)
	}
	path := filepath.Join(dir, "noise.static")
	b, err := os.ReadFile(path)
	if err == nil && len(b) == 32 {
		return b, nil
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

// sealedNoiseStatic keeps the KMS identity out of /tmp. A legacy plaintext
// file is read once, sealed, and removed.
func sealedNoiseStatic(dir string) ([]byte, error) {
	support, err := supportDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(support, "noise.static")
	key, err := AtRestKey()
	if err != nil {
		return nil, err
	}
	if plain, err := ReadSecret(path, key); err == nil && len(plain) == 32 {
		wipePlain(filepath.Join(dir, "noise.static"))
		return plain, nil
	}
	legacy := filepath.Join(dir, "noise.static")
	old, err := os.ReadFile(legacy)
	if err == nil && len(old) == 32 {
		if err := WriteSecret(path, key, old); err != nil {
			return nil, err
		}
		for i := range old {
			old[i] = 0
		}
		wipePlain(legacy)
		return ReadSecret(path, key)
	}
	fresh := make([]byte, 32)
	if _, err := rand.Read(fresh); err != nil {
		return nil, err
	}
	if err := WriteSecret(path, key, fresh); err != nil {
		return nil, err
	}
	return fresh, nil
}

func wipePlain(path string) {
	_ = os.WriteFile(path, make([]byte, 32), 0o600)
	_ = os.Remove(path)
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// Phone is the consensus signer whose private key stays on the phone.
type Phone struct{ L *Link }

func (p Phone) PubKey() []byte {
	b, err := p.L.PubKey()
	if err != nil {
		return nil
	}
	return b
}
func (p Phone) Scheme() config.Algorithm { return config.AlgoED25519 }
func (p Phone) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	return p.L.Sign(ctx, msg)
}
func (p Phone) Close() error { return nil }
