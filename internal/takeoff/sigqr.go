package takeoff

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SigQR is what the phone returned after signing a sign request.
//
// Zigner (rust/signer encode_cworch_signature, Android ScanViewModel) shows
// ur:cworch-sig when the amino memo starts with "cw-orch-": bytewords-minimal
// of 33-byte compressed pubkey || 64-byte compact r||s, CRC32 appended. It is
// one frame for 97 bytes, or fountain frames ur:cworch-sig/N-M/… when forced.
// Other Cosmos requests get a plain hex QR of the 64-byte signature only.
type SigQR struct {
	Pub    []byte // nil for a signature-only hex QR
	Sig    []byte
	Format string
}

// SigParts collects frames of one signature QR.
type SigParts struct {
	Done  *SigQR
	Have  int
	Need  int
	Error string
}

var multiRe = regexp.MustCompile(`^ur:cworch-sig/(\d+)-(\d+)/([a-z]+)$`)

// AssembleSigQR reads every frame seen so far. Multipart frames are joined
// from their pure fragments (zigner loops 1.3x the fragment count, so every
// pure fragment is shown). Progress is reported until all are present.
func AssembleSigQR(frames []string) SigParts {
	var (
		seqLen, msgLen int
		check          uint32
		got            = map[int][]byte{}
	)
	for _, raw := range frames {
		t := strings.ToLower(strings.TrimSpace(raw))
		if t == "" {
			continue
		}
		if m := multiRe.FindStringSubmatch(t); m != nil {
			n, l, data, cs, ml, err := decodePart(m[3])
			if err != nil {
				return SigParts{Error: err.Error()}
			}
			if seqLen != 0 && (l != seqLen || ml != msgLen || cs != check) {
				return SigParts{Error: "takeoff: frames from two different signature QRs; rescan"}
			}
			seqLen, msgLen, check = l, ml, cs
			if n >= 1 && n <= l {
				got[n] = data
			}
			continue
		}
		q, err := ParseSigQR(t)
		if err != nil {
			return SigParts{Error: err.Error()}
		}
		return SigParts{Done: &q, Have: 1, Need: 1}
	}
	if seqLen == 0 {
		return SigParts{Error: "takeoff: no signature frame"}
	}
	if len(got) < seqLen {
		return SigParts{Have: len(got), Need: seqLen}
	}
	var msg []byte
	for i := 1; i <= seqLen; i++ {
		msg = append(msg, got[i]...)
	}
	if len(msg) < msgLen {
		return SigParts{Error: "takeoff: signature frames are short"}
	}
	msg = msg[:msgLen]
	if crc32.ChecksumIEEE(msg) != check {
		return SigParts{Error: "takeoff: signature frames checksum"}
	}
	if len(msg) != 97 {
		return SigParts{Error: fmt.Sprintf("takeoff: signature QR is %d bytes", len(msg))}
	}
	return SigParts{Have: seqLen, Need: seqLen, Done: &SigQR{Pub: msg[:33], Sig: msg[33:], Format: fmt.Sprintf("ur:cworch-sig, %d frames", seqLen)}}
}

// ParseSigQR reads one single-frame signature QR.
func ParseSigQR(raw string) (SigQR, error) {
	t := strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(t), "ur:cworch-sig/") {
		pub, sig, err := DecodeCworch(t)
		if err != nil {
			return SigQR{}, err
		}
		return SigQR{Pub: pub, Sig: sig, Format: "ur:cworch-sig"}, nil
	}
	h := strings.TrimPrefix(strings.ToLower(t), "0x")
	b, err := hex.DecodeString(h)
	if err == nil {
		switch len(b) {
		case 64:
			return SigQR{Sig: b, Format: "hex signature (no pubkey)"}, nil
		case 97:
			return SigQR{Pub: b[:33], Sig: b[33:], Format: "hex pubkey+signature"}, nil
		}
	}
	return SigQR{}, fmt.Errorf("takeoff: not a zigner signature QR (expected ur:cworch-sig/…); it starts with %q", clip(t, 24))
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// decodePart reads the CBOR [seqNum, seqLen, messageLen, checksum, fragment].
func decodePart(words string) (n, l int, data []byte, check uint32, msgLen int, err error) {
	body, err := decodeMinimal(words)
	if err != nil {
		return
	}
	if len(body) < 5 {
		err = fmt.Errorf("takeoff: signature frame is short")
		return
	}
	cb, sum := body[:len(body)-4], body[len(body)-4:]
	if crc32.ChecksumIEEE(cb) != binary.BigEndian.Uint32(sum) {
		err = fmt.Errorf("takeoff: signature frame checksum")
		return
	}
	if cb[0] != 0x85 {
		err = fmt.Errorf("takeoff: signature frame is not a UR part")
		return
	}
	p := cb[1:]
	var vals [4]uint64
	for i := range vals {
		var v uint64
		v, p, err = cborUint(p, 0)
		if err != nil {
			return
		}
		vals[i] = v
	}
	var bl uint64
	bl, p, err = cborUint(p, 2)
	if err != nil {
		return
	}
	if uint64(len(p)) < bl {
		err = fmt.Errorf("takeoff: signature frame fragment")
		return
	}
	return int(vals[0]), int(vals[1]), p[:bl], uint32(vals[3]), int(vals[2]), nil
}

func cborUint(p []byte, major byte) (uint64, []byte, error) {
	if len(p) == 0 || p[0]>>5 != major {
		return 0, nil, fmt.Errorf("takeoff: signature frame cbor")
	}
	ai := p[0] & 31
	p = p[1:]
	switch {
	case ai < 24:
		return uint64(ai), p, nil
	case ai == 24 && len(p) >= 1:
		return uint64(p[0]), p[1:], nil
	case ai == 25 && len(p) >= 2:
		return uint64(binary.BigEndian.Uint16(p)), p[2:], nil
	case ai == 26 && len(p) >= 4:
		return uint64(binary.BigEndian.Uint32(p)), p[4:], nil
	case ai == 27 && len(p) >= 8:
		return binary.BigEndian.Uint64(p), p[8:], nil
	}
	return 0, nil, fmt.Errorf("takeoff: signature frame cbor")
}

// SigCheck is the verdict on one scanned signature.
type SigCheck struct {
	OK      bool   `json:"ok"`
	Format  string `json:"format"`
	Signer  string `json:"signer,omitempty"`
	AuthID  string `json:"auth_id"`
	Part    string `json:"mismatch,omitempty"` // key | account | sequence | chain | doc
	Reason  string `json:"reason,omitempty"`
	HighS   bool   `json:"high_s,omitempty"`
	Pub     []byte `json:"-"`
	NormSig []byte `json:"-"`
}

var (
	reSeq   = regexp.MustCompile(`"sequence":"\d+"`)
	reAcct  = regexp.MustCompile(`"account_number":"\d+"`)
	reChain = regexp.MustCompile(`"chain_id":"[^"]*"`)
)

// CheckSignature verifies q against the exact amino bytes in cur under the
// owner's key. On failure it says which part did not match: the signing key,
// an older QR (listed in prev), the sequence, account number or chain id, or
// otherwise the document itself.
func CheckSignature(q SigQR, owner []byte, granter string, cur Prepared, chainID string, prev []Prepared) SigCheck {
	out := SigCheck{Format: q.Format, AuthID: cur.ID()}
	pub := q.Pub
	if pub == nil {
		pub = owner
	}
	if len(pub) != 33 {
		out.Part, out.Reason = "key", "this signature QR has no public key and the owner key is unknown; scan the owner account first"
		return out
	}
	addr, _ := bech32Encode("terp", secpAddr(pub))
	out.Signer = addr
	if addr != granter {
		out.Part, out.Reason = "key", fmt.Sprintf("signed by %s, not the owner %s. Pick the owner key on zigner.", addr, granter)
		return out
	}
	if owner != nil && len(owner) == 33 && !bytesEqual(owner, pub) {
		out.Part, out.Reason = "key", "the QR's public key differs from the owner key on file"
		return out
	}
	norm, high, err := NormalizeSig(q.Sig)
	if err != nil {
		out.Part, out.Reason = "signature", err.Error()
		return out
	}
	out.HighS = high
	if verifyAmino(pub, norm, cur.Amino) {
		out.OK, out.Pub, out.NormSig = true, pub, norm
		return out
	}
	for i := len(prev) - 1; i >= 0; i-- {
		p := prev[i]
		if len(p.Amino) == 0 || !verifyAmino(pub, norm, p.Amino) {
			continue
		}
		var why []string
		if p.Sequence != cur.Sequence {
			why = append(why, fmt.Sprintf("sequence %d, chain is now at %d", p.Sequence, cur.Sequence))
		}
		if p.Account != cur.Account {
			why = append(why, fmt.Sprintf("account number %d, now %d", p.Account, cur.Account))
		}
		part := "sequence"
		if len(why) == 0 {
			part = "doc"
			why = append(why, "an expired QR")
		}
		out.Part = part
		out.Reason = fmt.Sprintf("this signs older QR %s (%s). Scan the QR shown now (%s) and sign again.", p.ID(), strings.Join(why, "; "), cur.ID())
		return out
	}
	doc := string(cur.Amino)
	for d := -5; d <= 5; d++ {
		s := int64(cur.Sequence) + int64(d)
		if d == 0 || s < 0 {
			continue
		}
		if verifyAmino(pub, norm, []byte(reSeq.ReplaceAllString(doc, `"sequence":"`+strconv.FormatInt(s, 10)+`"`))) {
			out.Part, out.Reason = "sequence", fmt.Sprintf("signed for sequence %d, the account is at %d. Scan the current QR.", s, cur.Sequence)
			return out
		}
	}
	for _, c := range []string{"", "morocco-1", "90u-4", "terp-1", "120u-1"} {
		if c == chainID {
			continue
		}
		if verifyAmino(pub, norm, []byte(reChain.ReplaceAllString(doc, `"chain_id":"`+c+`"`))) {
			out.Part, out.Reason = "chain", fmt.Sprintf("signed for chain %q, this validator is on %q", c, chainID)
			return out
		}
	}
	if verifyAmino(pub, norm, []byte(reAcct.ReplaceAllString(doc, `"account_number":"0"`))) {
		out.Part, out.Reason = "account", fmt.Sprintf("signed with account number 0, the owner account is %d", cur.Account)
		return out
	}
	out.Part, out.Reason = "doc", fmt.Sprintf("the owner key signed something else, not QR %s (different messages, fee, memo, or expiry). Scan the QR shown now and sign again.", cur.ID())
	return out
}

// AccountOfPub is the terp1 address of a compressed secp256k1 key.
func AccountOfPub(pub []byte) string {
	a, _ := bech32Encode("terp", secpAddr(pub))
	return a
}

// PrepareFor builds the sign QR for known account numbers, without RPC.
func PrepareFor(granter, grantee, chainID string, acct, seq uint64, types []string, now time.Time) (Prepared, error) {
	_, p, err := prepareFrom(granter, grantee, chainID, acct, seq, types, true, now)
	return p, err
}

// EncodeCworchForTest is zigner's single-frame ur:cworch-sig for pub||sig.
func EncodeCworchForTest(pub, sig []byte) string {
	return "ur:cworch-sig/" + encodeMinimal(append(append([]byte(nil), pub...), sig...))
}
