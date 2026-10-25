package takeoff

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"strings"
	"testing"
	"time"

	dcrsecp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// zignerSign is what zigner's sign_cosmos_amino does: RFC6979 ECDSA over
// SHA256(amino JSON), compact r||s (rust secp256k1 emits low-S).
func zignerSign(priv *dcrsecp.PrivateKey, doc []byte) []byte {
	h := sha256.Sum256(doc)
	c := dcrecdsa.SignCompact(priv, h[:], true)
	return append([]byte(nil), c[1:]...)
}

// zignerSingle is encode_cworch_signature with max_fragment_len 0.
func zignerSingle(pub, sig []byte) string {
	return "ur:cworch-sig/" + encodeMinimal(append(append([]byte(nil), pub...), sig...))
}

// zignerMulti mirrors ur-rs Encoder pure parts: CBOR [seq, len, msgLen, crc, frag].
func zignerMulti(payload []byte, frag int) []string {
	n := (len(payload) + frag - 1) / frag
	sum := crc32.ChecksumIEEE(payload)
	var out []string
	for i := 1; i <= n; i++ {
		f := make([]byte, frag)
		copy(f, payload[(i-1)*frag:])
		cb := []byte{0x85}
		cb = append(cb, cu(0, uint64(i))...)
		cb = append(cb, cu(0, uint64(n))...)
		cb = append(cb, cu(0, uint64(len(payload)))...)
		cb = append(cb, cu(0, uint64(sum))...)
		cb = append(cb, cu(2, uint64(frag))...)
		cb = append(cb, f...)
		out = append(out, fmt.Sprintf("ur:cworch-sig/%d-%d/%s", i, n, encodeMinimal(cb)))
	}
	return out
}

func cu(major byte, v uint64) []byte {
	m := major << 5
	switch {
	case v < 24:
		return []byte{m | byte(v)}
	case v < 256:
		return []byte{m | 24, byte(v)}
	case v < 65536:
		b := []byte{m | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(v))
		return b
	}
	b := []byte{m | 26, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(v))
	return b
}

func testOwner() (*dcrsecp.PrivateKey, []byte, string) {
	k, _ := hex.DecodeString("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
	priv := dcrsecp.PrivKeyFromBytes(k)
	pub := priv.PubKey().SerializeCompressed()
	return priv, pub, AccountOfPub(pub)
}

var testNow = time.Date(2026, 10, 24, 21, 0, 0, 0, time.UTC)

func testPrepared(t *testing.T, granter string, seq uint64) Prepared {
	t.Helper()
	p, err := PrepareFor(granter, "terp1fel0j4hevv2wy3actfdrl23emm8tl6x44z2qfw", "morocco-1", 7, seq, []string{unjailURL, revokeAuthzURL, revokeAllowanceURL}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Pinned derived vector: the exact frame zigner shows for this key and doc.
func TestZignerSignatureVector(t *testing.T) {
	priv, pub, granter := testOwner()
	p := testPrepared(t, granter, 3)
	if !strings.Contains(string(p.Amino), `"memo":"cw-orch-session:v1"`) || !strings.Contains(string(p.Amino), `"chain_id":"morocco-1"`) ||
		!strings.Contains(string(p.Amino), `"account_number":"7"`) || !strings.Contains(string(p.Amino), `"sequence":"3"`) {
		t.Fatalf("sign doc must carry the cw-orch memo, chain, account and sequence: %s", p.Amino)
	}
	sig := zignerSign(priv, p.Amino)
	frame := zignerSingle(pub, sig)
	t.Logf("granter %s auth %s\nframe %s", granter, p.ID(), frame)
	const golden = "ur:cworch-sig/aohejschoslygdzedmytkirltkspfrtlkgdmdwbtbttdhypefgkngecedrfetobblnbbplhnkgpflphlmnltvssbyleejswtnyethlhtrkpteetavwotbnwdnntblydibbkspdgrmtwevydiiswydrzshniopdadclenlgvwwecfndnewyhnidfpykplflgebnnlrhpkde"
	if granter != "terp1sqczdzsyfzry02duvj50t0cucmdj05cqj6sk68" || p.ID() != "b6cd2929" || frame != golden {
		t.Fatalf("vector drifted: %s %s %s", granter, p.ID(), frame)
	}
	if len(frame) > 1200 {
		t.Fatal("zigner shows one frame up to 1200 chars")
	}
	r := AssembleSigQR([]string{frame})
	if r.Done == nil || r.Done.Format != "ur:cworch-sig" {
		t.Fatalf("%+v", r)
	}
	c := CheckSignature(*r.Done, pub, granter, p, "morocco-1", nil)
	if !c.OK || c.Signer != granter || c.AuthID != p.ID() {
		t.Fatalf("%+v", c)
	}
	// Uppercase (QR alphanumeric mode) is the same frame.
	if r := AssembleSigQR([]string{strings.ToUpper(frame)}); r.Done == nil {
		t.Fatal("uppercase frame")
	}
}

func TestZignerMultipartFrames(t *testing.T) {
	priv, pub, granter := testOwner()
	p := testPrepared(t, granter, 3)
	payload := append(append([]byte(nil), pub...), zignerSign(priv, p.Amino)...)
	parts := zignerMulti(payload, 40)
	if len(parts) != 3 {
		t.Fatalf("want 3 parts, got %d", len(parts))
	}
	r := AssembleSigQR([]string{parts[0], parts[2], parts[0]})
	if r.Done != nil || r.Have != 2 || r.Need != 3 {
		t.Fatalf("progress: %+v", r)
	}
	r = AssembleSigQR([]string{parts[2], parts[0], parts[1]})
	if r.Done == nil || !CheckSignature(*r.Done, nil, granter, p, "morocco-1", nil).OK {
		t.Fatalf("assembled: %+v", r)
	}
	other := zignerMulti(append([]byte{1}, payload[1:]...), 50)
	if r := AssembleSigQR([]string{parts[0], other[1]}); r.Error == "" {
		t.Fatal("frames from two QRs must be refused")
	}
	bad := parts[1][:len(parts[1])-2] + "ae"
	if r := AssembleSigQR([]string{bad}); r.Error == "" {
		t.Fatal("bad frame checksum")
	}
}

func TestSignatureOnlyHexUsesOwnerKey(t *testing.T) {
	priv, pub, granter := testOwner()
	p := testPrepared(t, granter, 3)
	q, err := ParseSigQR(hex.EncodeToString(zignerSign(priv, p.Amino)))
	if err != nil || q.Pub != nil {
		t.Fatal(err)
	}
	if c := CheckSignature(q, pub, granter, p, "morocco-1", nil); !c.OK {
		t.Fatalf("%+v", c)
	}
	if c := CheckSignature(q, nil, granter, p, "morocco-1", nil); c.OK || c.Part != "key" {
		t.Fatalf("no owner key: %+v", c)
	}
	if _, err := ParseSigQR("cosmos:terp1abc:0x00"); err == nil {
		t.Fatal("an account QR is not a signature")
	}
}

func TestSignatureMismatchReasons(t *testing.T) {
	priv, pub, granter := testOwner()
	cur := testPrepared(t, granter, 3)
	sign := func(doc []byte) SigQR { return SigQR{Pub: pub, Sig: zignerSign(priv, doc), Format: "ur:cworch-sig"} }
	check := func(q SigQR, prev ...Prepared) SigCheck {
		return CheckSignature(q, pub, granter, cur, "morocco-1", prev)
	}

	other, _ := dcrsecp.GeneratePrivateKey()
	op := other.PubKey().SerializeCompressed()
	if c := CheckSignature(SigQR{Pub: op, Sig: zignerSign(other, cur.Amino)}, pub, granter, cur, "morocco-1", nil); c.Part != "key" || !strings.Contains(c.Reason, "not the owner") {
		t.Fatalf("wrong key: %+v", c)
	}
	old := testPrepared(t, granter, 2)
	if c := check(sign(old.Amino), old); c.Part != "sequence" || !strings.Contains(c.Reason, "sequence 2, chain is now at 3") {
		t.Fatalf("older QR: %+v", c)
	}
	if c := check(sign(old.Amino)); c.Part != "sequence" || !strings.Contains(c.Reason, "signed for sequence 2") {
		t.Fatalf("sequence: %+v", c)
	}
	if c := check(sign([]byte(strings.Replace(string(cur.Amino), `"chain_id":"morocco-1"`, `"chain_id":"90u-4"`, 1)))); c.Part != "chain" {
		t.Fatalf("chain: %+v", c)
	}
	if c := check(sign([]byte(strings.Replace(string(cur.Amino), `"account_number":"7"`, `"account_number":"0"`, 1)))); c.Part != "account" {
		t.Fatalf("account: %+v", c)
	}
	if c := check(sign([]byte(strings.Replace(string(cur.Amino), `"cw-orch-session:v1"`, `""`, 1)))); c.Part != "doc" {
		t.Fatalf("doc: %+v", c)
	}
	// High-S from a non-normalizing signer still verifies (normalized).
	s := zignerSign(priv, cur.Amino)
	var sv dcrsecp.ModNScalar
	sv.SetByteSlice(s[32:])
	sv.Negate()
	hb := sv.Bytes()
	hs := append(append([]byte(nil), s[:32]...), hb[:]...)
	if c := check(SigQR{Pub: pub, Sig: hs}); !c.OK || !c.HighS {
		t.Fatalf("high-S: %+v", c)
	}
}
