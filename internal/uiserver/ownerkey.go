package uiserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/cosmos/kms/internal/takeoff"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // cosmos account addresses are ripemd160(sha256(pub))
)

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(v []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, b := range v {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(b)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for _, c := range hrp {
		out = append(out, byte(c)>>5)
	}
	out = append(out, 0)
	for _, c := range hrp {
		out = append(out, byte(c)&31)
	}
	return out
}

func convertBits(in []byte, from, to uint, pad bool) ([]byte, error) {
	var acc, bits uint
	var out []byte
	maxv := uint(1)<<to - 1
	for _, b := range in {
		acc = acc<<from | uint(b)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv))
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, errors.New("bad padding")
	}
	return out, nil
}

// bech32Encode encodes data bytes under hrp (BIP-173).
func bech32Encode(hrp string, data []byte) string {
	d, _ := convertBits(data, 8, 5, true)
	v := append(hrpExpand(hrp), d...)
	pm := bech32Polymod(append(v, 0, 0, 0, 0, 0, 0)) ^ 1
	var sb strings.Builder
	sb.WriteString(hrp + "1")
	for _, x := range d {
		sb.WriteByte(bech32Charset[x])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(bech32Charset[(pm>>uint(5*(5-i)))&31])
	}
	return sb.String()
}

// AccountAddress is the terp1… address of a compressed secp256k1 pubkey.
func AccountAddress(pub []byte) string {
	h := sha256.Sum256(pub)
	r := ripemd160.New()
	r.Write(h[:])
	return bech32Encode("terp", r.Sum(nil))
}

var (
	reAddr = regexp.MustCompile(`terp1[02-9ac-hj-np-z]{38}`)
	reHex  = regexp.MustCompile(`\b0[23][0-9a-fA-F]{64}\b`)
	reB64  = regexp.MustCompile(`A[A-Za-z0-9+/]{43}`)
)

var reZignerAddr = regexp.MustCompile(`^(?:cosmos|substrate):(terp1[02-9ac-hj-np-z]{38}):0x[0-9a-fA-F]{64}$`)

// OwnerQR is what an account QR carried.
type OwnerQR struct {
	Pub    []byte
	Addr   string
	Format string
}

// ParseOwnerQR reads an account QR. Formats, in order:
//   - zigner key-details address QR: "cosmos:<terp1…>:0x<genesis hash>" (address only)
//   - zigner cosmos export JSON: {"type":"cosmos-accounts","public_key":"<hex>",…}
//   - a compressed secp256k1 pubkey, hex or base64, bare, amino JSON or in a URI
//   - a bare terp1… address (address only)
//
// Address-only results have Pub == nil; the caller fetches the key from chain.
func ParseOwnerQR(s string) (OwnerQR, error) {
	s = strings.TrimSpace(s)
	if m := reZignerAddr.FindStringSubmatch(s); m != nil {
		if !takeoff.ValidAccount(m[1]) {
			return OwnerQR{}, errors.New("the QR's terp1 address has a bad checksum")
		}
		return OwnerQR{Addr: m[1], Format: "zigner address (cosmos:addr:genesis)"}, nil
	}
	var exp struct {
		Type      string `json:"type"`
		PublicKey string `json:"public_key"`
	}
	if strings.HasPrefix(s, "{") && json.Unmarshal([]byte(s), &exp) == nil && exp.Type == "cosmos-accounts" {
		b, err := hex.DecodeString(exp.PublicKey)
		if err != nil || len(b) != 33 || (b[0] != 2 && b[0] != 3) {
			return OwnerQR{}, errors.New("zigner export has no 33-byte compressed public_key")
		}
		return OwnerQR{Pub: b, Addr: AccountAddress(b), Format: "zigner cosmos-accounts export"}, nil
	}
	q := OwnerQR{Addr: reAddr.FindString(s)}
	if q.Addr != "" && !takeoff.ValidAccount(q.Addr) {
		return OwnerQR{}, errors.New("the QR's terp1 address has a bad checksum")
	}
	if m := reHex.FindString(s); m != "" {
		q.Pub, _ = hex.DecodeString(m)
		q.Format = "pubkey (hex)"
	} else {
		for _, m := range reB64.FindAllString(s, -1) {
			if b, e := base64.StdEncoding.DecodeString(m); e == nil && len(b) == 33 && (b[0] == 2 || b[0] == 3) {
				q.Pub, q.Format = b, "pubkey (base64)"
				break
			}
		}
	}
	if q.Pub == nil {
		if q.Addr == "" {
			return OwnerQR{}, errors.New("no terp1 address or secp256k1 pubkey in the QR")
		}
		q.Format = "address only"
	}
	return q, nil
}

// accountPubKey is swapped in tests.
var accountPubKey = takeoff.AccountPubKey

// ownerPubkey checks a scanned owner-account QR against the granter address.
func (s *Server) ownerPubkey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID      string `json:"id"`
		Granter string `json:"granter"`
		QR      string `json:"qr"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	q, err := ParseOwnerQR(body.QR)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	granter := strings.TrimSpace(body.Granter)
	if granter == "" {
		granter = q.Addr
	}
	if q.Pub != nil {
		if d := AccountAddress(q.Pub); q.Addr != "" && q.Addr != d {
			http.Error(w, "the QR's address "+q.Addr+" does not match its pubkey ("+d+")", http.StatusUnprocessableEntity)
			return
		}
	}
	if granter != q.Addr && q.Addr != "" {
		http.Error(w, "the QR is for "+q.Addr+", not the owner account "+granter, http.StatusUnprocessableEntity)
		return
	}
	if bound, ok := s.ownerStore().get(body.ID); ok && bound.Granter != "" {
		scanned := q.Addr
		if scanned == "" && q.Pub != nil {
			scanned = AccountAddress(q.Pub)
		}
		if scanned != "" && scanned != bound.Granter && strings.TrimSpace(body.Granter) == bound.Granter {
			http.Error(w, "this slot's owner is "+bound.Granter+"; the scanned account is "+scanned+". Clear the owner first to bind another.", http.StatusUnprocessableEntity)
			return
		}
	}
	source := "qr"
	if q.Pub == nil {
		rpc, _, ok := s.tabTarget(body.ID)
		if !ok {
			http.Error(w, "address-only QR: this tab has no rpc to look up the account's pubkey", http.StatusUnprocessableEntity)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		pub, err := accountPubKey(ctx, rpc, q.Addr)
		cancel()
		if err != nil && !errors.Is(err, takeoff.ErrAccountMissing) {
			http.Error(w, "account lookup failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		if pub == nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"address": q.Addr, "format": q.Format, "pubkey_hex": "",
				"note": "address accepted, but the chain has no public key for it yet: an account only publishes its key with its first signed transaction. Show zigner's public key QR (Export) instead, or sign any transaction with this account once.",
			})
			return
		}
		if AccountAddress(pub) != q.Addr {
			http.Error(w, "the chain's pubkey for "+q.Addr+" derives a different address", http.StatusBadGateway)
			return
		}
		q.Pub, source = pub, "chain"
	}
	pub, derived := q.Pub, AccountAddress(q.Pub)
	if granter != "" && granter != derived {
		http.Error(w, "pubkey belongs to "+derived+", not the owner account "+granter, http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"address":    derived,
		"format":     q.Format,
		"source":     source,
		"pubkey_hex": hex.EncodeToString(pub),
		"pubkey_b64": base64.StdEncoding.EncodeToString(pub),
	})
}
