package takeoff

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	"google.golang.org/protobuf/types/known/anypb"
)

// GrantQR is the Zigner account-scan payload for one session grant.
// The phone's main scan authorizes it. The memo makes the phone return ur:cworch-sig.
func GrantQR(granter, grantee, chainID string, account, sequence uint64, now time.Time) ([]byte, []byte, error) {
	if !ValidAccount(granter) || !ValidAccount(grantee) {
		return nil, nil, fmt.Errorf("takeoff: granter and ephemeral account are required")
	}
	doc, err := aminoGrant(granter, grantee, chainID, account, sequence, now, nil, true)
	if err != nil {
		return nil, nil, err
	}
	payload := cosmosQR(doc)
	// Zigner hex-encodes the QR's raw bytes and looks for the prefix 530510.
	// A text QR of that hex is a different payload and the account scan ignores it.
	png, err := qrcode.Encode(string(payload), qrcode.Low, 640)
	if err != nil {
		return nil, nil, err
	}
	return png, doc, nil
}

func grantQR(granter, grantee, chainID string, account, sequence uint64, now time.Time, types []string, fee bool) ([]byte, []byte, error) {
	doc, err := aminoGrant(granter, grantee, chainID, account, sequence, now, types, fee)
	if err != nil {
		return nil, nil, err
	}
	png, err := qrcode.Encode(string(cosmosQR(doc)), qrcode.Low, 640)
	if err != nil {
		return nil, nil, err
	}
	return png, doc, nil
}

// Prepared is one authorization waiting for the phone's signature.
type Prepared struct {
	Amino    []byte
	Msgs     []*anypb.Any
	PNG      []byte
	Kind     string
	Granter  string
	Grantee  string
	Account  uint64
	Sequence uint64
}

// ID is the short hash of the exact bytes the phone signs.
func (p Prepared) ID() string {
	if len(p.Amino) == 0 {
		return ""
	}
	sum := sha256.Sum256(p.Amino)
	return hex.EncodeToString(sum[:4])
}

// Prepare builds the QR and the matching proto messages for the granter's current account.
func Prepare(ctx context.Context, rpc, granter, grantee, chainID string) ([]byte, Prepared, error) {
	acct, seq, err := account(ctx, rpc, granter)
	if err != nil {
		return nil, Prepared{}, err
	}
	missing, fee, err := Missing(ctx, rpc, granter, grantee)
	if err != nil {
		return nil, Prepared{}, err
	}
	if len(missing) == 0 && !fee {
		return nil, Prepared{
			Kind: "ready", Granter: granter, Grantee: grantee,
			Account: acct, Sequence: seq,
		}, nil
	}
	now := time.Now().UTC().Truncate(time.Second)
	png, doc, err := grantQR(granter, grantee, chainID, acct, seq, now, missing, fee)
	if err != nil {
		return nil, Prepared{}, err
	}
	msgs, err := grantsFor(granter, grantee, feeDenom, now, missing, fee)
	if err != nil {
		return nil, Prepared{}, err
	}
	kind := "grant"
	if !fee {
		kind = "omit-fee"
	}
	return png, Prepared{
		Amino: doc, Msgs: msgs, PNG: png, Kind: kind,
		Granter: granter, Grantee: grantee,
		Account: acct, Sequence: seq,
	}, nil
}

func aminoGrant(granter, grantee, chainID string, account, sequence uint64, now time.Time, types []string, fee bool) ([]byte, error) {
	if types == nil {
		types = SessionTypes()
		fee = true
	}
	exp := now.UTC().Truncate(time.Second).Add(sessionDuration).Format(time.RFC3339)
	var msgs []string
	for _, typeURL := range types {
		msgs = append(msgs, fmt.Sprintf(
			`{"type":"cosmos-sdk/MsgGrant","value":{"grant":{"authorization":{"type":"cosmos-sdk/GenericAuthorization","value":{"msg":%s}},"expiration":%s},"grantee":%s,"granter":%s}}`,
			jsonString(typeURL), jsonString(exp), jsonString(grantee), jsonString(granter),
		))
	}
	if fee {
		msgs = append(msgs, fmt.Sprintf(
			`{"type":"cosmos-sdk/MsgGrantAllowance","value":{"allowance":{"type":"cosmos-sdk/BasicAllowance","value":{"expiration":%s,"spend_limit":[{"amount":%s,"denom":%s}]}},"grantee":%s,"granter":%s}}`,
			jsonString(exp), jsonString(sessionSpendLimit), jsonString(feeDenom), jsonString(grantee), jsonString(granter),
		))
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("takeoff: nothing to grant")
	}
	doc := fmt.Sprintf(
		`{"account_number":%s,"chain_id":%s,"fee":{"amount":[{"amount":%s,"denom":%s}],"gas":%s},"memo":"cw-orch-session:v1","msgs":[%s],"sequence":%s}`,
		jsonString(fmt.Sprintf("%d", account)),
		jsonString(chainID),
		jsonString(grantTxFee),
		jsonString(feeDenom),
		jsonString("800000"),
		strings.Join(msgs, ","),
		jsonString(fmt.Sprintf("%d", sequence)),
	)
	return []byte(doc), nil
}

func cosmosQR(signDoc []byte) []byte {
	name := []byte("terp")
	out := []byte{0x53, 0x05, 0x10}
	var idx [4]byte
	out = append(out, idx[:]...)
	out = append(out, byte(len(name)))
	out = append(out, name...)
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(signDoc)))
	out = append(out, n[:]...)
	out = append(out, signDoc...)
	out = append(out, idx[:]...)
	return out
}

func jsonString(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range value {
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// StatusFrame is the block session the phone shows without signing a vote.
// 0x30 | height u64be | lag u64be | validator | chain | consensus address.
func StatusFrame(height uint64, lagMs int64, validator bool, chain, addr string) []byte {
	if lagMs < 0 {
		lagMs = 0
	}
	if len(chain) > 64 {
		chain = chain[:64]
	}
	if len(addr) > 64 {
		addr = addr[:64]
	}
	out := make([]byte, 0, 32+len(chain)+len(addr))
	out = append(out, 0x30)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], height)
	out = append(out, n[:]...)
	binary.BigEndian.PutUint64(n[:], uint64(lagMs))
	out = append(out, n[:]...)
	if validator {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	out = append(out, byte(len(chain)))
	out = append(out, chain...)
	out = append(out, byte(len(addr)))
	out = append(out, addr...)
	return out
}
