package takeoff

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

func TestGrantQRUsesTheZignerAccountScan(t *testing.T) {
	granter, err := bech32Encode("terp", bytes20(0x03))
	if err != nil {
		t.Fatal(err)
	}
	grantee, err := bech32Encode("terp", bytes20(0x04))
	if err != nil {
		t.Fatal(err)
	}
	png, doc, err := GrantQR(granter, grantee, "morocco-1", 7, 1, time.Unix(1_700_000_000, 0).UTC())
	if err != nil || len(png) < 8 || string(png[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatal(err, len(png))
	}
	if !bytes.Contains(doc, []byte("cw-orch-session:v1")) || !bytes.Contains(doc, []byte(createURL)) || !bytes.Contains(doc, []byte("MsgGrantAllowance")) {
		t.Fatalf("doc %s", doc)
	}
	if !bytes.Contains(doc, []byte(`"amount":"`+AminoFee()+`"`)) {
		t.Fatal("signed fee is not the broadcast fee")
	}
	limit, one := new(big.Int), new(big.Int)
	limit.SetString(sessionSpendLimit, 10)
	one.SetString(actionFee, 10)
	if limit.Cmp(new(big.Int).Mul(one, big.NewInt(2))) < 0 {
		t.Fatal("feegrant does not cover create and revoke")
	}
	raw := cosmosQR(doc)
	if !bytes.HasPrefix(raw, []byte{0x53, 0x05, 0x10}) {
		t.Fatal(raw[:3])
	}
	if bytes.Contains(png, []byte("530510")) {
		t.Fatal("the image must carry the raw request, not the hex text")
	}
	doc, err = aminoGrant(granter, grantee, "morocco-1", 7, 1, time.Unix(1_700_000_000, 0).UTC(), []string{createURL}, false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(doc, []byte("MsgGrantAllowance")) || !bytes.Contains(doc, []byte(createURL)) {
		t.Fatal("existing feegrant must be omitted")
	}
}

func TestStatusFrameCarriesHeightWithoutASignature(t *testing.T) {
	frame := StatusFrame(24032900, 1500, false, "morocco-1", "E7353DEE")
	if frame[0] != 0x30 || binary.BigEndian.Uint64(frame[1:9]) != 24032900 || frame[17] != 0 {
		t.Fatal(frame)
	}
}

func TestCworchRoundTrip(t *testing.T) {
	pub := bytes32(0x02)
	pub = append([]byte{0x02}, pub...)
	sig := bytesN(64, 0x05)
	payload := append(append([]byte{}, pub...), sig...)
	ur := "ur:cworch-sig/" + encodeMinimal(payload)
	gotPub, gotSig, err := DecodeCworch(ur)
	if err != nil || !bytes.Equal(gotPub, pub) || !bytes.Equal(gotSig, sig) {
		t.Fatal(err, len(gotPub), len(gotSig))
	}
}
