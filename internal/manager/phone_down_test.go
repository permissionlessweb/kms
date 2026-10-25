package manager

import (
	"crypto/ed25519"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/protoio"
	privvalproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	"github.com/cosmos/kms/internal/signer"
	"github.com/cosmos/kms/signing/bluetooth"
)

// A phone that is down must not stall the node: the sign request gets an
// error reply in well under a second, the connection stays up, pings keep
// working, and the double-sign floor does not move.
func TestPhoneDownAnswersFastAndKeepsConn(t *testing.T) {
	dir := t.TempDir()
	link := bluetooth.Open(filepath.Join(dir, "ble"))
	pub, _, _ := ed25519.GenerateKey(nil)
	kl, err := link.ForKey("k", pub)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state.json")
	cs, err := signer.NewChainSigner("test-1", kl, state, true)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(state)
	if len(before) == 0 {
		t.Fatal("no sign state written")
	}

	node, kms := net.Pipe()
	defer node.Close()
	m := New(log.NewNopLogger(), nil)
	go m.handleConnection(kms, ValidatorConn{ChainID: "test-1", Signer: cs}, log.NewNopLogger())
	defer m.Stop()

	w := protoio.NewDelimitedWriter(node)
	r := protoio.NewDelimitedReader(node, maxRemoteSignerMsgSize)
	roundTrip := func(req privvalproto.Message) (privvalproto.Message, time.Duration) {
		t.Helper()
		start := time.Now()
		_ = node.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := w.WriteMsg(&req); err != nil {
			t.Fatalf("write: %v", err)
		}
		var resp privvalproto.Message
		if _, err := r.ReadMsg(&resp); err != nil {
			t.Fatalf("read (connection dropped?): %v", err)
		}
		return resp, time.Since(start)
	}
	vote := func(h int64) privvalproto.Message {
		return privvalproto.Message{Sum: &privvalproto.Message_SignVoteRequest{SignVoteRequest: &privvalproto.SignVoteRequest{
			ChainId: "test-1",
			Vote:    &cmtproto.Vote{Type: cmtproto.PrevoteType, Height: h, Round: 0, ValidatorAddress: make([]byte, 20)},
		}}}
	}
	ping := privvalproto.Message{Sum: &privvalproto.Message_PingRequest{PingRequest: &privvalproto.PingRequest{}}}

	for i, h := range []int64{100, 100, 101} {
		resp, d := roundTrip(vote(h))
		sv := resp.GetSignedVoteResponse()
		if sv == nil || sv.Error == nil {
			t.Fatalf("vote %d: want signer error reply, got %+v", i, resp)
		}
		if d > time.Second {
			t.Fatalf("vote %d took %v", i, d)
		}
		if resp, d := roundTrip(ping); resp.GetPingResponse() == nil || d > 200*time.Millisecond {
			t.Fatalf("ping after vote %d: %+v in %v", i, resp, d)
		}
	}
	after, _ := os.ReadFile(state)
	if string(before) != string(after) {
		t.Fatalf("sign state moved on error:\n%s\n%s", before, after)
	}
}
