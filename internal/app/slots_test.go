package app_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/internal/app"
	"github.com/cosmos/kms/signing"
	"github.com/cosmos/kms/signing/file"
)

type countingPV struct {
	types.PrivValidator
	n *int
}

func (c countingPV) SignVote(id string, v *cmtproto.Vote) error {
	*c.n++
	return c.PrivValidator.SignVote(id, v)
}

// Two keys on one network, each in its own slot with its own sign-state,
// served by one engine (the console's multi-tab layout).
func TestBuildWithTwoSlotsOneNetwork(t *testing.T) {
	const network = "morocco-1"
	logger := log.TestingLogger()
	home := t.TempDir()
	var vals []config.Validator
	var keys []config.Key
	var eps []*privval.SignerListenerEndpoint
	for _, slot := range []string{"a", "b"} {
		d := filepath.Join(home, slot)
		require.NoError(t, os.MkdirAll(d, 0o700))
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		ep := startListener(t, logger, ln)
		t.Cleanup(func() { _ = ep.Stop() })
		eps = append(eps, ep)
		vals = append(vals, config.Validator{ChainID: network + "/" + slot, Addr: "tcp://" + ln.Addr().String(), IdentityKey: filepath.Join(d, "id.json")})
		keys = append(keys, config.Key{ChainIDs: []string{network + "/" + slot}, Backend: config.BackendFile, Algorithm: config.AlgoED25519, FileConfig: config.FileConfig{KeyFile: writeKey(t, d)}})
	}
	c := &config.Config{
		Chains:     []config.Chain{{ID: network + "/a", Network: network}, {ID: network + "/b", Network: network}},
		Validators: vals,
		Keys:       keys,
	}
	require.NoError(t, c.Validate(home))
	hooked, wrapped := 0, map[string]bool{}
	signs := 0
	mgr, cleanup, err := app.BuildWith(c, []string{network + "/a", network + "/b"}, logger, app.Options{
		Signer: func(k config.Key) (signing.Signer, bool, error) {
			hooked++
			s, err := file.LoadEd25519(k.KeyFile)
			return s, true, err
		},
		Wrap: func(slot string, _ config.Key, pv types.PrivValidator) types.PrivValidator {
			wrapped[slot] = true
			return countingPV{pv, &signs}
		},
	})
	require.NoError(t, err)
	t.Cleanup(cleanup)
	require.Equal(t, 2, hooked)
	require.Len(t, wrapped, 2)
	require.NoError(t, mgr.Start())
	defer mgr.Stop()

	var clients []*privval.SignerClient
	for _, ep := range eps {
		cl, err := privval.NewSignerClient(ep, network)
		require.NoError(t, err)
		require.NoError(t, cl.WaitForConnection(5*time.Second))
		clients = append(clients, cl)
	}
	pa, _ := clients[0].GetPubKey()
	pb, _ := clients[1].GetPubKey()
	require.NotEqual(t, pa.Address(), pb.Address())

	va := &cmtproto.Vote{Type: cmtproto.PrevoteType, Height: 50}
	require.NoError(t, clients[0].SignVote(network, va))
	require.True(t, pa.VerifySignature(types.VoteSignBytes(network, va), va.Signature))
	// Slot b's floor is independent of a's.
	vb := &cmtproto.Vote{Type: cmtproto.PrevoteType, Height: 10}
	require.NoError(t, clients[1].SignVote(network, vb))
	// Slot a still refuses its own lower height.
	require.Error(t, clients[0].SignVote(network, &cmtproto.Vote{Type: cmtproto.PrevoteType, Height: 49}))
	require.GreaterOrEqual(t, signs, 2)
}
