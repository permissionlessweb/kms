package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/log"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
	"github.com/spf13/cobra"

	"github.com/cosmos/kms/internal/manager"
	"github.com/cosmos/kms/internal/signer"
	"github.com/cosmos/kms/internal/uiserver"
	"github.com/cosmos/kms/signing/bluetooth"
)

func init() {
	rootExtra = append(rootExtra, consoleCmd)
}

var rootExtra []func() *cobra.Command

func consoleCmd() *cobra.Command {
	var httpAddr, nodeURL, dial, chainID, stateFile, exportKey, granter string
	cmd := &cobra.Command{
		Use:   "console",
		Short: "Serve the Bluetooth signer page for the temporary test chain",
		RunE: func(_ *cobra.Command, _ []string) error {
			srv, err := uiserver.New(httpAddr, nodeURL)
			if err != nil {
				return err
			}
			defer srv.Close()
			fmt.Printf("zcinti http://%s\ntemporary chain %s node %s\nlive Morocco KMS is not this process\n", srv.Addr(), chainID, nodeURL)
			srv.SetChain(chainID)
			if err := srv.SetExportKey(exportKey); err != nil {
				fmt.Println("export key:", err)
			}
			srv.SetGranter(granter)
			if err := srv.Resume(); err != nil {
				fmt.Println("scanner:", err)
			}
			go armDialer(dial, chainID, stateFile)
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			<-sig
			return nil
		},
	}
	cmd.Flags().StringVar(&httpAddr, "http", "127.0.0.1:8791", "console listen address")
	cmd.Flags().StringVar(&nodeURL, "node", "http://127.0.0.1:26757", "RPC of the temporary test node")
	cmd.Flags().StringVar(&dial, "dial", "tcp://127.0.0.1:27159", "privval listener of the temporary test node")
	cmd.Flags().StringVar(&chainID, "chain-id", "morocco-1", "chain id the temporary node sends on its privval socket")
	cmd.Flags().StringVar(&stateFile, "state", "/tmp/kms-ble-console/state.json", "double-sign floor for the temporary chain")
	cmd.Flags().StringVar(&exportKey, "export-key", "", "consensus key file this console may send to the phone over Noise")
	cmd.Flags().StringVar(&granter, "granter", "", "offline account that signs the authz and feegrant for takeoff")
	return cmd
}

// hrsPV stamps the height onto the phone request, then lets FilePV sign.
type hrsPV struct {
	inner types.PrivValidator
	link  *bluetooth.Link
}

func (p *hrsPV) GetPubKey() (crypto.PubKey, error) { return p.inner.GetPubKey() }

func (p *hrsPV) SignVote(chainID string, vote *cmtproto.Vote) error {
	step := uint8(2)
	if vote.Type == cmtproto.PrecommitType {
		step = 3
	}
	p.link.SetHRS(uint64(vote.Height), uint32(vote.Round), step)
	return p.inner.SignVote(chainID, vote)
}

func (p *hrsPV) SignProposal(chainID string, proposal *cmtproto.Proposal) error {
	p.link.SetHRS(uint64(proposal.Height), uint32(proposal.Round), 1)
	return p.inner.SignProposal(chainID, proposal)
}

// armDialer waits until the cutover marker, the phone public key, and the
// sign-state file are all present, then dials the temporary node.
func armDialer(dial, chainID, stateFile string) {
	link := bluetooth.DefaultLink()
	for {
		if _, err := os.Stat(filepath.Join(bluetooth.Dir, "arm")); err != nil {
			time.Sleep(300 * time.Millisecond)
			continue
		}
		pub, err := link.PubKey()
		if err != nil || len(pub) != 32 {
			time.Sleep(300 * time.Millisecond)
			continue
		}
		if _, err := os.Stat(stateFile); err != nil {
			fmt.Println("waiting for temporary-chain sign state", stateFile)
			time.Sleep(300 * time.Millisecond)
			continue
		}
		cs, err := signer.NewChainSigner(chainID, bluetooth.Phone{L: link}, stateFile, false)
		if err != nil {
			fmt.Println("temporary chain signer:", err)
			time.Sleep(time.Second)
			continue
		}
		logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout))
		mgr := manager.New(logger, []manager.ValidatorConn{{
			ChainID:           chainID,
			Addr:              dial,
			IdentityKey:       ed25519.GenPrivKey(),
			Signer:            &hrsPV{inner: cs, link: link},
			Reconnect:         true,
			UseRequestChainID: true,
		}})
		if err := mgr.Start(); err != nil {
			fmt.Println("dialer:", err)
			return
		}
		fmt.Printf("dialing temporary chain %s at %s\n", chainID, dial)
		return
	}
}
