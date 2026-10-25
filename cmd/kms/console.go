package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/cosmos/kms/internal/uiserver"
	"github.com/cosmos/kms/signing/bluetooth"
)

func init() {
	rootExtra = append(rootExtra, consoleCmd)
}

var rootExtra []func() *cobra.Command

func consoleCmd() *cobra.Command {
	var httpAddr, nodeURL, dial, chainID, granter string
	var replace, readOnly bool
	var configs []string
	var engine, bleDir string
	cmd := &cobra.Command{
		Use:   "console",
		Short: "Serve the Bluetooth signer page for the temporary test chain",
		RunE: func(_ *cobra.Command, _ []string) error {
			if bleDir != "" {
				bluetooth.Dir = bleDir
			}
			if readOnly && engine != "" {
				return fmt.Errorf("--read-only never runs the engine; drop --engine")
			}
			if !readOnly && engine == "" {
				return fmt.Errorf("--engine is required (the single-chain console was removed); use --read-only to preview")
			}
			srv, err := uiserver.New(httpAddr, nodeURL, replace)
			if err != nil {
				return err
			}
			defer srv.Close()
			srv.EnableToken()
			srv.SetReadOnly(readOnly)
			fmt.Printf("zcinti http://%s\ntemporary chain %s node %s\nlive Morocco KMS is not this process\n", srv.Addr(), chainID, nodeURL)
			srv.SetChain(chainID)
			srv.SetGranter(granter)
			vals, err := consoleValidators(configs, nodeURL, dial, chainID)
			if err != nil {
				return err
			}
			if engine != "" {
				ev, err := consoleValidators([]string{engine}, nodeURL, dial, chainID)
				if err != nil {
					return err
				}
				vals = append(ev, vals...)
			}
			srv.SetValidators(vals)
			if engine != "" {
				// Console bookkeeping only, beside (not inside) the sign-state files.
				if err := srv.SetOwnersPath(filepath.Join(filepath.Dir(engine), "state", "console", "owners.json")); err != nil {
					fmt.Println("owners:", err)
				}
			}
			switch {
			case readOnly:
				fmt.Println("read-only preview: no scanner, no privval dial, no broadcasts")
				for _, v := range vals {
					srv.SetEngine(v.Source, v.Slot, "read-only", "")
				}
			case engine != "":
				if err := srv.Resume(); err != nil {
					fmt.Println("scanner:", err)
				}
				go func() {
					if _, err := runEngine(srv, engine); err != nil {
						fmt.Println("engine:", err)
					}
				}()
			}
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			<-sig
			return nil
		},
	}
	cmd.Flags().StringVar(&httpAddr, "http", "127.0.0.1:8791", "console listen address")
	cmd.Flags().StringVar(&nodeURL, "node", "http://127.0.0.1:27657", "RPC of the temporary test node")
	cmd.Flags().StringVar(&dial, "dial", "tcp://127.0.0.1:27159", "privval listener of the temporary test node")
	cmd.Flags().StringVar(&chainID, "chain-id", "morocco-1", "chain id the temporary node sends on its privval socket")
	cmd.Flags().StringVar(&granter, "granter", "", "offline account that signs the authz and feegrant for takeoff")
	cmd.Flags().StringArrayVar(&configs, "config", nil, "kms config file whose validators the console lists (repeatable; one file per kms instance)")
	cmd.Flags().BoolVar(&replace, "replace", false, "stop a stale console that already serves --http (SIGTERM) before binding")
	cmd.Flags().StringVar(&engine, "engine", "", "kms config this console serves itself: every validator in it signs through one shared phone link ")
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "preview: list and plan only; no scanner, no privval dial, no grants or broadcasts")
	cmd.Flags().StringVar(&bleDir, "ble-dir", "", "Bluetooth link directory (default /tmp/kms-ble)")
	return cmd
}

// consoleValidators lists the validators from each --config file. With none,
// the flag-driven phone validator is the only entry, as before.
func consoleValidators(configs []string, nodeURL, dial, chainID string) ([]uiserver.ValidatorView, error) {
	self := uiserver.ValidatorView{Name: "console", Source: "flags", ChainID: chainID, Privval: dial, RPC: strings.TrimRight(nodeURL, "/"), Signer: "phone"}
	if len(configs) == 0 {
		return []uiserver.ValidatorView{self}, nil
	}
	var out []uiserver.ValidatorView
	seen := false
	for _, p := range configs {
		vs, err := uiserver.ValidatorsFromConfig(p)
		if err != nil {
			return nil, err
		}
		for _, v := range vs {
			if v.Privval == dial {
				seen = true
			}
		}
		out = append(out, vs...)
	}
	if !seen {
		out = append([]uiserver.ValidatorView{self}, out...)
	}
	return out, nil
}
