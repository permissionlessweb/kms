package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/internal/app"
	"github.com/cosmos/kms/internal/manager"
	"github.com/cosmos/kms/signing"
	"github.com/cosmos/kms/signing/bluetooth"
)

// keyHRS stamps height/round/step on one phone key before its slot signs.
type keyHRS struct {
	inner types.PrivValidator
	key   *bluetooth.KeyLink
}

func (p *keyHRS) GetPubKey() (crypto.PubKey, error) { return p.inner.GetPubKey() }

func (p *keyHRS) SignVote(chainID string, vote *cmtproto.Vote) error {
	step := uint8(2)
	if vote.Type == cmtproto.PrecommitType {
		step = 3
	}
	p.key.SetHRS(uint64(vote.Height), uint32(vote.Round), step)
	return p.inner.SignVote(chainID, vote)
}

func (p *keyHRS) SignProposal(chainID string, proposal *cmtproto.Proposal) error {
	p.key.SetHRS(uint64(proposal.Height), uint32(proposal.Round), 1)
	return p.inner.SignProposal(chainID, proposal)
}

func keyLabel(k config.Key) string {
	if len(k.ChainIDs) > 0 {
		return strings.ReplaceAll(k.ChainIDs[0], "/", "_")
	}
	return k.KeyID
}

// engineStatus receives per-slot engine status for the console tabs.
type engineStatus interface {
	SetEngine(source, slot, status, keyID string)
}

// engine runs one goroutine per chain slot over a shared phone link.
type engine struct {
	path string
	c    *config.Config
	st   engineStatus
	link *bluetooth.Link
	dial func(config.Validator) privval.SocketDialer // tests only
	poll time.Duration
	stop chan struct{}
	wg   sync.WaitGroup
	mu   sync.Mutex
	mgrs []*manager.Manager
}

// runEngine serves every validator in one kms config from this console. Each
// slot arms on its own: it dials as soon as the arm marker exists and its own
// phone key is published, so one slot serves while another still waits for
// its key or its node. A fresh sign-state file is never created.
func runEngine(srv engineStatus, path string) (*engine, error) {
	c, err := loadEngineConfig(path)
	if err != nil {
		return nil, err
	}
	e := &engine{path: path, c: c, st: srv, link: bluetooth.DefaultLink(), poll: time.Second, stop: make(chan struct{})}
	e.start()
	return e, nil
}

// loadEngineConfig loads and validates a config, resolving relative paths
// (state files, identity keys) against the config's directory.
func loadEngineConfig(path string) (*config.Config, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return c, nil
}

func (e *engine) start() {
	for _, ch := range e.c.Chains {
		sub, ok := slotConfig(e.c, ch.ID)
		if !ok {
			e.st.SetEngine(e.path, ch.ID, "waiting: no validator or key for this slot", "")
			continue
		}
		e.wg.Add(1)
		go e.runSlot(ch.ID, sub)
	}
}

// Stop ends every slot (tests; the console exits on signal).
func (e *engine) Stop() {
	close(e.stop)
	e.wg.Wait()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, m := range e.mgrs {
		m.Stop()
	}
}

// slotConfig is the part of c that serves one chain slot.
func slotConfig(c *config.Config, slot string) (*config.Config, bool) {
	sub := &config.Config{}
	for _, ch := range c.Chains {
		if ch.ID == slot {
			sub.Chains = append(sub.Chains, ch)
		}
	}
	for _, v := range c.Validators {
		if v.ChainID == slot {
			sub.Validators = append(sub.Validators, v)
		}
	}
	for _, k := range c.Keys {
		for _, id := range k.ChainIDs {
			if id == slot {
				k.ChainIDs = []string{slot}
				sub.Keys = append(sub.Keys, k)
				break
			}
		}
	}
	return sub, len(sub.Chains) == 1 && len(sub.Validators) > 0 && len(sub.Keys) == 1
}

func (e *engine) runSlot(slot string, sub *config.Config) {
	defer e.wg.Done()
	k := sub.Keys[0]
	set := func(st, id string) { e.st.SetEngine(e.path, slot, st, id) }
	last := ""
	for {
		why := ""
		if _, err := os.Stat(filepath.Join(bluetooth.Dir, "arm")); err != nil {
			why = "waiting for arm"
		} else if k.Backend == config.BackendBluetooth {
			if _, err := e.link.PubKeyFor(k, keyLabel(k)); err != nil {
				why = "waiting for phone key " + keyLabel(k)
			}
		}
		if why == "" {
			break
		}
		if why != last {
			set(why, "")
			last = why
		}
		select {
		case <-e.stop:
			return
		case <-time.After(e.poll):
		}
	}
	var kl *bluetooth.KeyLink
	opts := app.Options{
		Signer: func(k config.Key) (signing.Signer, bool, error) {
			if k.Backend != config.BackendBluetooth {
				return nil, false, nil
			}
			pub, err := e.link.PubKeyFor(k, keyLabel(k))
			if err != nil {
				return nil, true, err
			}
			kl, err = e.link.ForKey(keyLabel(k), pub)
			if err != nil {
				return nil, true, err
			}
			return kl, true, nil
		},
		Wrap: func(_ string, k config.Key, pv types.PrivValidator) types.PrivValidator {
			if kl != nil && k.Backend == config.BackendBluetooth {
				pv = &keyHRS{inner: pv, key: kl}
			}
			id := ""
			if kl != nil {
				id = kl.ID()
			}
			return &servedPV{PrivValidator: pv, first: func() { set("serving", id) }}
		},
		Dial: e.dial,
	}
	logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout)).With("slot", slot)
	mgr, _, err := app.BuildWith(sub, nil, logger, opts)
	if err != nil {
		set("error: "+err.Error(), "")
		return
	}
	id := ""
	if kl != nil {
		id = kl.ID()
	}
	set("waiting for node privval "+sub.Validators[0].Addr, id)
	_ = mgr.Start()
	e.mu.Lock()
	e.mgrs = append(e.mgrs, mgr)
	e.mu.Unlock()
	fmt.Printf("engine slot %s dialing %s (key %s)\n", slot, sub.Validators[0].Addr, id)
}

// servedPV marks its slot serving on the first request from the node.
type servedPV struct {
	types.PrivValidator
	once  sync.Once
	first func()
}

func (p *servedPV) GetPubKey() (crypto.PubKey, error) {
	p.once.Do(p.first)
	return p.PrivValidator.GetPubKey()
}

func (p *servedPV) SignVote(chainID string, v *cmtproto.Vote) error {
	p.once.Do(p.first)
	return p.PrivValidator.SignVote(chainID, v)
}

func (p *servedPV) SignProposal(chainID string, pr *cmtproto.Proposal) error {
	p.once.Do(p.first)
	return p.PrivValidator.SignProposal(chainID, pr)
}
