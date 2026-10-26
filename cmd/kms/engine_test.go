package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cometbft/cometbft/privval"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/internal/signer"
	"github.com/cosmos/kms/signing/bluetooth"
)

type statusRec struct {
	mu sync.Mutex
	m  map[string]string
	id map[string]string
}

func (r *statusRec) SetEngine(_, slot, st, id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[slot] = st
	if id != "" {
		r.id[slot] = id
	}
}

func (r *statusRec) get(slot string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[slot]
}

func publish(t *testing.T, dir, label string) []byte {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "keys", label), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keys", label, "pub.hex"), []byte(hex.EncodeToString(pub)), 0o600))
	return pub
}

func TestEngineArmsEachSlotOnItsOwn(t *testing.T) {
	home, ble := t.TempDir(), t.TempDir()
	old := bluetooth.Dir
	bluetooth.Dir = ble
	defer func() { bluetooth.Dir = old }()
	y := `chains:
  - {id: net/a, network: net}
  - {id: net/b, network: net}
validators:
  - {chain_id: net/a, addr: "tcp://127.0.0.1:1", identity_key: ida}
  - {chain_id: net/b, addr: "tcp://127.0.0.1:2", identity_key: idb}
keys:
  - {chain_ids: [net/a], backend: bluetooth, peer: zafu}
  - {chain_ids: [net/b], backend: bluetooth, peer: zafu}
`
	path := filepath.Join(home, "kms.yaml")
	require.NoError(t, os.WriteFile(path, []byte(y), 0o600))
	c, err := loadEngineConfig(path)
	require.NoError(t, err)
	for _, ch := range c.Chains {
		require.NoError(t, signer.InitState(ch.StateFile, 10, 0, 3))
	}
	rec := &statusRec{m: map[string]string{}, id: map[string]string{}}
	e := &engine{path: path, c: c, st: rec, link: bluetooth.NewMesh(ble), poll: 10 * time.Millisecond, stop: make(chan struct{}),
		dial: func(config.Validator) privval.SocketDialer {
			return func() (net.Conn, error) { return nil, errors.New("node not listening") }
		}}
	e.start()
	defer e.Stop()

	wait := func(slot, want string) {
		require.Eventually(t, func() bool { return strings.HasPrefix(rec.get(slot), want) }, 2*time.Second, 5*time.Millisecond, "%s: %q", slot, rec.get(slot))
	}
	wait("net/a", "waiting for arm")
	wait("net/b", "waiting for arm")

	pub := publish(t, ble, "net_a")
	require.NoError(t, os.WriteFile(filepath.Join(ble, "arm"), nil, 0o600))
	// a dials (node not up yet => waiting, not error) while b still has no key.
	wait("net/a", "waiting for node privval tcp://127.0.0.1:1")
	wait("net/b", "waiting for phone key net_b")
	rec.mu.Lock()
	require.Equal(t, bluetooth.KeyIDHex(pub), rec.id["net/a"])
	rec.mu.Unlock()

	publish(t, ble, "net_b")
	wait("net/b", "waiting for node privval tcp://127.0.0.1:2")
	require.True(t, strings.HasPrefix(rec.get("net/a"), "waiting for node"))
}

func TestSlotConfigSplitsSharedKey(t *testing.T) {
	c := &config.Config{
		Chains:     []config.Chain{{ID: "a"}, {ID: "b"}},
		Validators: []config.Validator{{ChainID: "a"}, {ChainID: "b"}},
		Keys:       []config.Key{{ChainIDs: []string{"a", "b"}}},
	}
	sub, ok := slotConfig(c, "b")
	require.True(t, ok)
	require.Equal(t, []string{"b"}, sub.Keys[0].ChainIDs)
	require.Equal(t, []string{"a", "b"}, c.Keys[0].ChainIDs, "original untouched")
	_, ok = slotConfig(c, "zz")
	require.False(t, ok)
}

func TestServedPVMarksFirstRequest(t *testing.T) {
	n := 0
	p := &servedPV{PrivValidator: nil, first: func() { n++ }}
	func() { defer func() { _ = recover() }(); _, _ = p.GetPubKey() }()
	func() { defer func() { _ = recover() }(); _, _ = p.GetPubKey() }()
	require.Equal(t, 1, n)
}
