package uiserver

import (
	"context"
	"sync"
	"time"

	"github.com/cosmos/kms/internal/takeoff"
)

// jailTTL bounds how often a tab re-reads slashing state (probes run every 3s).
const jailTTL = 30 * time.Second

type jailEntry struct {
	at   time.Time
	info *takeoff.JailInfo
}

var (
	jailMu    sync.Mutex
	jailCache = map[string]jailEntry{}
	// queryJail is swapped in tests.
	queryJail = takeoff.QueryJail
)

// jailFor returns the cached slashing state for a node's consensus address.
// Errors keep the last good value so a slow RPC never hides a jail.
func jailFor(rpc, consHex string) *takeoff.JailInfo {
	if rpc == "" || consHex == "" {
		return nil
	}
	key := rpc + "|" + consHex
	jailMu.Lock()
	e, ok := jailCache[key]
	jailMu.Unlock()
	if !ok || time.Since(e.at) > jailTTL {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		j, err := queryJail(ctx, rpc, consHex)
		cancel()
		if err == nil {
			e = jailEntry{at: time.Now(), info: &j}
		} else {
			e.at = time.Now() // retry after the ttl, keep the old info
		}
		jailMu.Lock()
		jailCache[key] = e
		jailMu.Unlock()
	}
	if e.info == nil {
		return nil
	}
	j := *e.info
	j.Evaluate(time.Now()) // jailed_until passes without a new query
	return &j
}

// forgetJail drops cached state so the next probe re-reads it (after an unjail).
func forgetJail() {
	jailMu.Lock()
	jailCache = map[string]jailEntry{}
	jailMu.Unlock()
}
