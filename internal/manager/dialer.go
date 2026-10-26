package manager

import (
	"errors"
	"math/rand"
	"net"
	"time"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
)

// errDialerStopped is returned by a backoff dialer after its stop channel closes.
var errDialerStopped = errors.New("kms: dialer stopped")

// dialFailLogEvery rate-limits "dial failed" logging while a slot is down: the
// first failure is logged, then one summary per interval.
const dialFailLogEvery = 30 * time.Second

// backoffDialer wraps a one-shot SocketDialer so it blocks, retrying with capped
// exponential backoff plus jitter, until it obtains a connection or stop is
// closed. Because it blocks until success, privval's serviceLoop never exits on
// transient outages. A CometBFT node only accepts for a short window
// (timeout_accept, ~3s) at startup, so max should stay well below that (default
// 750ms). Each slot has exactly one supervising goroutine calling this dialer
// sequentially, so a fast redial can never open two concurrent connections to
// the same node; signing state (HWM / double-sign protection) is untouched here.
func backoffDialer(base privval.SocketDialer, stop <-chan struct{}, logger log.Logger, initial, max time.Duration) privval.SocketDialer {
	if max <= 0 {
		max = defaultBackoffMax
	}
	if initial <= 0 || initial > max {
		initial = max
	}
	return func() (net.Conn, error) {
		wait := initial
		var failures int
		var firstFail, lastLog time.Time
		for {
			select {
			case <-stop:
				return nil, errDialerStopped
			default:
			}

			conn, err := base()
			if err == nil {
				if failures > 0 {
					logger.Info("kms: dial succeeded", "failures", failures, "down_for", time.Since(firstFail).Round(time.Millisecond))
				}
				return conn, nil
			}
			now := time.Now()
			failures++
			if failures == 1 {
				firstFail, lastLog = now, now
				logger.Error("kms: dial failed; retrying", "max_wait", max, "err", err)
			} else if now.Sub(lastLog) >= dialFailLogEvery {
				lastLog = now
				logger.Error("kms: dial still failing", "failures", failures, "down_for", now.Sub(firstFail).Round(time.Second), "err", err)
			}

			select {
			case <-stop:
				return nil, errDialerStopped
			case <-time.After(jitter(wait)):
			}
			if wait *= 2; wait > max {
				wait = max
			}
		}
	}
}

// jitter returns d scaled by a random factor in [0.8, 1.0], so it never exceeds d.
func jitter(d time.Duration) time.Duration {
	return d - time.Duration(rand.Int63n(int64(d)/5+1))
}
