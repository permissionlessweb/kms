package manager

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/stretchr/testify/require"
)

func TestBackoffDialerRetriesThenSucceeds(t *testing.T) {
	var calls int32
	base := func() (net.Conn, error) {
		if atomic.AddInt32(&calls, 1) < 3 {
			return nil, errors.New("refused")
		}
		c, _ := net.Pipe()
		return c, nil
	}

	stop := make(chan struct{})
	d := backoffDialer(base, stop, log.TestingLogger(), time.Millisecond, 5*time.Millisecond)

	conn, err := d()
	require.NoError(t, err)
	require.NotNil(t, conn)
	require.GreaterOrEqual(t, atomic.LoadInt32(&calls), int32(3))
}

func TestBackoffDialerUnblocksOnStop(t *testing.T) {
	base := func() (net.Conn, error) { return nil, errors.New("always fails") }
	stop := make(chan struct{})
	d := backoffDialer(base, stop, log.TestingLogger(), time.Millisecond, 5*time.Millisecond)

	done := make(chan struct{})
	go func() {
		_, err := d()
		require.Error(t, err)
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)
	close(stop)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dialer did not unblock on stop")
	}
}

func TestBackoffDialerFastCadence(t *testing.T) {
	var times []time.Time
	base := func() (net.Conn, error) {
		times = append(times, time.Now())
		if len(times) < 6 {
			return nil, errors.New("refused")
		}
		c, _ := net.Pipe()
		return c, nil
	}
	d := backoffDialer(base, make(chan struct{}), log.NewNopLogger(), defaultBackoffInitial, defaultBackoffMax)
	_, err := d()
	require.NoError(t, err)
	for i := 1; i < len(times); i++ {
		require.LessOrEqual(t, times[i].Sub(times[i-1]), defaultBackoffMax+100*time.Millisecond)
	}
	require.LessOrEqual(t, defaultBackoffMax, time.Second)
}

func TestJitterBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		j := jitter(500 * time.Millisecond)
		require.LessOrEqual(t, j, 500*time.Millisecond)
		require.GreaterOrEqual(t, j, 400*time.Millisecond)
	}
}
