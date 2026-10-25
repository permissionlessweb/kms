package uiserver

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// listen binds addr. When the port is already held, it says who holds it
// instead of a bare "address already in use". With replace set, a stale
// zcinti console on that port is asked to exit with SIGTERM, and the bind is
// retried once the port is free. Any other owner is never signalled.
func listen(addr string, replace bool) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err == nil || !errors.Is(err, syscall.EADDRINUSE) {
		return ln, err
	}
	console := isConsole(addr)
	pid := portOwner(addr)
	who := "another process"
	if console {
		who = "another zcinti console"
	}
	if pid > 0 {
		who += fmt.Sprintf(" (pid %d)", pid)
	}
	if !replace {
		return nil, fmt.Errorf("%s already serves %s; stop it (kill -TERM %d) or pass --replace", who, addr, pid)
	}
	if !console || pid <= 0 {
		return nil, fmt.Errorf("%s holds %s and is not a zcinti console; refusing to replace it", who, addr)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return nil, fmt.Errorf("stop console pid %d: %w", pid, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		if ln, err = net.Listen("tcp", addr); err == nil {
			return ln, nil
		}
	}
	return nil, fmt.Errorf("console pid %d did not release %s within 10s", pid, addr)
}

// isConsole reports whether addr answers /api/state like this console does.
func isConsole(addr string) bool {
	c := http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://" + addr + "/api/state")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK && strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json")
}

// portOwner returns the pid listening on addr's port, or 0.
func portOwner(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	out, err := exec.Command("lsof", "-nP", "-t", "-iTCP:"+port, "-sTCP:LISTEN").Output()
	if err != nil {
		return 0
	}
	first := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	pid, _ := strconv.Atoi(first)
	return pid
}
