package uiserver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Radio is the laptop Bluetooth scanner. It does not sign.
type Radio struct {
	mu    sync.Mutex
	cmd   *exec.Cmd
	gen   int
	State string
	Link  string
	Seen  map[string]int
	// Links is each chosen code's connection (scanner mesh mode).
	Links map[string]string
}

func (r *Radio) Start(bin string) error {
	r.Stop()
	_ = os.Remove("/tmp/kms-ble-events.jsonl")
	if err := os.WriteFile("/tmp/kms-ble-events.jsonl", nil, 0o600); err != nil {
		return err
	}
	// Launch the scanner app itself so macOS asks to allow "KMS Bluetooth",
	// not whichever browser is showing this page.
	app := bin
	if strings.HasSuffix(bin, "/ble-scan") {
		app = filepath.Dir(filepath.Dir(filepath.Dir(bin)))
	}
	cmd := exec.Command("open", "-W", app)
	cmd.Env = append(os.Environ(), "KMS_BLE_LOG=/tmp/kms-ble-events.jsonl")
	if err := cmd.Start(); err != nil {
		return err
	}
	r.mu.Lock()
	r.gen++
	gen := r.gen
	r.cmd = cmd
	r.State = "starting"
	r.Seen = map[string]int{}
	r.mu.Unlock()
	go r.follow("/tmp/kms-ble-events.jsonl", gen)
	return nil
}

func (r *Radio) follow(path string, gen int) {
	for {
		r.mu.Lock()
		alive := r.gen == gen
		r.mu.Unlock()
		if !alive {
			return
		}
		f, err := os.Open(path)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			r.apply(sc.Bytes())
		}
		_ = f.Close()
		time.Sleep(300 * time.Millisecond)
	}
}

func (r *Radio) apply(line []byte) {
	var ev struct {
		Event string `json:"event"`
		Value string `json:"value"`
		Code  string `json:"code"`
		RSSI  int    `json:"rssi"`
	}
	if json.Unmarshal(line, &ev) != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch ev.Event {
	case "state":
		r.State = ev.Value
	case "link":
		r.Link = ev.Value
		if ev.Code != "" {
			if r.Links == nil {
				r.Links = map[string]string{}
			}
			r.Links[ev.Code] = ev.Value
		}
	case "seen":
		if r.Seen == nil {
			r.Seen = map[string]int{}
		}
		r.Seen[ev.Code] = ev.RSSI
	}
}

func (r *Radio) Stop() {
	r.mu.Lock()
	cmd := r.cmd
	r.cmd = nil
	r.State = "off"
	r.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
	_ = exec.Command("pkill", "-f", "BleScan.app/Contents/MacOS/ble-scan").Run()
	_ = os.Remove("/tmp/kms-ble-events.jsonl")
}

// LinkStates is each code's last reported connection.
func (r *Radio) LinkStates() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]string{}
	for k, v := range r.Links {
		out[k] = v
	}
	return out
}

func (r *Radio) Snapshot() (string, map[string]int, string) {
	r.mu.Lock()
	state := r.State
	link := r.Link
	out := map[string]int{}
	for k, v := range r.Seen {
		out[k] = v
	}
	r.mu.Unlock()
	// The scanner writes this file. Read it on each poll so a missed
	// tail still shows the pairing codes.
	b, err := os.ReadFile("/tmp/kms-ble-events.jsonl")
	if err != nil {
		return state, out, link
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var ev struct {
			Event string `json:"event"`
			Value string `json:"value"`
			Code  string `json:"code"`
			RSSI  int    `json:"rssi"`
		}
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		if ev.Event == "state" && ev.Value != "" {
			state = ev.Value
		}
		if ev.Event == "link" && ev.Value != "" {
			link = ev.Value
		}
		if ev.Event == "seen" && ev.Code != "" {
			out[ev.Code] = ev.RSSI
		}
	}
	return state, out, link
}
