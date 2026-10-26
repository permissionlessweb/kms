// Package uiserver serves the KMS and zafu pages for the Bluetooth signer.
package uiserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cosmos/kms/internal/takeoff"
	"github.com/cosmos/kms/signing/bluetooth"
)

// Sign is one completed cold-sign round trip.
type Sign struct {
	Height    uint64 `json:"height"`
	Round     uint32 `json:"round"`
	Step      uint8  `json:"step"`
	LatencyMs int64  `json:"latency_ms"`
	At        string `json:"at"`
}

// State is the page model.
type State struct {
	Bluetooth bool   `json:"bluetooth"`
	Paired    bool   `json:"paired"`
	Healthy   bool   `json:"healthy"`
	NodeURL   string `json:"node_url"`
	Height    uint64 `json:"height"`
	LagMs     int64  `json:"lag_ms"`
	LastMs    int64  `json:"last_latency_ms"`
	BlockMs   int64  `json:"block_ms"`
	ChainID   string `json:"chain_id"`
	Network   string `json:"network"`
	Qr        string `json:"qr"`
	Validator bool   `json:"validator"`
	// Halted: no new block for haltAfter; validator status is then the
	// last known set, not a fresh "not a validator".
	Halted         bool           `json:"halted"`
	ConsAddr       string         `json:"consensus_addr"`
	Takeoff        bool           `json:"takeoff"`
	Granter        string         `json:"granter"`
	Ephemeral      string         `json:"ephemeral"`
	AuthID         string         `json:"auth_id"`
	AuthKind       string         `json:"auth_kind"`
	Balance        string         `json:"balance"`
	Thiol          string         `json:"thiol"`
	GrantFee       string         `json:"grant_fee"`
	RunFee         string         `json:"run_fee"`
	Error          string         `json:"error"`
	Radio          string         `json:"radio"`
	Link           string         `json:"link"`
	Seen           map[string]int `json:"seen"`
	Chosen         string         `json:"chosen"`
	Signs          []Sign         `json:"signs"`
	KmsFingerprint string         `json:"kms_fingerprint"`
	PhonePending   string         `json:"phone_pending"`
	PhonePinned    bool           `json:"phone_pinned"`
	// Codes is every chosen pairing code (one scanner link each).
	Codes []string `json:"codes"`
	// Devices is the phone mesh: one entry per authorized phone, plus the
	// phone waiting for its fingerprint to be confirmed.
	Devices  []DeviceView `json:"devices"`
	MaxLinks int          `json:"max_links"`
}

// DeviceView is one mesh member on the console.
type DeviceView struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Noise       string   `json:"noise"`
	Fingerprint string   `json:"fingerprint"`
	Code        string   `json:"code"`
	Link        string   `json:"link"` // up | connecting | down | pending
	Slots       []string `json:"slots"`
	RSSI        *int     `json:"rssi,omitempty"`
	LastMs      int64    `json:"last_ms"`
	LastAt      string   `json:"last_at"`
	Caps        []string `json:"caps"`
	Pending     bool     `json:"pending"`
}

// Server is the local console.
type Server struct {
	node       string
	radio      Radio
	bin        string
	chosen     string
	rejected   map[string]bool
	prevHeight uint64
	prevBlock  time.Time
	blockMs    int64
	chainID    string
	ephemeral  []byte
	granter    string
	prepared   takeoff.Prepared
	mu         sync.Mutex
	st         State
	ln         net.Listener
	vals       validatorSet
	acts       actionState
	token      string
	readOnly   bool
	owners     *ownerStore
}

// New binds addr and watches nodeURL for block time.
func New(addr, nodeURL string, replace bool) (*Server, error) {
	ln, err := listen(addr, replace)
	if err != nil {
		return nil, err
	}
	s := &Server{node: nodeURL, ln: ln, bin: os.Getenv("KMS_BLE_SCAN"), rejected: map[string]bool{}, st: State{NodeURL: nodeURL, Radio: "off", Seen: map[string]int{}}}
	if err := s.useRuntimeKey(); err != nil {
		_ = ln.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/state", s.state)
	mux.HandleFunc("/api/bluetooth", s.guard(s.setBT))
	mux.HandleFunc("/api/pair", s.guard(s.pair))
	mux.HandleFunc("/api/reject", s.guard(s.reject))
	mux.HandleFunc("/api/confirm-phone", s.guard(s.confirmPhone))
	s.registerValidators(mux)
	s.registerActions(mux)
	s.registerOwners(mux)
	s.registerHandoff(mux)
	s.registerShell(mux)
	go func() { _ = http.Serve(ln, mux) }()
	go s.poll()
	return s, nil
}

// Addr is the bound URL host.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Close stops the listener.
func (s *Server) Close() error {
	s.mu.Lock()
	for i := range s.ephemeral {
		s.ephemeral[i] = 0
	}
	s.mu.Unlock()
	return s.ln.Close()
}

func (s *Server) poll() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for range t.C {
		s.refreshNode()
	}
}

func (s *Server) refreshNode() {
	client := http.Client{Timeout: 2 * time.Second}
	s.mu.Lock()
	cur := s.node
	s.mu.Unlock()
	resp, err := client.Get(cur + "/status")
	s.mu.Lock()
	if err != nil {
		s.st.Error = err.Error()
		s.st.Healthy = false
		node := s.node
		s.mu.Unlock()
		s.noteValidator(node)
		s.writeStatus()
		s.noteSession()
		return
	}
	defer resp.Body.Close()
	s.st.Error = ""
	var body struct {
		Result struct {
			SyncInfo struct {
				LatestBlockHeight string `json:"latest_block_height"`
				LatestBlockTime   string `json:"latest_block_time"`
			} `json:"sync_info"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		s.st.Error = err.Error()
		s.st.Healthy = false
		node := s.node
		s.mu.Unlock()
		s.noteValidator(node)
		s.writeStatus()
		s.noteSession()
		return
	}
	var h uint64
	_, _ = fmt.Sscan(body.Result.SyncInfo.LatestBlockHeight, &h)
	s.st.Height = h
	if t, err := time.Parse(time.RFC3339Nano, body.Result.SyncInfo.LatestBlockTime); err == nil {
		s.st.LagMs = time.Since(t).Milliseconds()
		if h > s.prevHeight && !s.prevBlock.IsZero() {
			s.blockMs = t.Sub(s.prevBlock).Milliseconds()
		}
		if h != s.prevHeight {
			s.prevHeight = h
			s.prevBlock = t
		}
	}
	s.st.BlockMs = s.blockMs
	s.st.Halted = s.st.LagMs > haltAfter.Milliseconds()
	node := s.node
	s.applySession("")
	s.applyGranter()
	s.mu.Unlock()
	s.noteValidator(node)
	s.writeStatus()
	s.noteSession()
}

const haltAfter = 30 * time.Second

// nodePubs lists the phone keys to check against node's set: first the slots
// whose RPC is this node, then the legacy link key. With several slots the
// legacy pub.hex can be another slot's key (zcinti2), which made the status
// frame report "not a validator" for zcinti.
func (s *Server) nodePubs(node string) [][]byte {
	var out [][]byte
	seen := map[string]bool{}
	add := func(b []byte) {
		if len(b) == 32 && !seen[string(b)] {
			seen[string(b)] = true
			out = append(out, b)
		}
	}
	trim := func(u string) string { return strings.TrimRight(u, "/") }
	for _, v := range s.Validators() {
		if v.Signer != "phone" || trim(v.RPC) != trim(node) {
			continue
		}
		if h, ok := phonePubHex(v); ok {
			b, _ := hex.DecodeString(h)
			add(b)
		}
	}
	if b, err := bluetooth.DefaultMesh().Root().PubKey(); err == nil {
		add(b)
	}
	return out
}

func (s *Server) noteValidator(node string) {
	pubs := s.nodePubs(node)
	if len(pubs) == 0 {
		s.mu.Lock()
		s.st.Validator = false
		s.st.ConsAddr = ""
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addr, ok, failed := takeoff.ConsensusAddr(pubs[0]), false, false
	for _, pub := range pubs {
		in, err := takeoff.InValidatorSet(ctx, node, pub)
		if err != nil {
			failed = true
			continue
		}
		if in {
			addr, ok = takeoff.ConsensusAddr(pub), true
			break
		}
	}
	s.mu.Lock()
	s.st.ConsAddr = addr
	// a failed query keeps the last answer (never a fresh "not a validator")
	if ok || !failed {
		s.st.Validator = ok
	}
	s.mu.Unlock()
}

func (s *Server) state(w http.ResponseWriter, _ *http.Request) {
	radio, seen, link := s.radio.Snapshot()
	s.mu.Lock()
	s.st.Radio = radio
	s.st.Link = link
	s.st.Seen = seen
	for code := range s.rejected {
		delete(seen, code)
	}
	s.applySession(radio)
	s.applyGranter()
	st := s.st
	s.mu.Unlock()
	if fp, err := kmsFingerprint(); err == nil {
		st.KmsFingerprint = fp
	}
	st.PhonePending = bluetooth.PendingPhone()
	st.PhonePinned = bluetooth.PhonePinned()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

func (s *Server) setBT(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if body.Enabled {
		if s.bin == "" {
			http.Error(w, "bluetooth scanner is not built", 500)
			return
		}
		if err := s.radio.Start(s.bin); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = exec.Command("open", "x-apple.systempreferences:com.apple.BluetoothSettings").Start()
	} else {
		s.radio.Stop()
	}
	s.mu.Lock()
	s.st.Bluetooth = body.Enabled
	if !body.Enabled {
		s.st.Paired = false
		s.st.Healthy = false
		s.st.Seen = map[string]int{}
	}
	s.mu.Unlock()
	s.state(w, r)
}

func (s *Server) pair(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	on := s.st.Bluetooth
	s.mu.Unlock()
	if !on {
		http.Error(w, "bluetooth disabled", 409)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	radio, seen, _ := s.radio.Snapshot()
	if _, ok := seen[body.Code]; !ok {
		s.mu.Lock()
		s.st.Error = "that pairing code is not in the list"
		s.mu.Unlock()
		s.state(w, r)
		return
	}
	if radio != "on" {
		s.mu.Lock()
		s.st.Error = "scanner is not on yet"
		s.mu.Unlock()
		s.state(w, r)
		return
	}
	codes := bluetooth.ChosenCodes(bluetooth.Dir)
	has := false
	for _, c := range codes {
		has = has || c == body.Code
	}
	if !has && len(codes) >= bluetooth.MaxLinks {
		s.mu.Lock()
		s.st.Error = fmt.Sprintf("already linked to %d phones (the limit); drop one first", bluetooth.MaxLinks)
		s.mu.Unlock()
		s.state(w, r)
		return
	}
	if !has {
		codes = append(codes, body.Code)
	}
	s.mu.Lock()
	s.chosen = body.Code
	s.st.Paired = true
	s.st.Error = ""
	delete(s.rejected, body.Code)
	s.mu.Unlock()
	_ = bluetooth.WriteChosen(bluetooth.Dir, codes)
	_ = radio
	s.state(w, r)
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	s.mu.Lock()
	if body.Code != "" {
		s.rejected[body.Code] = true
		codes := bluetooth.ChosenCodes(bluetooth.Dir)
		keep := codes[:0]
		for _, c := range codes {
			if c != body.Code {
				keep = append(keep, c)
			}
		}
		_ = bluetooth.WriteChosen(bluetooth.Dir, keep)
		if s.chosen == body.Code {
			s.chosen = ""
			if len(keep) > 0 {
				s.chosen = keep[len(keep)-1]
			}
			s.st.Paired = len(keep) > 0
		}
	}
	s.st.Error = ""
	s.mu.Unlock()
	s.state(w, r)
}

// SetExportKey is the consensus key this console may send to the phone.
// The live Morocco and Penumbra key paths are refused.
func (s *Server) noteSession() {
	s.mu.Lock()
	granter := s.granter
	seed := append([]byte(nil), s.ephemeral...)
	node := s.node
	s.mu.Unlock()
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	grantee, err := takeoff.AddressOf(seed)
	if err != nil || granter == "" {
		return
	}
	missing, fee, err := takeoff.Missing(context.Background(), node, granter, grantee)
	if err != nil {
		return
	}
	kind := "grant"
	if len(missing) == 0 && !fee {
		kind = "ready"
	} else if !fee {
		kind = "omit-fee"
	}
	balance, berr := takeoff.Spendable(context.Background(), node, granter, "uterp")
	if berr != nil {
		balance = ""
	}
	thiol, terr := takeoff.Spendable(context.Background(), node, granter, "uthiol")
	if terr != nil {
		thiol = ""
	}
	grantFee, runFee := takeoff.Fees(kind != "ready")
	s.mu.Lock()
	s.st.AuthKind = kind
	s.st.Balance = balance
	s.st.Thiol = thiol
	s.st.GrantFee = grantFee
	s.st.RunFee = runFee
	s.mu.Unlock()
}

func (s *Server) writeStatus() {
	s.mu.Lock()
	frame := takeoff.StatusFrame(s.st.Height, s.st.LagMs, s.st.Validator, s.chainID, s.st.ConsAddr)
	s.mu.Unlock()
	_ = os.WriteFile(filepath.Join(bluetooth.Dir, "status.frame"), frame, 0o600)
}

func (s *Server) applyGranter() {
	raw, err := os.ReadFile(filepath.Join(bluetooth.Dir, "granter"))
	if err != nil {
		return
	}
	address := strings.TrimSpace(string(raw))
	if !takeoff.ValidAccount(address) {
		return
	}
	if s.granter == address {
		s.st.Granter = address
		return
	}
	s.granter = address
	s.st.Granter = address
	s.prepared = takeoff.Prepared{}
	s.st.AuthID = ""
	s.st.AuthKind = ""
}

// SetGranter is the offline account that signs the authz and feegrant.
// The ephemeral key is already generated by this runtime.
func (s *Server) SetGranter(granter string) {
	s.mu.Lock()
	if s.granter != granter {
		s.prepared = takeoff.Prepared{}
		s.st.AuthID = ""
		s.st.AuthKind = ""
	}
	s.granter = granter
	s.st.Granter = granter
	s.mu.Unlock()
}

func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && !localPost(r) {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			if code, msg := s.allowPost(r); code != 0 {
				http.Error(w, msg, code)
				return
			}
		}
		next(w, r)
	}
}

func localPost(r *http.Request) bool {
	host := r.Host
	if host != "127.0.0.1:8791" && host != "localhost:8791" && !strings.HasPrefix(host, "127.0.0.1:") && !strings.HasPrefix(host, "localhost:") {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+host && origin != "http://127.0.0.1:8791" {
		return false
	}
	return strings.Contains(r.Header.Get("Content-Type"), "application/json")
}

func (s *Server) confirmPhone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	pub, err := bluetooth.ConfirmPhone()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if l := bluetooth.DefaultMesh().LinkFor(pub); l != nil {
		_ = bluetooth.RegisterDevice(pub, "", l.Code())
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "pinned"})
}

func (s *Server) useRuntimeKey() error {
	path := filepath.Join(bluetooth.Dir, "ephemeral.bin")
	key, err := bluetooth.AtRestKey()
	if err != nil {
		return err
	}
	seed, err := bluetooth.ReadSecret(path, key)
	if os.IsNotExist(err) {
		seed, _, err = takeoff.GenerateKey()
		if err != nil {
			return err
		}
		if err := bluetooth.WriteSecret(path, key, seed); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	addr, err := takeoff.AddressOf(seed)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ephemeral = append([]byte(nil), seed...)
	s.st.Ephemeral = addr
	s.st.Takeoff = true
	s.mu.Unlock()
	return nil
}

// SetChain is the Terp chain this console signs for. The phone scans it.
func (s *Server) SetChain(id string) {
	s.mu.Lock()
	s.chainID = id
	s.st.ChainID = id
	s.st.Network = "terp"
	if id != "" {
		s.st.Qr = "zcinti:1:terp:" + id
	}
	s.mu.Unlock()
}

func kmsFingerprint() (string, error) {
	seed, err := bluetoothStatic()
	if err != nil {
		return "", err
	}
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	pub, err := bluetooth.StaticPublic(seed)
	if err != nil {
		return "", err
	}
	return bluetooth.Fingerprint(pub), nil
}

func bluetoothStatic() ([]byte, error) {
	return bluetooth.NoiseStatic()
}

func containsForbiddenKeyPath(chain string) bool {
	return strings.Contains(chain, ".kms") || strings.Contains(chain, "/")
}

// Resume starts the scanner again when a phone is already accepted.
// It does not open System Settings.
func (s *Server) Resume() error {
	codes := bluetooth.ChosenCodes(bluetooth.Dir)
	if len(codes) == 0 || s.bin == "" {
		return nil
	}
	code := codes[len(codes)-1]
	s.mu.Lock()
	s.chosen = code
	s.st.Paired = true
	s.st.Bluetooth = true
	s.mu.Unlock()
	return s.radio.Start(s.bin)
}

// applySession keeps the page on the live phone session. The chosen code
// lives in a file, so a console restart does not look unpaired while the
// phone is still signing. The caller holds s.mu.
func (s *Server) applySession(radio string) {
	codes := bluetooth.ChosenCodes(bluetooth.Dir)
	if n := len(codes); n > 0 {
		s.chosen = codes[n-1]
		s.st.Paired = true
	}
	s.st.Codes = codes
	s.st.MaxLinks = bluetooth.MaxLinks
	if radio == "on" {
		s.st.Bluetooth = true
		s.st.Radio = radio
	}
	signs := bluetooth.DefaultMesh().Recent()
	s.st.Devices = s.deviceViews(codes)
	s.st.Signs = signsFrom(signs)
	s.st.BlockMs = s.blockMs
	recent := false
	if n := len(signs); n > 0 {
		last := signs[n-1]
		s.st.LastMs = last.LatencyMs
		if t, err := time.Parse(time.RFC3339, last.At); err == nil && time.Since(t) < 20*time.Second {
			recent = true
			s.st.Paired = true
		}
	}
	s.st.Chosen = s.chosen
	s.st.Healthy = s.st.Error == "" && s.st.Height > 0 && recent
}

func signsFrom(in []bluetooth.SignRecord) []Sign {
	out := make([]Sign, 0, len(in))
	for _, row := range in {
		out = append(out, Sign{
			Height: row.Height, Round: row.Round, Step: row.Step,
			LatencyMs: row.LatencyMs, At: row.At,
		})
	}
	return out
}
