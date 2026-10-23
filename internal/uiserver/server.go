// Package uiserver serves the KMS and zafu pages for the Bluetooth signer.
package uiserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/skip2/go-qrcode"
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
	Bluetooth      bool           `json:"bluetooth"`
	Paired         bool           `json:"paired"`
	Healthy        bool           `json:"healthy"`
	NodeURL        string         `json:"node_url"`
	Height         uint64         `json:"height"`
	LagMs          int64          `json:"lag_ms"`
	LastMs         int64          `json:"last_latency_ms"`
	BlockMs        int64          `json:"block_ms"`
	ChainID        string         `json:"chain_id"`
	Network        string         `json:"network"`
	Qr             string         `json:"qr"`
	Validator      bool           `json:"validator"`
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
	exportKey  string
	ephemeral  []byte
	granter    string
	prepared   takeoff.Prepared
	mu         sync.Mutex
	st         State
	ln         net.Listener
}

// New binds addr and watches nodeURL for block time.
func New(addr, nodeURL string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{node: nodeURL, ln: ln, bin: os.Getenv("KMS_BLE_SCAN"), rejected: map[string]bool{}, st: State{NodeURL: nodeURL, Radio: "off", Seen: map[string]int{}}}
	if err := s.useRuntimeKey(); err != nil {
		_ = ln.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.page)
	mux.HandleFunc("/signer", s.page)
	mux.HandleFunc("/api/state", s.state)
	mux.HandleFunc("/api/bluetooth", s.guard(s.setBT))
	mux.HandleFunc("/api/pair", s.guard(s.pair))
	mux.HandleFunc("/api/reject", s.guard(s.reject))
	mux.HandleFunc("/qr.png", s.qr)
	mux.HandleFunc("/kms-id.png", s.kmsID)
	mux.HandleFunc("/api/import", s.guard(s.importKey))
	mux.HandleFunc("/api/confirm-phone", s.guard(s.confirmPhone))
	mux.HandleFunc("/api/recover", s.guard(s.recover))
	mux.HandleFunc("/api/takeoff", s.guard(s.takeoff))
	mux.HandleFunc("/takeoff-qr.png", s.takeoffQR)
	mux.HandleFunc("/api/takeoff/signature", s.guard(s.takeoffSignature))
	mux.HandleFunc("/api/takeoff/continue", s.guard(s.takeoffContinue))
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
	resp, err := client.Get(s.node + "/status")
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
	node := s.node
	s.applySession("")
	s.applyGranter()
	s.mu.Unlock()
	s.noteValidator(node)
	s.writeStatus()
	s.noteSession()
}

func (s *Server) noteValidator(node string) {
	pub, err := bluetooth.DefaultLink().PubKey()
	if err != nil || len(pub) != 32 {
		s.mu.Lock()
		s.st.Validator = false
		s.st.ConsAddr = ""
		s.mu.Unlock()
		return
	}
	addr := takeoff.ConsensusAddr(pub)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ok, qerr := takeoff.InValidatorSet(ctx, node, pub)
	s.mu.Lock()
	s.st.ConsAddr = addr
	if qerr == nil {
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
	s.mu.Lock()
	s.chosen = body.Code
	s.st.Paired = true
	s.st.Error = ""
	delete(s.rejected, body.Code)
	s.mu.Unlock()
	_ = os.MkdirAll(bluetooth.Dir, 0o700)
	_ = os.WriteFile(filepath.Join(bluetooth.Dir, "chosen"), []byte(body.Code+"\n"), 0o600)
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
		if s.chosen == body.Code {
			s.chosen = ""
			s.st.Paired = false
			_ = os.WriteFile(filepath.Join(bluetooth.Dir, "chosen"), nil, 0o600)
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
	if err := bluetooth.ConfirmPhone(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
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

func (s *Server) takeoff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Moniker string `json:"moniker"`
		Amount  string `json:"amount"`
		Granter string `json:"granter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	seed := append([]byte(nil), s.ephemeral...)
	granter := s.granter
	chain := s.chainID
	node := s.node
	s.mu.Unlock()
	if body.Granter != "" {
		granter = strings.TrimSpace(body.Granter)
		s.SetGranter(granter)
	}
	if granter == "" {
		http.Error(w, "the offline granter account is required", http.StatusConflict)
		return
	}
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	pub, err := bluetooth.DefaultLink().PubKey()
	if err != nil {
		http.Error(w, "phone public key is not connected", http.StatusConflict)
		return
	}
	amount, err := takeoff.ParseTERP(body.Amount)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out, err := takeoff.Run(r.Context(), node, takeoff.Plan{
		ChainID: chain, Moniker: body.Moniker, Amount: amount, Denom: "uterp",
		PubKey: pub, Granter: granter,
	}, seed)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	grants := make([]map[string]string, 0, len(out.Grants))
	for _, msg := range out.Grants {
		grants = append(grants, map[string]string{
			"type_url": msg.TypeUrl,
			"value":    base64.StdEncoding.EncodeToString(msg.Value),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"phase":       out.Phase,
		"address":     out.Address,
		"granter":     granter,
		"types":       out.Types,
		"grants":      grants,
		"create_hash": out.CreateHash,
		"revoke_hash": out.RevokeHash,
	})
}

func (s *Server) takeoffQR(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	granter := s.granter
	seed := append([]byte(nil), s.ephemeral...)
	chain := s.chainID
	node := s.node
	s.mu.Unlock()
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	if !takeoff.ValidAccount(granter) {
		http.Error(w, "waiting for the Terp account from the offline signer", http.StatusConflict)
		return
	}
	grantee, err := takeoff.AddressOf(seed)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.mu.Lock()
	cached := s.prepared
	s.mu.Unlock()
	acct, seq, acctErr := takeoff.AccountNumbers(r.Context(), node, granter)
	if acctErr == nil && cached.Granter == granter && cached.Grantee == grantee && cached.Account == acct && cached.Sequence == seq && len(cached.PNG) > 0 {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(cached.PNG)
		return
	}
	png, prepared, err := takeoff.Prepare(r.Context(), node, granter, grantee, chain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.mu.Lock()
	s.prepared = prepared
	s.st.AuthID = prepared.ID()
	s.st.AuthKind = prepared.Kind
	s.mu.Unlock()
	if prepared.Kind == "ready" || len(png) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func (s *Server) takeoffSignature(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Payload string `json:"payload"`
		Moniker string `json:"moniker"`
		Amount  string `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Println("takeoff signature received", len(body.Payload))
	steps := []takeoffStep{{Name: "signature", Detail: "not read"}}
	pub, sig, err := takeoff.DecodeCworch(body.Payload)
	if err != nil {
		steps[0] = takeoffStep{Name: "signature", Detail: err.Error()}
		writeTakeoffSteps(w, steps)
		return
	}
	steps[0] = takeoffStep{Name: "signature", OK: true, Detail: fmt.Sprintf("read %d bytes, public key %d bytes", len(sig), len(pub))}
	s.mu.Lock()
	prepared := s.prepared
	seed := append([]byte(nil), s.ephemeral...)
	granter := s.granter
	chain := s.chainID
	node := s.node
	authID := s.st.AuthID
	s.mu.Unlock()
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	if len(prepared.Amino) == 0 {
		steps = append(steps, takeoffStep{Name: "verify", Detail: "no authorization is on the page"})
		writeTakeoffSteps(w, steps)
		return
	}
	normalized, note, err := takeoff.MatchAuthorization(pub, sig, prepared.Amino)
	if err != nil {
		steps = append(steps, takeoffStep{Name: "verify", Detail: err.Error() + ". page authorization " + authID})
		steps = append(steps, takeoffStep{Name: "grant", Detail: "not sent"})
		steps = append(steps, takeoffStep{Name: "create", Detail: "not sent"})
		steps = append(steps, takeoffStep{Name: "revoke", Detail: "not sent"})
		fmt.Println("takeoff verify rejected", err)
		writeTakeoffSteps(w, steps)
		return
	}
	steps = append(steps, takeoffStep{Name: "verify", OK: true, Detail: note + ". page authorization " + prepared.ID()})
	if prepared.Kind != "ready" && len(prepared.Msgs) > 0 {
		if refuse := s.shortBalance(r.Context(), node, granter, body.Amount, true); refuse != "" {
			steps = append(steps, takeoffStep{Name: "grant", Detail: refuse})
			steps = append(steps, takeoffStep{Name: "create", Detail: "not sent"})
			steps = append(steps, takeoffStep{Name: "revoke", Detail: "not sent"})
			writeTakeoffSteps(w, steps)
			return
		}
	}
	if prepared.Kind == "ready" || len(prepared.Msgs) == 0 {
		steps = append(steps, takeoffStep{Name: "grant", OK: true, Detail: "feegrant already registered, omitted"})
		steps = append(steps, s.ephemeralActions(r.Context(), node, chain, granter, body.Moniker, body.Amount, seed)...)
		writeTakeoffSteps(w, steps)
		return
	}
	hash, err := takeoff.BroadcastAmino(r.Context(), node, chain, prepared.Account, prepared.Sequence, pub, normalized, prepared.Amino, prepared.Msgs)
	if err != nil {
		steps = append(steps, takeoffStep{Name: "grant", Detail: err.Error()})
		steps = append(steps, takeoffStep{Name: "create", Detail: "not sent"})
		steps = append(steps, takeoffStep{Name: "revoke", Detail: "not sent"})
		fmt.Println("takeoff grant rejected", err)
		writeTakeoffSteps(w, steps)
		return
	}
	steps = append(steps, takeoffStep{Name: "grant", OK: true, Detail: hash + " committed. Feegrant pays gas for " + granter})
	fmt.Println("takeoff grant accepted", hash)
	steps = append(steps, s.ephemeralActions(r.Context(), node, chain, granter, body.Moniker, body.Amount, seed)...)
	writeTakeoffSteps(w, steps)
}

func (s *Server) takeoffContinue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Moniker string `json:"moniker"`
		Amount  string `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	seed := append([]byte(nil), s.ephemeral...)
	granter := s.granter
	chain := s.chainID
	node := s.node
	s.mu.Unlock()
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	writeTakeoffSteps(w, s.ephemeralActions(r.Context(), node, chain, granter, body.Moniker, body.Amount, seed))
}

func (s *Server) ephemeralActions(ctx context.Context, node, chain, granter, moniker, amountText string, seed []byte) []takeoffStep {
	var steps []takeoffStep
	phone, err := bluetooth.DefaultLink().PubKey()
	if err != nil {
		return append(steps,
			takeoffStep{Name: "create", Detail: "phone public key is not connected"},
			takeoffStep{Name: "revoke", Detail: "not sent"},
		)
	}
	amount, err := takeoff.ParseTERP(amountText)
	if err != nil {
		return append(steps,
			takeoffStep{Name: "create", Detail: err.Error()},
			takeoffStep{Name: "revoke", Detail: "not sent"},
		)
	}
	if refuse := s.shortBalance(ctx, node, granter, amountText, false); refuse != "" {
		return append(steps,
			takeoffStep{Name: "create", Detail: refuse},
			takeoffStep{Name: "revoke", Detail: "not sent"},
		)
	}
	createHash, err := takeoff.Broadcast(ctx, node, takeoff.Plan{
		ChainID: chain, Moniker: moniker, Amount: amount, Denom: "uterp",
		PubKey: phone, Granter: granter,
	}, seed)
	if err != nil && strings.Contains(err.Error(), "not in a block yet") {
		detail := err.Error()
		if createHash != "" {
			detail = createHash + " " + detail
		}
		steps = append(steps, takeoffStep{Name: "create", Detail: detail})
		steps = append(steps, takeoffStep{Name: "revoke", Detail: "not sent"})
		fmt.Println("takeoff create waiting", createHash, err)
		return steps
	}
	if err != nil {
		detail := err.Error()
		if createHash != "" {
			detail = createHash + " " + detail
		}
		steps = append(steps, takeoffStep{Name: "create", Detail: detail})
		fmt.Println("takeoff create rejected", createHash, err)
	} else {
		steps = append(steps, takeoffStep{Name: "create", OK: true, Detail: createHash + " committed. Fee paid by the granter feegrant"})
		fmt.Println("takeoff create accepted", createHash)
	}
	revokeHash, err := takeoff.BroadcastRevoke(ctx, node, chain, "uterp", granter, seed)
	if err != nil {
		steps = append(steps, takeoffStep{Name: "revoke", Detail: err.Error()})
		fmt.Println("takeoff revoke rejected", err)
	} else {
		steps = append(steps, takeoffStep{Name: "revoke", OK: true, Detail: revokeHash + " committed. Fee paid by the granter feegrant"})
		fmt.Println("takeoff revoke accepted", revokeHash)
	}
	return steps
}

type takeoffStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func (s *Server) shortBalance(ctx context.Context, node, granter, amountText string, includeGrant bool) string {
	amount, err := takeoff.ParseTERP(amountText)
	if err != nil {
		return err.Error()
	}
	terp, thiolNeed, err := takeoff.Required(amount, includeGrant)
	if err != nil {
		return err.Error()
	}
	haveTerp, err := takeoff.Spendable(ctx, node, granter, "uterp")
	if err != nil {
		return err.Error()
	}
	haveThiol, err := takeoff.Spendable(ctx, node, granter, "uthiol")
	if err != nil {
		return err.Error()
	}
	if takeoff.CanCover(haveTerp, terp) && takeoff.CanCover(haveThiol, thiolNeed) {
		return ""
	}
	return "spendable " + takeoff.FormatToken(haveTerp) + " TERP and " + takeoff.FormatToken(haveThiol) + " THIOL, need " + takeoff.FormatToken(terp) + " TERP and " + takeoff.FormatToken(thiolNeed) + " THIOL"
}

func writeTakeoffSteps(w http.ResponseWriter, steps []takeoffStep) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"steps": steps})
}

func (s *Server) SetExportKey(path string) error {
	if path == "" {
		return nil
	}
	secret, _, err := bluetooth.CometSecret(path)
	if err != nil {
		return err
	}
	for i := range secret {
		secret[i] = 0
	}
	s.mu.Lock()
	s.exportKey = path
	s.mu.Unlock()
	return nil
}

func (s *Server) importKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post", 405)
		return
	}
	s.mu.Lock()
	path := s.exportKey
	chain := s.chainID
	s.mu.Unlock()
	secret, pub, err := bluetooth.CometSecret(path)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
	}()
	got, err := bluetooth.DefaultLink().SendKey(r.Context(), chain, secret)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	if !bytes.Equal(got, pub) {
		http.Error(w, "phone stored a different public key", 502)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "imported", "chain": chain})
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

func (s *Server) kmsID(w http.ResponseWriter, _ *http.Request) {
	seed, err := bluetoothStatic()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	pub, err := bluetooth.StaticPublic(seed)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	png, err := qrcode.Encode("zcinti-kms:1:"+base64.StdEncoding.EncodeToString(pub), qrcode.Medium, 256)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
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

func (s *Server) recover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post", 405)
		return
	}
	var body struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	seed, err := bluetoothStatic()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	chain, secret, err := bluetooth.OpenExport(seed, []byte(body.Payload))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
	}()
	if containsForbiddenKeyPath(chain) {
		http.Error(w, "refused", 400)
		return
	}
	pub := append([]byte(nil), secret[32:]...)
	for i := range secret {
		secret[i] = 0
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "recovered",
		"chain":  chain,
		"pubkey": base64.StdEncoding.EncodeToString(pub),
	})
}

func containsForbiddenKeyPath(chain string) bool {
	return strings.Contains(chain, ".kms") || strings.Contains(chain, "/")
}

func (s *Server) qr(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	payload := s.st.Qr
	s.mu.Unlock()
	if payload == "" {
		http.Error(w, "no chain", 404)
		return
	}
	png, err := qrcode.Encode(payload, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}

// Resume starts the scanner again when a phone is already accepted.
// It does not open System Settings.
func (s *Server) Resume() error {
	b, err := os.ReadFile(filepath.Join(bluetooth.Dir, "chosen"))
	if err != nil || s.bin == "" {
		return nil
	}
	code := strings.TrimSpace(string(b))
	if code == "" {
		return nil
	}
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
	if b, err := os.ReadFile(filepath.Join(bluetooth.Dir, "chosen")); err == nil {
		if code := strings.TrimSpace(string(b)); code != "" {
			s.chosen = code
			s.st.Paired = true
		}
	}
	if radio == "on" {
		s.st.Bluetooth = true
		s.st.Radio = radio
	}
	signs := bluetooth.DefaultLink().Recent()
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

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, page)
}

func bytesReader() *fixed {
	return &fixed{b: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}
}

type fixed struct{ b []byte }

func (f *fixed) Read(p []byte) (int, error) {
	n := copy(p, f.b)
	return n, nil
}

const page = `<!doctype html>
<html><head><meta charset="utf-8"><title>zcinti</title>
<style>
body{margin:0;background:#111;color:#eee;font:15px/1.45 ui-sans-serif,system-ui}
main{max-width:920px;margin:0 auto;padding:28px 20px 72px}
.mark{letter-spacing:.16em;font-size:12px;color:#9cf;margin:0}
h1{font-size:28px;margin:4px 0 8px}
.rail{display:flex;gap:8px;margin:18px 0 22px}
.rail span{flex:1;border:1px solid #333;border-radius:999px;padding:8px 10px;color:#888;text-align:center;cursor:pointer}
.rail span.on{color:#eee;border-color:#9cf}
section{border:1px solid #2a2a2a;border-radius:16px;padding:8px 18px;margin:0 0 10px}
section.open{border-color:#456;padding:16px 18px}
section .body{display:none}
section.open .body{display:block}
button.sum{display:block;width:100%;margin:0;padding:10px 0;border:0;background:transparent;color:#eee;text-align:left;font-size:16px}
button.sum small{display:block;color:#999;font-size:12px;font-weight:400}
h2{margin:0 0 8px;font-size:18px}
.step{color:#9cf;font-size:12px;letter-spacing:.12em;margin:0 0 4px}
.row{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
.card{flex:1;min-width:120px;border:1px solid #333;border-radius:12px;padding:10px 12px}
.card div{color:#999;font-size:12px}
.card b{font-variant-numeric:tabular-nums;font-size:18px}
button{margin:0 8px 8px 0;padding:8px 14px;border:1px solid #444;background:#1b1b1b;color:#eee;border-radius:8px}
.pair{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid #2a2a2a}
.logwrap{max-height:220px;overflow:auto;border:1px solid #2a2a2a;border-radius:8px}
table{width:100%;border-collapse:collapse;margin:0;font-size:13px}
.logwrap thead th{position:sticky;top:0;background:#161616}
th,td{text-align:right;padding:4px 8px;border-bottom:1px solid #2a2a2a;font-variant-numeric:tabular-nums}
th:first-child,td:first-child{text-align:left}
img{background:#fff;border-radius:8px;padding:8px}
video{width:100%;max-width:420px;min-height:240px;background:#000;border:1px solid #6ea8fe;border-radius:8px}
textarea,pre{width:100%;box-sizing:border-box;background:#1b1b1b;color:#eee;border:1px solid #333;border-radius:8px;padding:8px;white-space:pre-wrap;word-break:break-all}
#err{color:#f88}
</style></head>
<body><main>
<p class="mark">ZCINTI</p>
<h1>Bluetooth signer</h1>
<p id="where">Terp. This console is not the live Morocco signer.</p>
<p id="need">Waiting for the phone consensus key.</p>
<div class="rail">
<span id="rail1">1 Preflight</span>
<span id="rail2">2 Takeoff</span>
<span id="rail3">3 Flight</span>
<span id="rail4">4 Post flight</span>
</div>

<section id="pre">
<button type="button" class="sum" id="pre-sum">Connect<small id="pre-sub">Scanner and chain QR</small></button>
<div class="body">
<p class="step">PREFLIGHT</p>
<h2>Connect</h2>
<p>Turn the scanner on. On the phone, open a signer key set and scan the chain QR. Then accept the pairing code the phone shows.</p>
<div class="row">
<div class="card"><div>Radio</div><b id="radio">off</b></div>
<div class="card"><div>Session</div><b id="paired">no</b></div>
<div class="card"><div>Chain</div><b id="chain">Terp</b></div>
</div>
<p>
<button id="on">Enable scanner</button>
<button id="off">Stop scanner</button>
</p>
<p id="story"></p>
<div id="live"></div>
<div id="codes"></div>
<p>Chain QR. The phone scans this into one signer key set. It is not a private key.</p>
<img id="qr" alt="Terp chain QR" width="180" height="180" src="/qr.png">
</div>
</section>

<section id="take">
<button type="button" class="sum" id="take-sum">Validator<small id="take-sub">Create until this key is in the set</small></button>
<div class="body">
<p class="step">VALIDATOR</p>
<h2 id="take-title">Create the validator</h2>
<p id="val">Checking the validator set.</p>
<div id="manage" hidden>
<p>Create is finished. This is the management plane for the validator that is already signing.</p>
<p>
<button type="button" id="plane-manage">Manage</button>
<button type="button" id="plane-update">Update</button>
<button type="button" id="plane-rewards">Rewards</button>
<button type="button" id="plane-create">Create again</button>
</p>
<div id="panel-manage">
<p id="manage-line"></p>
<p id="rpc"></p>
<p id="auth"></p>
</div>
<div id="panel-update" hidden>
<p>An edit changes the moniker, commission, or description of this operator. That message is not sent from this page. Create is the only broadcast that is wired.</p>
</div>
<div id="panel-rewards" hidden>
<p>Rewards stay on the validator until a withdraw message is signed. That message is not sent from this page.</p>
</div>
</div>
<div id="create-box">
<p>This runtime generates the ephemeral account. The granter is the Terp account on the phone. When this key is not a validator, scan the QR below with Zigner's account scan, authorize the grant, then scan the signature QR the phone shows.</p>
<p>
<label>Offline granter <input id="granter" readonly placeholder="Waiting for the offline signer"></label>
<label>Moniker <input id="moniker" value="zcinti"></label>
<label>Self delegation TERP <input id="amount" value="1.000000"></label>
</p>
<p><img id="authqr" alt="Authorize on Zigner" width="420" height="420" hidden></p>
<p>Signer tab, Scan. That is the account scan. Hold the phone steady on this code.</p>
<p><button id="scan-sig">Scan signature QR</button></p>
<pre id="sigstatus">Signature scan is idle.</pre>
<p id="authid"></p>
<p id="bal">Checking the granter balance.</p>
<p id="sigcam" hidden><video id="sigvideo" autoplay playsinline muted></video></p>
<p><textarea id="sigpaste" rows="3" placeholder="Or paste ur:cworch-sig/ from the phone"></textarea></p>
<p><button id="sigpastebtn">Submit signature text</button></p>
<p>Self-delegation is TERP. Gas is THIOL. The feegrant is 0.040000 THIOL so it can pay create and, after that fee is paid, the revoke of the authz and the feegrant. A limit of one fee is removed when create pays it.</p>
<p><button id="continue-takeoff">Run create and revoke</button></p>
<pre id="grants"></pre>
</div>
</div>
</section>

<section id="fly" class="open">
<button type="button" class="sum" id="fly-sum">Sign<small id="fly-sub">Height and the latest signatures</small></button>
<div class="body">
<p class="step">FLIGHT</p>
<h2>Sign</h2>
<div class="row">
<div class="card"><div>Health</div><b id="health">down</b></div>
<div class="card"><div>Height</div><b id="h">0</b></div>
<div class="card"><div>Sign round trip</div><b id="lag">—</b></div>
<div class="card"><div>Block interval</div><b id="block">—</b></div>
<div class="card"><div>Since last block</div><b id="since">—</b></div>
</div>
<h2>Recent signatures</h2>
<div class="logwrap">
<table><thead><tr><th>Height</th><th>Round</th><th>Step</th><th>Round trip</th><th>Time</th></tr></thead><tbody id="log"></tbody></table>
</div>
</div>
</section>

<section id="post">
<button type="button" class="sum" id="post-sum">Keys<small id="post-sub">Import and recovery stay out of the way</small></button>
<div class="body">
<p class="step">KEYS</p>
<h2>Move the key</h2>
<p>Do this when the session is finished. Signing does not need this step.</p>
<p><button id="import">Import the configured key over Noise</button></p>
<p>The phone scans the KMS identity, then shows a recovery QR. Paste that QR here. The secret is checked and not written to disk.</p>
<img alt="KMS identity" width="180" height="180" src="/kms-id.png">
<p>Fingerprint <b id="kfp">—</b>. The phone seals a key only after this fingerprint is typed there. The phone does not display the answer.</p>
<p id="phone-pin" hidden>Phone waiting: <b id="phone-fp">—</b> <button id="confirm-phone" type="button">Confirm this phone</button></p>
<p id="phone-held">This phone is not pinned.</p>
<p><textarea id="recover" rows="3" placeholder="Paste the phone recovery QR"></textarea></p>
<p><button id="recoverbtn">Recover key from phone QR</button></p>
</div>
</section>
<p id="err"></p>
<script>
async function api(path, body){
  const r=await fetch(path,{method:body?"POST":"GET",headers:{"Content-Type":"application/json"},body:body?JSON.stringify(body):undefined});
  const text=await r.text();
  let data=null;
  try{ data=JSON.parse(text); }catch(e){ data=null; }
  if(!r.ok) throw new Error(text);
  return data;
}
function mark(id, on){ document.getElementById(id).classList.toggle("on", !!on); }
var focus=null;
var plane="manage";
function autoFocus(s){
  if (s.phone_pending) return "post";
  if (s.link!=="connected") return "pre";
  if (s.consensus_addr && !s.validator) return "take";
  return "fly";
}
function applyFocus(which){
  ["pre","take","fly","post"].forEach(function(id){
    document.getElementById(id).classList.toggle("open", id===which);
  });
}
function showPlane(name){
  plane=name;
  ["manage","update","rewards"].forEach(function(id){
    var panel=document.getElementById("panel-"+id);
    if (panel) panel.hidden = name!==id;
  });
  var create=document.getElementById("create-box");
  if (create) create.hidden = name!=="create";
}
async function refresh(){
  try{
    const s=await api("/api/state");
    const kfp=document.getElementById("kfp");
    if(kfp) kfp.textContent=s.kms_fingerprint||"—";
    const pin=document.getElementById("phone-pin");
    if(pin){
      pin.hidden=!s.phone_pending;
      const fp=document.getElementById("phone-fp");
      if(fp) fp.textContent=s.phone_pending||"—";
    }
    const held=document.getElementById("phone-held");
    if(held) held.textContent=s.phone_pinned?"This phone is pinned. Stop the signer on the phone to leave. Opening the app does not start it again.":(s.phone_pending?"Confirm the fingerprint above.":"This phone is not pinned.");
    const radio=s.radio||"off";
    const codes=Object.keys(s.seen||{});
    document.getElementById("radio").textContent=radio;
    document.getElementById("paired").textContent = s.link==="connected"
      ? ("live "+(s.chosen||""))
      : (s.chosen ? "waiting" : "no");
    document.getElementById("health").textContent=s.healthy?"signing":"down";
    document.getElementById("h").textContent=s.height||0;
    document.getElementById("lag").textContent=(s.last_latency_ms?s.last_latency_ms+" ms":"—");
    document.getElementById("block").textContent=(s.block_ms?s.block_ms+" ms":"—");
    document.getElementById("since").textContent=((s.lag_ms||0)+" ms");
    document.getElementById("chain").textContent=s.chain_id?("Terp · "+s.chain_id):"Terp";
    document.getElementById("where").textContent="Terp"+(s.chain_id?" · "+s.chain_id:"")+". This console is not the live Morocco signer.";
    document.getElementById("on").textContent=radio==="on"?"Scanner on":"Enable scanner";
    const connected = s.link==="connected";
    mark("rail1", !connected);
    mark("rail2", !!s.consensus_addr && !s.validator);
    mark("rail3", !!s.healthy);
    mark("rail4", !!s.healthy);
    mark("take", !!s.consensus_addr && !s.validator);
    document.getElementById("rpc").textContent = "RPC "+(s.node_url||"");
    var val = "Waiting for the phone consensus key.";
    if (s.consensus_addr && s.validator) val = "Validator "+s.consensus_addr+".";
    else if (s.consensus_addr) val = "Not a validator "+s.consensus_addr+".";
    document.getElementById("val").textContent = val;
    document.getElementById("need").textContent = !s.consensus_addr
      ? "Waiting for the phone consensus key."
      : (s.validator
        ? ("Validator "+s.consensus_addr+".")
        : ("Not a validator "+s.consensus_addr+". Authorize create-validator with Zigner's account scan."));
    var qr=document.getElementById("authqr");
    if (s.auth_kind==="ready") {
      qr.hidden=true;
    } else if (s.consensus_addr && !s.validator && s.granter) {
      if (qr.getAttribute("data-for")!==s.granter) {
        qr.src="/takeoff-qr.png?g="+encodeURIComponent(s.granter)+"&t="+Date.now();
        qr.setAttribute("data-for", s.granter);
      }
      qr.hidden=false;
      qr.onerror=function(){
        fetch("/takeoff-qr.png").then(function(r){return r.text()}).then(function(t){
          document.getElementById("err").textContent=t;
        });
      };
    } else {
      qr.hidden=true;
    }
    document.getElementById("granter").value = s.granter || "";
    var auth="Authorization "+(s.auth_id||"")+". Sign this code, then scan that signature.";
    if (s.auth_kind==="ready") auth="Feegrant is already registered for "+(s.ephemeral||"this ephemeral account")+". Create-validator and revoke authz are already registered. Press Run create and revoke.";
    else if (s.auth_kind==="omit-fee") auth="Feegrant is already registered, so this code omits it. It grants only what is missing.";
    document.getElementById("authid").textContent = (s.granter && s.ephemeral) ? auth : "";
    view=s;
    paintMoney();
    document.getElementById("auth").textContent = s.ephemeral
      ? ("Ephemeral "+s.ephemeral+". "+(s.granter ? "Granter "+s.granter+" came from the offline signer." : "Waiting for the Terp account from the offline signer."))
      : "This runtime is generating the ephemeral account.";
    mark("pre", !connected);
    mark("fly", connected);
    mark("post", !!s.healthy);
    let story="Enable the scanner. This scan is separate from the laptop Bluetooth device list.";
    if(radio==="unauthorized") story="macOS has not allowed KMS Bluetooth. System Settings, Privacy and Security, Bluetooth, turn on KMS Bluetooth.";
    else if(radio==="starting") story="Scanner is starting.";
    else if(s.healthy) story="The phone is returning signatures.";
    else if(s.chosen && s.link!=="connected") story="The code is accepted. The phone is not on this GATT session yet. Turn Bluetooth on and start that signer.";
    else if(radio==="on" && codes.length===0) story="Scanning. Scan the chain QR on the phone, then wait for its pairing code.";
    else if(radio==="on") story="Accept the code shown on the phone, or reject it.";
    document.getElementById("story").textContent=story;
    const live=document.getElementById("live");
    live.innerHTML="";
    if(s.chosen){
      const row=document.createElement("div");
      row.className="pair";
      const label=document.createElement("span");
      label.textContent="Accepted "+s.chosen;
      const drop=document.createElement("button");
      drop.textContent="Reject";
      drop.onclick=function(){ api("/api/reject",{code:s.chosen}).then(refresh).catch(function(e){ document.getElementById("err").textContent=e.message; }); };
      row.appendChild(label);
      row.appendChild(drop);
      live.appendChild(row);
    }
    const box=document.getElementById("codes");
    box.innerHTML="";
    codes.forEach(function(code){
      if(code===s.chosen) return;
      const row=document.createElement("div");
      row.className="pair";
      const label=document.createElement("span");
      label.textContent="New code "+code;
      const accept=document.createElement("button");
      accept.textContent="Accept";
      accept.onclick=function(){ api("/api/pair",{code:code}).then(refresh).catch(function(e){ document.getElementById("err").textContent=e.message; }); };
      const reject=document.createElement("button");
      reject.textContent="Reject";
      reject.onclick=function(){ api("/api/reject",{code:code}).then(refresh).catch(function(e){ document.getElementById("err").textContent=e.message; }); };
      row.appendChild(label);
      row.appendChild(accept);
      row.appendChild(reject);
      box.appendChild(row);
    });
    var managing=!!(s.consensus_addr && s.validator);
    document.getElementById("manage").hidden=!managing;
    document.getElementById("take-title").textContent=managing?"Validator":"Create the validator";
    document.getElementById("take-sub").textContent=managing?"In the set. Open this only to manage it.":"This key is not a validator yet.";
    document.getElementById("pre-sub").textContent=connected?"Connected. Open this to pair or show the chain QR.":"Scanner and chain QR.";
    document.getElementById("fly-sub").textContent=(s.healthy?"Signing":"Not signing")+" · height "+(s.height||0);
    document.getElementById("post-sub").textContent=s.phone_pending?"Confirm the phone fingerprint.":(s.phone_pinned?"Phone is pinned.":"Import and recovery.");
    var line=document.getElementById("manage-line");
    if (line) line.textContent=managing?("Operator "+s.consensus_addr+".") : "";
    if (!managing) document.getElementById("create-box").hidden=false;
    else showPlane(plane);
    applyFocus(focus || autoFocus(s));
    const log=document.getElementById("log");
    log.innerHTML="";
    (s.signs||[]).slice().reverse().forEach(function(row){
      const tr=document.createElement("tr");
      [row.height, row.round, row.step, (row.latency_ms+" ms"), row.at].forEach(function(cell){
        const td=document.createElement("td");
        td.textContent=cell;
        tr.appendChild(td);
      });
      log.appendChild(tr);
    });
    document.getElementById("err").textContent=s.error||"";
  }catch(e){document.getElementById("err").textContent=e.message}
}
["pre","take","fly","post"].forEach(function(id, i){
  document.getElementById("rail"+(i+1)).onclick=function(){ focus=id; refresh(); };
  document.getElementById(id+"-sum").onclick=function(){ focus=id; refresh(); };
});
["manage","update","rewards","create"].forEach(function(name){
  document.getElementById("plane-"+name).onclick=function(){ showPlane(name); };
});
document.getElementById("on").onclick=function(){ api("/api/bluetooth",{enabled:true}).then(refresh).catch(function(e){ document.getElementById("err").textContent=e.message; }); };
document.getElementById("off").onclick=function(){ api("/api/bluetooth",{enabled:false}).then(refresh).catch(function(e){ document.getElementById("err").textContent=e.message; }); };
document.getElementById("import").onclick=function(){ api("/api/import",{}).then(function(){ document.getElementById("err").textContent="Key imported on the phone."; }).catch(function(e){ document.getElementById("err").textContent=e.message; }); };
const confirmPhone=document.getElementById("confirm-phone");
if(confirmPhone) confirmPhone.onclick=function(){ api("/api/confirm-phone",{}).then(function(){ document.getElementById("err").textContent="Phone pinned."; refresh(); }).catch(function(e){ document.getElementById("err").textContent=e.message; }); };
var view=null;
function tokens(micro){
  var v=BigInt(micro||"0");
  var neg=v<0n;
  if (neg) v=-v;
  var whole=v/1000000n;
  var frac=(v%1000000n).toString().padStart(6,"0");
  return (neg?"-":"")+whole+"."+frac;
}
function toMicro(text){
  text=(text||"").trim();
  if (!/^\d+(\.\d{0,6})?$/.test(text)) return null;
  var parts=text.split(".");
  var frac=(parts[1]||"").padEnd(6,"0").slice(0,6);
  return BigInt(parts[0]+frac);
}
function paintMoney(){
  var s=view;
  var scan=document.getElementById("scan-sig");
  var go=document.getElementById("continue-takeoff");
  var qr=document.getElementById("authqr");
  if (!s || !s.granter || s.balance==="" || s.thiol==="") {
    document.getElementById("bal").textContent = s && s.granter ? "Balance is not available yet." : "Waiting for the granter before checking the balance.";
    if (scan) scan.disabled=true;
    if (go) go.disabled=true;
    return;
  }
  var del=toMicro(document.getElementById("amount").value);
  if (del===null) {
    document.getElementById("bal").textContent="Self-delegation must be TERP with up to 6 decimals.";
    if (scan) scan.disabled=true;
    if (go) go.disabled=true;
    if (qr) qr.hidden=true;
    return;
  }
  var grant=BigInt(s.auth_kind==="ready" ? "0" : (s.grant_fee||"0"));
  var run=BigInt(s.run_fee||"0");
  var thiolNeed=grant+run;
  var haveTerp=BigInt(s.balance||"0");
  var haveThiol=BigInt(s.thiol||"0");
  var ok=haveTerp>=del && haveThiol>=thiolNeed;
  document.getElementById("bal").textContent="Spendable "+tokens(haveTerp)+" TERP and "+tokens(haveThiol)+" THIOL. Required "+tokens(del)+" TERP and "+tokens(thiolNeed)+" THIOL."+(ok?" Enough to authorize.":" Not enough to authorize. Scanning stays off.");
  if (scan) scan.disabled=!ok;
  if (go) go.disabled=!ok;
  if (!ok && qr) qr.hidden=true;
}
document.getElementById("amount").oninput=paintMoney;
function sigStatus(text){ document.getElementById("sigstatus").textContent=text; }
function submitSignature(payload){
  sigStatus("Signature read.\nverify · waiting\ngrant · waiting\ncreate · waiting\nrevoke · waiting");
  return api("/api/takeoff/signature",{
    payload:payload,
    moniker:document.getElementById("moniker").value,
    amount:document.getElementById("amount").value
  }).then(function(s){
    if (!s.steps) { sigStatus("No step result."); return; }
    sigStatus(s.steps.map(function(st){
      return (st.ok?"ok":"failed")+" · "+st.name+" · "+st.detail;
    }).join("\n"));
  }).catch(function(e){
    sigStatus("failed · request · "+e.message);
  });
}
document.getElementById("continue-takeoff").onclick=function(){
  sigStatus("create · waiting\nrevoke · waiting");
  api("/api/takeoff/continue",{
    moniker:document.getElementById("moniker").value,
    amount:document.getElementById("amount").value
  }).then(function(s){
    if (!s.steps) { sigStatus("No step result."); return; }
    sigStatus(s.steps.map(function(st){
      return (st.ok?"ok":"failed")+" · "+st.name+" · "+st.detail;
    }).join("\n"));
  }).catch(function(e){ sigStatus("failed · request · "+e.message); });
};
document.getElementById("sigpastebtn").onclick=function(){
  var payload=(document.getElementById("sigpaste").value||"").trim();
  if (!payload) { sigStatus("Paste the signature QR text first."); return; }
  submitSignature(payload);
};
document.getElementById("scan-sig").onclick=function(){
  var box=document.getElementById("sigcam");
  var video=document.getElementById("sigvideo");
  box.hidden=false;
  sigStatus("Opening the camera.");
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    sigStatus("This browser has no camera API. Paste the signature QR text instead.");
    return;
  }
  if (!window.BarcodeDetector) {
    sigStatus("This browser cannot read QR codes. Paste the signature QR text instead. The camera preview stays up so you can see it is the right page.");
  }
  navigator.mediaDevices.getUserMedia({video:true}).then(function(stream){
    video.srcObject=stream;
    video.play();
    sigStatus(window.BarcodeDetector ? "Camera is on. Hold the phone's signature QR in the frame." : "Camera is on, but this browser cannot decode it. Paste the signature text.");
    if (!window.BarcodeDetector) return;
    var det=new BarcodeDetector({formats:["qr_code"]});
    var detect=async function(){
      if (box.hidden) return;
      try {
        if (video.readyState >= 2) {
          var codes=await det.detect(video);
          if (codes.length && codes[0].rawValue) {
            var raw=codes[0].rawValue;
            if (raw.toLowerCase().indexOf("ur:cworch-sig/")===0) {
              stream.getTracks().forEach(function(t){ t.stop(); });
              box.hidden=true;
              submitSignature(raw);
              return;
            }
            sigStatus("Saw a QR, not the signature. It starts with "+raw.slice(0,24));
          }
        }
      } catch (e) {
        sigStatus("Camera read failed. "+e.message);
      }
      setTimeout(detect, 400);
    };
    detect();
  }).catch(function(e){
    sigStatus("Camera was refused. "+e.message+" Paste the signature QR text instead.");
  });
};
document.getElementById("recoverbtn").onclick=function(){
  api("/api/recover",{payload:document.getElementById("recover").value}).then(function(s){
    document.getElementById("err").textContent="Recovered "+(s.chain||"")+" public "+(s.pubkey||"");
  }).catch(function(e){ document.getElementById("err").textContent=e.message; });
};
refresh(); setInterval(refresh, 2000);
</script>
</main></body></html>`
