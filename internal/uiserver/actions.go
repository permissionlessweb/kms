package uiserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cosmos/kms/internal/takeoff"
)

// pendingAction is one reviewed action waiting for its grant and submit.
type pendingAction struct {
	req      takeoff.ActionRequest
	inner    []*anypb.Any
	review   takeoff.Review
	rpc      string
	chain    string
	prepared takeoff.Prepared
	result   *actionResult
	qrAt     time.Time
	history  []takeoff.Prepared // earlier QRs, to explain a stale signature
	verified *takeoff.SigCheck  // a scanned signature that verified for prepared
}

// qrTTL is how long one sign QR is offered before it is rebuilt.
const qrTTL = 10 * time.Minute

// actionResult is the one tx's on-chain outcome and the validator after it.
type actionResult struct {
	Tx        takeoff.TxOutcome `json:"tx"`
	Error     string            `json:"error,omitempty"`
	Jailed    *bool             `json:"jailed,omitempty"`
	Status    string            `json:"status,omitempty"`
	Tokens    string            `json:"tokens,omitempty"`
	PowerNote string            `json:"power_note,omitempty"`
	Summary   string            `json:"summary"`
}

type actionState struct {
	mu      sync.Mutex
	pending map[string]*pendingAction // validator tab id -> action
	now     func() time.Time
	// send is swapped by tests; nil means takeoff.BroadcastSigned.
	send func(ctx context.Context, rpc string, p takeoff.Prepared, pub, sig []byte) (takeoff.TxOutcome, error)
}

// SetReadOnly makes the console a viewer: every state-changing POST except
// pure planning (review, tab select) is refused, nothing is broadcast.
func (s *Server) SetReadOnly(on bool) {
	s.mu.Lock()
	s.readOnly = on
	s.mu.Unlock()
}

// EnableToken requires a per-run token on every POST. The token is embedded
// in the page and sent back in X-KMS-Token, so a page from another origin
// that guesses the port still cannot drive the console.
func (s *Server) EnableToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	s.mu.Lock()
	s.token = hex.EncodeToString(b)
	t := s.token
	s.mu.Unlock()
	return t
}

// readOnlySafe are POSTs that compute but change nothing.
var readOnlySafe = map[string]bool{
	"/api/actions/review":     true,
	"/api/validators/select":  true,
	"/api/validators/refresh": true,
}

// allowPost is the token and read-only half of guard.
func (s *Server) allowPost(r *http.Request) (int, string) {
	s.mu.Lock()
	token, ro := s.token, s.readOnly
	s.mu.Unlock()
	if token != "" && r.Header.Get("X-KMS-Token") != token {
		return http.StatusForbidden, "refused: missing console token (reload the page)"
	}
	if ro && !readOnlySafe[r.URL.Path] {
		return http.StatusLocked, "read-only preview: this console does not change state or broadcast"
	}
	return 0, ""
}

func (s *Server) registerActions(mux *http.ServeMux) {
	if s.acts.pending == nil {
		s.acts.pending = map[string]*pendingAction{}
	}
	mux.HandleFunc("/api/actions/holdings", s.actionHoldings)
	mux.HandleFunc("/api/actions/owner-pubkey", s.ownerPubkey) // pure check, no state change: works in read-only too
	mux.HandleFunc("/jsqr.js", serveJSQR)
	mux.HandleFunc("/api/actions/review", s.guard(s.actionReview))
	mux.HandleFunc("/api/actions/grant", s.actionGrant)
	mux.HandleFunc("/api/actions/verify", s.actionVerify) // pure check, nothing is sent: works in read-only too
	mux.HandleFunc("/api/actions/signature", s.guard(s.actionSignature))
	mux.HandleFunc("/api/actions/cancel", s.guard(s.actionCancel))
}

func (s *Server) actNow() time.Time {
	if s.acts.now != nil {
		return s.acts.now()
	}
	return time.Now()
}

// tabTarget is the rpc and on-chain chain id of a validator tab.
func (s *Server) tabTarget(id string) (rpc, chain string, ok bool) {
	v, found := s.lookup(id)
	if !found || v.RPC == "" {
		return "", "", false
	}
	return v.RPC, v.ChainID, true
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) actionHoldings(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	granter := strings.TrimSpace(r.URL.Query().Get("granter"))
	rpc, _, ok := s.tabTarget(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "this tab has no rpc in its config"})
		return
	}
	if !takeoff.ValidAccount(granter) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"errors": []takeoff.FieldError{{Field: "granter", Message: "enter the terp1… account that owns the validator"}}})
		return
	}
	val := r.URL.Query().Get("validator")
	if val == "" {
		val = takeoff.ValoperOf(granter)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	h, err := takeoff.QueryHoldings(ctx, rpc, granter, val)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "rpc: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"holdings":       h,
		"rate_pct":       takeoff.DecPercent(h.Validator.Rate),
		"max_rate_pct":   takeoff.DecPercent(h.Validator.MaxRate),
		"max_change_pct": takeoff.DecPercent(h.Validator.MaxChangeRate),
		"fmt": map[string]string{
			"spendable":  takeoff.FormatToken(h.Spendable),
			"thiol":      takeoff.FormatToken(h.Thiol),
			"delegated":  takeoff.FormatToken(h.Delegated),
			"rewards":    takeoff.FormatToken(h.Rewards),
			"commission": takeoff.FormatToken(h.Commission),
		},
	})
}

func (s *Server) actionReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID  string                `json:"id"`
		Req takeoff.ActionRequest `json:"request"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	rpc, chain, ok := s.tabTarget(body.ID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "this tab has no rpc in its config"})
		return
	}
	if _, err := takeoff.ParseAction(string(body.Req.Action)); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"errors": []takeoff.FieldError{{Field: "action", Message: err.Error()}}})
		return
	}
	if !takeoff.ValidAccount(body.Req.Granter) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"errors": []takeoff.FieldError{{Field: "granter", Message: "enter the terp1… account that owns the validator"}}})
		return
	}
	val := body.Req.Validator
	if val == "" {
		val = takeoff.ValoperOf(body.Req.Granter)
	}
	if body.Req.Action == takeoff.ActionCreate {
		// The consensus key is always this slot's phone key, never a typed one.
		v, _ := s.lookup(body.ID)
		pub, ok := phonePubHex(v)
		if !ok {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"errors": []takeoff.FieldError{{Field: "consensus_pubkey_hex", Message: "the phone has not published a key for this slot yet"}}})
			return
		}
		forgetOnchain()
		if oc := onchainFor(rpc, pub); !oc.Checked || oc.Found {
			msg := "could not check the chain for this key; try again"
			if oc.Found {
				msg = "this slot's key is already validator " + oc.Valoper
			}
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"errors": []takeoff.FieldError{{Field: "action", Message: msg}}})
			return
		}
		body.Req.Create.ConsPubHex = pub
		body.Req.Validator = ""
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	h, err := takeoff.QueryHoldings(ctx, rpc, body.Req.Granter, val)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "rpc: " + err.Error()})
		return
	}
	inner, rv, errs := takeoff.BuildAction(body.Req, h, s.actNow())
	if errs != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"errors": errs})
		return
	}
	s.acts.mu.Lock()
	s.acts.pending[body.ID] = &pendingAction{req: body.Req, inner: inner, review: rv, rpc: rpc, chain: chain}
	s.acts.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"review": rv})
}

func (s *Server) pending(id string) *pendingAction {
	s.acts.mu.Lock()
	defer s.acts.mu.Unlock()
	return s.acts.pending[id]
}

// actionGrant is the live sign QR for the reviewed action: one tx, signed
// by the owner, carrying the action messages directly. It is rebuilt when
// the owner's sequence moves (the old QR could no longer verify) or after
// qrTTL.
func (s *Server) actionGrant(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	p := s.pending(id)
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "review an action first"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	acct, seq, err := takeoff.AccountNumbers(ctx, p.rpc, p.req.Granter)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "owner account: " + err.Error()})
		return
	}
	now := s.actNow()
	s.acts.mu.Lock()
	cached, qrAt, done := p.prepared, p.qrAt, p.result != nil && p.result.Tx.Stage != "rejected"
	s.acts.mu.Unlock()
	fresh := now.Sub(qrAt) < qrTTL && cached.Granter == p.req.Granter && cached.Account == acct && cached.Sequence == seq && cached.Kind == "direct"
	if !fresh && !done {
		prepared, err := takeoff.PrepareDirect(p.req.Granter, p.chain, acct, seq, p.inner)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		s.acts.mu.Lock()
		if len(p.prepared.Amino) > 0 {
			p.history = append(p.history, p.prepared)
			if len(p.history) > 8 {
				p.history = p.history[len(p.history)-8:]
			}
		}
		p.prepared, p.qrAt, p.verified = prepared, now, nil
		cached, qrAt = prepared, now
		s.acts.mu.Unlock()
	}
	s.acts.mu.Lock()
	verified := p.verified != nil && p.verified.AuthID == cached.ID()
	s.acts.mu.Unlock()
	out := map[string]any{
		"kind": cached.Kind, "auth_id": cached.ID(), "account": acct, "sequence": seq,
		"chain_id": p.chain, "qr_expires_at": qrAt.Add(qrTTL).Format(time.RFC3339),
		"verified": verified, "fee_uthiol": cached.Fee, "gas": cached.Gas, "memo": cached.Memo,
		"msg_count": len(cached.Msgs),
	}
	if len(cached.PNG) > 0 {
		out["png"] = base64.StdEncoding.EncodeToString(cached.PNG)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) actionSignature(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID      string `json:"id"`
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	p := s.pending(body.ID)
	if p == nil || len(p.prepared.Amino) == 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no sign QR is showing for this action"})
		return
	}
	var pub, sig []byte
	var err error
	s.acts.mu.Lock()
	v := p.verified
	s.acts.mu.Unlock()
	if strings.TrimSpace(body.Payload) == "" {
		if v == nil || v.AuthID != p.prepared.ID() {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "scan and verify the phone's signature for the QR shown now"})
			return
		}
		pub, sig = v.Pub, v.NormSig
	} else if pub, sig, err = takeoff.DecodeCworch(body.Payload); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"errors": []takeoff.FieldError{{Field: "payload", Message: err.Error()}}})
		return
	}
	s.acts.mu.Lock()
	prepared := p.prepared
	if p.result != nil && p.result.Tx.Stage != "rejected" {
		s.acts.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]any{"error": "this action was already broadcast", "result": p.result})
		return
	}
	s.acts.mu.Unlock()
	if _, _, err := takeoff.MatchAuthorization(pub, sig, prepared.Amino); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"errors": []takeoff.FieldError{{Field: "payload", Message: err.Error() + " (QR " + prepared.ID() + ")"}}})
		return
	}
	send := s.acts.send
	if send == nil {
		send = takeoff.BroadcastSigned
	}
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	out, err := send(ctx, p.rpc, prepared, pub, sig)
	res := &actionResult{Tx: out}
	if err != nil {
		res.Error = err.Error()
	}
	if out.Stage == "committed" {
		val := p.req.Validator
		if val == "" {
			val = takeoff.ValoperOf(p.req.Granter)
		}
		qctx, qcancel := context.WithTimeout(r.Context(), 6*time.Second)
		if info, found, qerr := takeoff.QueryValidator(qctx, p.rpc, val); qerr == nil && found {
			j := info.Jailed
			res.Jailed, res.Status, res.Tokens = &j, info.Status, info.Tokens
			res.PowerNote = takeoff.PowerNote(info.Tokens)
		}
		qcancel()
	}
	res.Summary = summarize(p.req.Action, res)
	s.acts.mu.Lock()
	p.result = res
	s.acts.mu.Unlock()
	if p.req.Action == takeoff.ActionUnjail {
		forgetJail()
	}
	code := http.StatusOK
	if err != nil {
		code = http.StatusBadGateway
	}
	writeJSON(w, code, res)
}

// summarize is the one-line on-chain result shown after the broadcast.
func summarize(a takeoff.Action, r *actionResult) string {
	switch r.Tx.Stage {
	case "rejected":
		return "Not broadcast: the node rejected the tx. Nothing changed on chain."
	case "failed":
		return "Included in block " + itoa(r.Tx.Height) + " but failed; nothing changed except the fee."
	case "pending":
		return "Accepted by the node; not in a block yet. Check the hash shortly."
	}
	s := "Committed in block " + itoa(r.Tx.Height) + "."
	if a == takeoff.ActionUnjail && r.Jailed != nil {
		if *r.Jailed {
			s += " The validator is still jailed."
		} else {
			s += " The validator left jail."
		}
	}
	if r.PowerNote != "" {
		s += " Not in the active set: " + r.PowerNote + "."
	} else if r.Status != "" && r.Status != "BOND_STATUS_BONDED" {
		s += " Status " + strings.TrimPrefix(r.Status, "BOND_STATUS_") + "; it joins the active set at the next block if its stake ranks."
	}
	return s
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func (s *Server) actionCancel(w http.ResponseWriter, r *http.Request) {
	id, err := readID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.acts.mu.Lock()
	delete(s.acts.pending, id)
	s.acts.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

// actionVerify reads the phone's signature QR frames and checks the
// secp256k1 signature against the exact sign bytes of the QR on screen and
// the owner key. It never broadcasts. Multipart QRs report progress.
func (s *Server) actionVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID       string   `json:"id"`
		Frames   []string `json:"frames"`
		OwnerHex string   `json:"owner_pubkey_hex"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	p := s.pending(body.ID)
	s.acts.mu.Lock()
	var cur takeoff.Prepared
	var prev []takeoff.Prepared
	if p != nil {
		cur, prev = p.prepared, append([]takeoff.Prepared(nil), p.history...)
	}
	s.acts.mu.Unlock()
	if p == nil || len(cur.Amino) == 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no sign QR is showing for this action"})
		return
	}
	parts := takeoff.AssembleSigQR(body.Frames)
	if parts.Error != "" {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"ok": false, "mismatch": "format", "reason": parts.Error})
		return
	}
	if parts.Done == nil {
		writeJSON(w, http.StatusOK, map[string]any{"progress": map[string]int{"have": parts.Have, "need": parts.Need}})
		return
	}
	owner, _ := hex.DecodeString(strings.TrimSpace(body.OwnerHex))
	if len(owner) != 33 {
		owner = nil
		ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
		pk, err := accountPubKey(ctx, p.rpc, p.req.Granter)
		cancel()
		if err == nil && len(pk) == 33 {
			owner = pk
		}
	}
	c := takeoff.CheckSignature(*parts.Done, owner, p.req.Granter, cur, p.chain, prev)
	if c.OK {
		s.acts.mu.Lock()
		if p.prepared.ID() == c.AuthID {
			p.verified = &c
		}
		s.acts.mu.Unlock()
	}
	code := http.StatusOK
	if !c.OK {
		code = http.StatusUnprocessableEntity
	}
	writeJSON(w, code, c)
}
