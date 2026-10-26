package uiserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"time"

	"github.com/cosmos/kms/config"
	"github.com/cosmos/kms/signing/bluetooth"
	qrcode "github.com/skip2/go-qrcode"
)

// Move a validator's consensus key from one phone to another. The key goes
// phone-to-phone by QR code only; this console never sees key bytes and no
// key crosses Bluetooth or the network.
//
//	start   check the owner binding, freeze the slot, floor = last signed
//	        height + handoffMargin, new nonce; show the start QR
//	        (old phone scans it; new phone shows a receive QR; old phone
//	        shows the sealed key; new phone imports and shows an ack; old
//	        phone tombstones the key and shows a signed retire proof)
//	retire  verify the retire proof (key, chain, slot, floor, nonce, target);
//	        tombstone, drop the old phone's pin for this slot
//	pair    the new phone connects over Bluetooth; its identity must be the
//	        retire proof's target; pin it for this slot
//	finish  unfreeze; the floor stays
//
// The slot never signs while frozen, and the key is on at least one phone
// at every step. Cancel is allowed only before the retire proof.

const handoffMargin = 10

// handoffTTL: a move whose key was not yet sent (no retire proof) is
// cancelled after this long; the floor stays. Matches the phone receive TTL.
const handoffTTL = 15 * time.Minute

var handoffNow = time.Now

type move struct {
	label, chain, slot string
	nonce              [bluetooth.NonceSize]byte
	floor              uint64
	old                []byte
	pub                []byte
	target             []byte
	stage              string
	started            int64
}

var (
	movesMu   sync.Mutex
	moves     = map[string]*move{}
	kmsStatic = bluetoothStatic
)

func (s *Server) registerHandoff(mux *http.ServeMux) {
	mux.HandleFunc("/api/handoff/state", localGet(s.handoffState))
	mux.HandleFunc("/api/handoff/qr.png", localGet(s.handoffQR))
	for _, n := range []string{"start", "retire", "pair", "finish", "cancel"} {
		mux.HandleFunc("/api/handoff/"+n, s.guard(s.handoffStep(n)))
	}
	mux.HandleFunc("/move.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, moveJS)
	})
}

// lastSigned reads the FilePV state of v's slot.
func lastSigned(v ValidatorView) (uint64, error) {
	c, err := config.Load(v.Source)
	if err != nil {
		return 0, err
	}
	home := filepath.Dir(v.Source)
	for _, ch := range c.Chains {
		if ch.ID != v.Slot {
			continue
		}
		path := config.AbsPath(home, ch.StateFile)
		if ch.StateFile == "" {
			path = filepath.Join(home, "state", slotKeyLabel(v)+".json")
		}
		return readStateHeight(path)
	}
	return 0, fmt.Errorf("slot %s not in %s", v.Slot, v.Source)
}

func readStateHeight(path string) (uint64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var st struct {
		Height json.RawMessage `json:"height"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return 0, err
	}
	h := strings.Trim(string(st.Height), `"`)
	return strconv.ParseUint(h, 10, 64)
}

// handoffPayload is the start QR the old phone scans in Move out.
func handoffPayload(m *move, kmsPub []byte) string {
	return fmt.Sprintf("%s%s:%s:%s:%d:%s", bluetooth.MoveStartPrefix, m.chain, m.slot, hex.EncodeToString(m.nonce[:]), m.floor, base64.StdEncoding.EncodeToString(kmsPub))
}

func kmsPublic() ([]byte, error) {
	seed, err := kmsStatic()
	if err != nil {
		return nil, err
	}
	defer zero(seed)
	return bluetooth.StaticPublic(seed)
}

func (s *Server) handoffQR(w http.ResponseWriter, r *http.Request) {
	v, ok := s.lookup(r.URL.Query().Get("id"))
	if !ok {
		http.Error(w, "unknown validator", 404)
		return
	}
	label := slotKeyLabel(v)
	movesMu.Lock()
	m := moves[label]
	if m == nil {
		if h, _ := bluetooth.GetHandoff(label); h.Frozen && h.Nonce != "" {
			m, _ = moveFromHandoff(label, h)
		}
	}
	movesMu.Unlock()
	if m == nil || m.stage != "retire" {
		http.Error(w, "no start QR at this stage", 409)
		return
	}
	pub, err := kmsPublic()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	png, err := qrcode.Encode(handoffPayload(m, pub), qrcode.Medium, 280)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

type handoffView struct {
	Stage     string `json:"stage"`
	Frozen    bool   `json:"frozen"`
	Floor     uint64 `json:"floor"`
	OldFP     string `json:"old_fp"`
	PendingFP string `json:"pending_fp"`
	TargetFP  string `json:"target_fp"`
	KmsFP     string `json:"kms_fp"`
	KeyID     string `json:"key_id"`
	Owner     string `json:"owner"`
	Retired   bool   `json:"retired"`
}

func fpHex(b []byte) string {
	if len(b) != 32 {
		return ""
	}
	return strings.ReplaceAll(bluetooth.Fingerprint(b), " ", "")
}

// resume rebuilds a move from the handoff file after a console restart.
// localGet refuses reads whose Host is not loopback (DNS rebinding).
func localGet(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localHost(r.Host) {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// expireStale cancels an unsent move older than handoffTTL. Callers hold movesMu.
func expireStale(label string) bool {
	h, err := bluetooth.GetHandoff(label)
	if err != nil || !h.Frozen || h.Sent || h.StartedAt == 0 {
		return false
	}
	if handoffNow().Sub(time.Unix(h.StartedAt, 0)) <= handoffTTL {
		return false
	}
	if bluetooth.SetHandoff(label, bluetooth.Handoff{Frozen: false, Floor: h.Floor}) != nil {
		return false
	}
	delete(moves, label)
	return true
}

func resume(label string) *move {
	expireStale(label)
	if m := moves[label]; m != nil {
		return m
	}
	h, _ := bluetooth.GetHandoff(label)
	if !h.Frozen || h.Nonce == "" {
		return nil
	}
	m, err := moveFromHandoff(label, h)
	if err != nil {
		return nil
	}
	moves[label] = m
	return m
}

func (s *Server) handoffState(w http.ResponseWriter, r *http.Request) {
	v, ok := s.lookup(r.URL.Query().Get("id"))
	if !ok {
		http.Error(w, "unknown validator", 404)
		return
	}
	label := slotKeyLabel(v)
	h, _ := bluetooth.GetHandoff(label)
	out := handoffView{Stage: "idle", Frozen: h.Frozen, Floor: h.Floor, PendingFP: fpHex(bluetooth.PendingPub())}
	if pub, err := kmsPublic(); err == nil {
		out.KmsFP = fpHex(pub)
	}
	out.OldFP = fpHex(bluetooth.SlotPinPub(label))
	if o, ok := s.ownerStore().get(v.ID); ok {
		out.Owner = o.Granter
	}
	movesMu.Lock()
	if m := resume(label); m != nil {
		out.Stage, out.TargetFP, out.KeyID = m.stage, fpHex(m.target), bluetooth.KeyIDHex(m.pub)
		if m.old != nil {
			out.OldFP = fpHex(m.old)
		}
		out.Retired = m.stage == "pair" || m.stage == "finish"
	} else if h.Frozen {
		out.Stage = "frozen"
		if _, ok := bluetooth.LastTombstone(label); ok {
			out.Retired = true
		}
	}
	movesMu.Unlock()
	writeJSON(w, 200, out)
}

func (s *Server) handoffStep(step string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", 405)
			return
		}
		var body struct {
			ID string `json:"id"`
			QR string `json:"qr"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		v, ok := s.lookup(body.ID)
		if !ok {
			http.Error(w, "unknown validator", 404)
			return
		}
		if v.Signer != "phone" {
			http.Error(w, "only phone-signed slots move between phones", 409)
			return
		}
		movesMu.Lock()
		defer movesMu.Unlock()
		res, err := s.doStep(r.Context(), step, v, strings.TrimSpace(body.QR))
		if err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		writeJSON(w, 200, res)
	}
}

func (m *move) persist(sent bool) error {
	h := bluetooth.Handoff{Frozen: true, Floor: m.floor, Sent: sent, Chain: m.chain, Slot: m.slot,
		Nonce: hex.EncodeToString(m.nonce[:]), KeyPub: hex.EncodeToString(m.pub), Old: hex.EncodeToString(m.old), StartedAt: m.started}
	if m.target != nil {
		h.Target = hex.EncodeToString(m.target)
	}
	return bluetooth.SetHandoff(m.label, h)
}

func (s *Server) doStep(_ context.Context, step string, v ValidatorView, qr string) (map[string]any, error) {
	label := slotKeyLabel(v)
	m := resume(label)
	need := func(stage string) error {
		if m == nil {
			return errors.New("no move in progress; start again")
		}
		if m.stage != stage {
			return fmt.Errorf("move is at %q, not %q", m.stage, stage)
		}
		return nil
	}
	switch step {
	case "start":
		if m != nil {
			return nil, errors.New("a move is already in progress for this slot")
		}
		pubHex, ok := phonePubHex(v)
		if !ok {
			return nil, errors.New("this slot has no phone key yet")
		}
		old := bluetooth.SlotPinPub(label)
		if old == nil {
			return nil, errors.New("no phone is pinned for this slot")
		}
		// The operator key moves separately (seed backup); the new phone
		// takes the owner from the old one, so the binding must exist here.
		if o, bound := s.ownerStore().get(v.ID); !bound || o.Granter == "" {
			return nil, errors.New("bind this slot's owner first (Owner key): a move carries the owner binding")
		}
		if err := bluetooth.SetHandoff(label, bluetooth.Handoff{Frozen: true}); err != nil {
			return nil, err
		}
		// Read the mark after freezing: no vote can land between them.
		hgt, err := lastSigned(v)
		if err != nil {
			return nil, fmt.Errorf("slot frozen, but its sign state is unreadable: %w", err)
		}
		pub, _ := hex.DecodeString(pubHex)
		nm := &move{label: label, chain: v.ChainID, slot: slotName(v), old: old, pub: pub, floor: hgt + handoffMargin, stage: "retire", started: handoffNow().Unix()}
		if _, err := rand.Read(nm.nonce[:]); err != nil {
			return nil, err
		}
		if err := nm.persist(false); err != nil {
			return nil, err
		}
		moves[label] = nm
		return map[string]any{"floor": nm.floor}, nil
	case "retire":
		if err := need("retire"); err != nil {
			return nil, err
		}
		target, sig, err := bluetooth.VerifyRetireV2(qr, m.chain, m.slot, m.pub, m.floor, m.nonce)
		if err != nil {
			return nil, err
		}
		if string(target) == string(m.old) {
			return nil, errors.New("retire proof names the old phone as the new one")
		}
		if err := bluetooth.RecordTombstone(label, bluetooth.Tombstone{KeyID: bluetooth.KeyIDHex(m.pub), OldPeer: hex.EncodeToString(m.old), NewPeer: hex.EncodeToString(target), Floor: m.floor, Nonce: hex.EncodeToString(m.nonce[:]), Sig: base64.StdEncoding.EncodeToString(sig), At: time.Now().UTC().Format(time.RFC3339)}); err != nil {
			return nil, err
		}
		if err := bluetooth.RetirePeer(label, m.old); err != nil {
			return nil, err
		}
		m.target = target
		if err := m.persist(true); err != nil {
			return nil, err
		}
		m.stage = "pair"
		return map[string]any{"target_fp": fpHex(target)}, nil
	case "pair":
		if err := need("pair"); err != nil {
			return nil, err
		}
		known := false
		for _, d := range bluetooth.Devices() {
			if d.ID == bluetooth.DeviceID(m.target) {
				known = true
			}
		}
		if p := bluetooth.PendingPub(); !known && string(p) != string(m.target) {
			if p == nil {
				return nil, errors.New("the new phone has not connected yet; open zigner on it and pair this KMS")
			}
			return nil, errors.New("the phone asking to pair is not the one in the retire proof")
		}
		if err := bluetooth.PinSlot(label, m.target); err != nil {
			return nil, err
		}
		_ = bluetooth.RegisterDevice(m.target, "", "")
		m.stage = "finish"
		return map[string]any{"target_fp": fpHex(m.target)}, nil
	case "finish":
		if m != nil && m.stage != "finish" {
			return nil, fmt.Errorf("move is at %q", m.stage)
		}
		if m == nil {
			if _, ok := bluetooth.LastTombstone(label); !ok {
				return nil, errors.New("nothing to finish")
			}
		}
		h, _ := bluetooth.GetHandoff(label)
		if err := bluetooth.SetHandoff(label, bluetooth.Handoff{Frozen: false, Floor: h.Floor}); err != nil {
			return nil, err
		}
		delete(moves, label)
		return map[string]any{"floor": h.Floor}, nil
	case "cancel":
		if m != nil && m.stage != "retire" {
			return nil, errors.New("old phone is retired; pair the new phone and finish")
		}
		h, _ := bluetooth.GetHandoff(label)
		if h.Sent {
			return nil, errors.New("old phone is retired; pair the new phone and finish")
		}
		if err := bluetooth.SetHandoff(label, bluetooth.Handoff{Frozen: false, Floor: h.Floor}); err != nil {
			return nil, err
		}
		delete(moves, label)
		return map[string]any{"note": "if the old phone already showed its move QR, cancel on both phones too; only the pinned phone can sign"}, nil
	}
	return nil, errors.New("unknown step")
}

func moveFromHandoff(label string, h bluetooth.Handoff) (*move, error) {
	dec := func(x string, n int) ([]byte, error) {
		b, err := hex.DecodeString(x)
		if err != nil || len(b) != n {
			return nil, errors.New("handoff file")
		}
		return b, nil
	}
	pub, err := dec(h.KeyPub, 32)
	if err != nil {
		return nil, err
	}
	old, err := dec(h.Old, 32)
	if err != nil {
		return nil, err
	}
	n, err := dec(h.Nonce, bluetooth.NonceSize)
	if err != nil {
		return nil, err
	}
	m := &move{label: label, chain: h.Chain, slot: h.Slot, old: old, pub: pub, floor: h.Floor, stage: "retire", started: h.StartedAt}
	if h.Sent {
		tgt, err := dec(h.Target, 32)
		if err != nil {
			return nil, err
		}
		m.target, m.stage = tgt, "pair"
		if _, ok := bluetooth.LastTombstone(label); ok && bluetooth.SlotAllows(label, tgt) == nil {
			m.stage = "finish"
		}
	}
	copy(m.nonce[:], n)
	return m, nil
}
