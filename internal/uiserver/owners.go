package uiserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cosmos/kms/internal/takeoff"
	"github.com/cosmos/kms/signing/bluetooth"
)

// Owner is the account that owns one validator slot's on-chain validator
// (or will create it). It is console bookkeeping only: the signing engine
// never reads it, so setting or clearing it cannot affect block signing.
type Owner struct {
	Granter   string    `json:"granter"`
	PubkeyHex string    `json:"pubkey_hex,omitempty"`
	Name      string    `json:"name,omitempty"` // console name for the slot
	Updated   time.Time `json:"updated"`
}

// ownerStore persists owners per slot (config chain id, e.g. morocco-1/zcinti2).
type ownerStore struct {
	mu   sync.Mutex
	path string
	m    map[string]Owner
}

func loadOwners(path string) (*ownerStore, error) {
	o := &ownerStore{path: path, m: map[string]Owner{}}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return o, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &o.m); err != nil {
			return nil, fmt.Errorf("owners %s: %w", path, err)
		}
	}
	return o, nil
}

func (o *ownerStore) get(slot string) (Owner, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, ok := o.m[slot]
	return v, ok
}

func (o *ownerStore) all() map[string]Owner {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make(map[string]Owner, len(o.m))
	for k, v := range o.m {
		out[k] = v
	}
	return out
}

// put sets (or with clear deletes) one slot and writes the file atomically.
func (o *ownerStore) put(slot string, v *Owner) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	next := make(map[string]Owner, len(o.m)+1)
	for k, x := range o.m {
		next[k] = x
	}
	if v == nil {
		delete(next, slot)
	} else {
		next[slot] = *v
	}
	if o.path != "" {
		raw, _ := json.MarshalIndent(next, "", "  ")
		if err := os.MkdirAll(filepath.Dir(o.path), 0o700); err != nil {
			return err
		}
		tmp := o.path + ".tmp"
		if err := os.WriteFile(tmp, raw, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, o.path); err != nil {
			return err
		}
	}
	o.m = next
	return nil
}

// SetOwnersPath loads (or starts) the per-slot owner file.
func (s *Server) SetOwnersPath(path string) error {
	o, err := loadOwners(path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.owners = o
	s.mu.Unlock()
	return nil
}

func (s *Server) ownerStore() *ownerStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owners == nil {
		s.owners = &ownerStore{m: map[string]Owner{}} // memory only
	}
	return s.owners
}

func (s *Server) registerOwners(mux *http.ServeMux) {
	mux.HandleFunc("/api/owners", s.ownersHandler)
}

// ownersHandler: GET lists owners by validator id; POST {id, granter,
// pubkey_hex, name} sets one slot, {id, clear:true} clears it. Neither
// touches the engine, the scanner or the Bluetooth link.
func (s *Server) ownersHandler(w http.ResponseWriter, r *http.Request) {
	store := s.ownerStore()
	if r.Method == http.MethodGet {
		out := map[string]Owner{}
		for _, v := range s.Validators() {
			if o, ok := store.get(v.Slot); ok {
				out[v.ID] = o
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"owners": out})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "get or post", http.StatusMethodNotAllowed)
		return
	}
	if code, msg := s.allowPost(r); code != 0 {
		http.Error(w, msg, code)
		return
	}
	var body struct {
		ID        string `json:"id"`
		Granter   string `json:"granter"`
		PubkeyHex string `json:"pubkey_hex"`
		Name      string `json:"name"`
		Clear     bool   `json:"clear"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	v, ok := s.lookup(body.ID)
	if !ok || v.Slot == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown validator"})
		return
	}
	if body.Clear {
		if err := store.put(v.Slot, nil); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"slot": v.Slot, "cleared": true})
		return
	}
	o, _ := store.get(v.Slot)
	if g := strings.TrimSpace(body.Granter); g != "" {
		if !takeoff.ValidAccount(g) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"errors": []takeoff.FieldError{{Field: "granter", Message: "enter the terp1… account that owns the validator"}}})
			return
		}
		if g != o.Granter {
			o.PubkeyHex = "" // a pubkey belongs to one account
		}
		o.Granter = g
	}
	if p := strings.TrimSpace(body.PubkeyHex); p != "" {
		pub, err := hex.DecodeString(p)
		if err != nil || len(pub) != 33 || AccountAddress(pub) != o.Granter {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"errors": []takeoff.FieldError{{Field: "pubkey_hex", Message: "the pubkey is not this owner account's"}}})
			return
		}
		o.PubkeyHex = strings.ToLower(p)
	}
	if n := strings.TrimSpace(body.Name); n != "" {
		if len([]rune(n)) > 40 {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"errors": []takeoff.FieldError{{Field: "name", Message: "at most 40 characters"}}})
			return
		}
		o.Name = n
	}
	o.Updated = time.Now().UTC()
	if err := store.put(v.Slot, &o); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"slot": v.Slot, "owner": o})
}

// phonePubHex is the full ed25519 key the phone published for this slot.
func phonePubHex(v ValidatorView) (string, bool) {
	raw, err := os.ReadFile(filepath.Join(bluetooth.Dir, "keys", slotKeyLabel(v), "pub.hex"))
	if err != nil {
		return "", false
	}
	h := strings.ToLower(strings.TrimSpace(string(raw)))
	if b, err := hex.DecodeString(h); err != nil || len(b) != 32 {
		return "", false
	}
	return h, true
}

// phoneNames reads keys.json. A key entry carries "name" only when the
// phone sends the name trailer; names reports whether any entry did.
func phoneNames() (byLabel map[string]string, names bool) {
	raw, err := os.ReadFile(filepath.Join(bluetooth.Dir, "keys.json"))
	if err != nil {
		return nil, false
	}
	var doc struct {
		Keys []struct {
			Label string  `json:"label"`
			Name  *string `json:"name"`
		} `json:"keys"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil, false
	}
	byLabel = map[string]string{}
	for _, k := range doc.Keys {
		if k.Name != nil {
			names = true
			byLabel[k.Label] = *k.Name
		}
	}
	return byLabel, names
}

// OnChain is the validator registered for a slot's phone consensus key.
type OnChain struct {
	Checked  bool   `json:"checked"`
	Found    bool   `json:"found"`
	Valoper  string `json:"valoper,omitempty"`
	Moniker  string `json:"moniker,omitempty"`
	Status   string `json:"status,omitempty"`
	Jailed   bool   `json:"jailed,omitempty"`
	Tokens   string `json:"tokens,omitempty"`
	ConsAddr string `json:"consensus_addr,omitempty"`
	Error    string `json:"error,omitempty"`
}

const onchainTTL = 30 * time.Second

type onchainEntry struct {
	at time.Time
	oc OnChain
}

var (
	onchainMu    sync.Mutex
	onchainCache = map[string]onchainEntry{}
	// queryByCons is swapped in tests.
	queryByCons = takeoff.ValidatorByConsensus
)

// onchainFor looks up the validator for a phone key (cached). A failed
// query keeps the last good answer and never reports "not a validator".
func onchainFor(rpc, pubHex string) OnChain {
	pub, err := hex.DecodeString(pubHex)
	if rpc == "" || err != nil || len(pub) != 32 {
		return OnChain{}
	}
	cons := takeoff.ConsensusAddr(pub)
	key := rpc + "|" + cons
	onchainMu.Lock()
	e, ok := onchainCache[key]
	onchainMu.Unlock()
	if ok && time.Since(e.at) < onchainTTL {
		return e.oc
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	info, found, err := queryByCons(ctx, rpc, cons)
	cancel()
	if err != nil {
		oc := e.oc
		oc.Error = err.Error()
		onchainMu.Lock()
		onchainCache[key] = onchainEntry{at: time.Now(), oc: oc}
		onchainMu.Unlock()
		return oc
	}
	oc := OnChain{Checked: true, Found: found, ConsAddr: cons}
	if found {
		oc.Valoper, oc.Moniker, oc.Status, oc.Jailed, oc.Tokens = info.Operator, info.Moniker, info.Status, info.Jailed, info.Tokens
	}
	onchainMu.Lock()
	onchainCache[key] = onchainEntry{at: time.Now(), oc: oc}
	onchainMu.Unlock()
	return oc
}

func forgetOnchain() {
	onchainMu.Lock()
	onchainCache = map[string]onchainEntry{}
	onchainMu.Unlock()
}

// fillSlotInfo adds names, owner and on-chain registration to each slot.
func (s *Server) fillSlotInfo(list []ValidatorView) {
	names, supported := phoneNames()
	store := s.ownerStore()
	for i := range list {
		v := &list[i]
		v.PhoneNames = supported
		if n, ok := names[slotKeyLabel(*v)]; ok {
			v.PhoneName = n
		}
		if o, ok := store.get(v.Slot); ok {
			oc := o
			v.Owner = &oc
		}
		if v.Signer == "phone" {
			if pub, ok := phonePubHex(*v); ok {
				v.PhonePub = pub
				oc := onchainFor(v.RPC, pub)
				v.OnChain = &oc
			}
		}
		v.DisplayName = v.PhoneName
		if v.DisplayName == "" && v.Owner != nil {
			v.DisplayName = v.Owner.Name
		}
		if v.DisplayName == "" {
			v.DisplayName = v.SlotName
		}
	}
}
