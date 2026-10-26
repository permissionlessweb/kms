package uiserver

import (
	"encoding/json"
	"fmt"
	"github.com/cosmos/kms/internal/takeoff"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cosmos/kms/config"
)

// ValidatorView is one validator connection the console knows about, taken
// from a kms config file (validators + keys) or from the console flags.
// It never carries key material: only the key file base name or phone peer.
type ValidatorView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Source      string `json:"source"`
	ChainID     string `json:"chain_id"`
	Privval     string `json:"privval"`
	RPC         string `json:"rpc"`
	Signer      string `json:"signer"`
	SignerRef   string `json:"signer_ref"`
	Active      bool   `json:"active"`
	Healthy     bool   `json:"healthy"`
	CatchingUp  bool   `json:"catching_up"`
	Height      uint64 `json:"height"`
	LagMs       int64  `json:"lag_ms"`
	Moniker     string `json:"moniker"`
	ConsAddr    string `json:"consensus_addr"`
	VotingPower string `json:"voting_power"`
	LastSigned  uint64 `json:"last_signed"`
	// LastCommit is the newest height whose commit carries this validator's
	// signature (read from the node, so it covers every signer kind);
	// LastCommitAgoS is its age. Status "signing" depends on these, not on
	// voting power alone.
	LastCommit     uint64    `json:"last_commit"`
	LastCommitAgoS int64     `json:"last_commit_ago_s"`
	lastCommitAt   time.Time `json:"-"`
	Status         string    `json:"status"`
	Error          string    `json:"error"`
	Actions        []string  `json:"actions"`
	// Slot is the config chain entry (its own sign-state); ChainID is the
	// on-chain id. They differ when one engine runs several keys per chain.
	Slot   string `json:"slot"`
	KeyID  string `json:"key_id"`
	Engine string `json:"engine"`
	// PhoneKey reports whether the phone has published a key for this slot.
	PhoneKey   bool   `json:"phone_key"`
	PhoneKeyID string `json:"phone_key_id"`
	SlotName   string `json:"slot_name"`
	// Jail is the validator's slashing state (nil until read).
	Jail *takeoff.JailInfo `json:"jail,omitempty"`
	// PhoneName is the name set on the phone (keys.json "name", sent by a
	// zigner with the name trailer); PhoneNames reports that support.
	PhoneName   string   `json:"phone_name,omitempty"`
	PhoneNames  bool     `json:"phone_names"`
	DisplayName string   `json:"display_name"`
	PhonePub    string   `json:"phone_pub,omitempty"` // ed25519 consensus pubkey (public)
	OnChain     *OnChain `json:"onchain,omitempty"`
	Owner       *Owner   `json:"owner,omitempty"`
	// OwnerDerived is the account address re-encoded from OnChain.Valoper.
	OwnerDerived string `json:"owner_derived,omitempty"`
}

type validatorSet struct {
	mu   sync.Mutex
	list []ValidatorView
}

// signerOf names the custodian a kms config binds to chainID.
func signerOf(c *config.Config, chainID string) (kind, ref string) {
	for _, k := range c.Keys {
		for _, id := range k.ChainIDs {
			if id != chainID {
				continue
			}
			switch k.Backend {
			case "", config.BackendFile:
				return "file", filepath.Base(k.KeyFile)
			case config.BackendBluetooth:
				return "phone", k.Peer
			case config.BackendPKCS11:
				return "pkcs11", k.KeyLabel
			case config.BackendAWSKMS:
				return "awskms", k.KeyID
			default:
				return string(k.Backend), ""
			}
		}
	}
	return "none", ""
}

// ValidatorsFromConfig lists every validator entry declared by one kms config.
// It parses only; it does not validate paths or open key files.
func ValidatorsFromConfig(path string) ([]ValidatorView, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	network := map[string]string{}
	for _, ch := range c.Chains {
		network[ch.ID] = ch.NetworkID()
	}
	out := make([]ValidatorView, 0, len(c.Validators))
	for i, v := range c.Validators {
		kind, ref := signerOf(c, v.ChainID)
		chain := network[v.ChainID]
		if chain == "" {
			chain = v.ChainID
		}
		name := v.Name
		if name == "" {
			name = fmt.Sprintf("%s #%d", v.ChainID, i+1)
		}
		out = append(out, ValidatorView{
			Name: name, Source: path, ChainID: chain, Slot: v.ChainID, Privval: v.Addr,
			RPC: strings.TrimRight(v.RPC, "/"), Signer: kind, SignerRef: ref,
		})
	}
	return out, nil
}

// SetValidators replaces the validator list. IDs are assigned by position.
// The entry whose RPC matches the console node is marked active.
func (s *Server) SetValidators(list []ValidatorView) {
	s.mu.Lock()
	node := s.node
	s.mu.Unlock()
	cp := dedupeValidators(list)
	for i := range cp {
		cp[i].ID = fmt.Sprintf("v%d", i)
		if cp[i].Slot == "" {
			cp[i].Slot = cp[i].ChainID
		}
		if cp[i].Engine == "" {
			cp[i].Engine = "not served"
		}
		cp[i].Active = cp[i].RPC != "" && cp[i].RPC == node
		cp[i].Actions = actionsFor(cp[i])
		if cp[i].Status == "" {
			cp[i].Status = "unknown"
		}
	}
	s.vals.mu.Lock()
	s.vals.list = cp
	s.vals.mu.Unlock()
}

func actionsFor(v ValidatorView) []string {
	a := []string{"refresh"}
	if v.RPC != "" && !v.Active {
		a = append(a, "select")
	}
	return a
}

// Validators returns a copy of the list.
func (s *Server) Validators() []ValidatorView {
	s.vals.mu.Lock()
	defer s.vals.mu.Unlock()
	out := make([]ValidatorView, len(s.vals.list))
	copy(out, s.vals.list)
	return out
}

func (s *Server) registerValidators(mux *http.ServeMux) {
	mux.HandleFunc("/api/validators", s.listValidators)
	mux.HandleFunc("/slot-qr.png", s.slotQR)
	mux.HandleFunc("/api/validators/select", s.guard(s.selectValidator))
	mux.HandleFunc("/api/validators/refresh", s.guard(s.refreshValidator))
	mux.HandleFunc("/validators.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, validatorsJS)
	})
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			s.probeValidators("")
			<-t.C
		}
	}()
}

func (s *Server) listValidators(w http.ResponseWriter, _ *http.Request) {
	list := s.Validators()
	s.mu.Lock()
	signs := s.st.Signs
	s.mu.Unlock()
	var last uint64
	for _, g := range signs {
		if g.Height > last {
			last = g.Height
		}
	}
	for i := range list {
		if list[i].Active && list[i].Signer == "phone" {
			list[i].LastSigned = last
		}
	}
	fillPhoneKeys(list)
	s.fillSlotInfo(list)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"validators": list})
}

func readID(r *http.Request) (string, error) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		return "", err
	}
	return body.ID, nil
}

func (s *Server) lookup(id string) (ValidatorView, bool) {
	for _, v := range s.Validators() {
		if v.ID == id {
			return v, true
		}
	}
	return ValidatorView{}, false
}

// selectValidator points the single-validator panels (height, signing log,
// takeoff) at another configured node. It does not move the privval dialer.
func (s *Server) selectValidator(w http.ResponseWriter, r *http.Request) {
	id, err := readID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	v, ok := s.lookup(id)
	if !ok {
		http.Error(w, "unknown validator", http.StatusNotFound)
		return
	}
	if v.RPC == "" {
		http.Error(w, "validator has no rpc in the config", http.StatusConflict)
		return
	}
	s.mu.Lock()
	s.node = v.RPC
	s.st.NodeURL = v.RPC
	s.prevHeight = 0
	s.prevBlock = time.Time{}
	s.blockMs = 0
	s.mu.Unlock()
	s.SetChain(v.ChainID)
	s.vals.mu.Lock()
	for i := range s.vals.list {
		s.vals.list[i].Active = s.vals.list[i].ID == id
		s.vals.list[i].Actions = actionsFor(s.vals.list[i])
	}
	s.vals.mu.Unlock()
	s.listValidators(w, r)
}

func (s *Server) refreshValidator(w http.ResponseWriter, r *http.Request) {
	id, err := readID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, ok := s.lookup(id); !ok {
		http.Error(w, "unknown validator", http.StatusNotFound)
		return
	}
	s.probeValidators(id)
	s.listValidators(w, r)
}

type nodeStatus struct {
	Result struct {
		NodeInfo struct {
			Network string `json:"network"`
			Moniker string `json:"moniker"`
		} `json:"node_info"`
		SyncInfo struct {
			LatestBlockHeight string `json:"latest_block_height"`
			LatestBlockTime   string `json:"latest_block_time"`
			CatchingUp        bool   `json:"catching_up"`
		} `json:"sync_info"`
		ValidatorInfo struct {
			Address     string `json:"address"`
			VotingPower string `json:"voting_power"`
		} `json:"validator_info"`
	} `json:"result"`
}

// probeValidators reads /status from each validator RPC (only id when set).
// It never dials the privval socket: a node accepts one signer there.
func (s *Server) probeValidators(id string) {
	client := http.Client{Timeout: 2 * time.Second}
	for _, v := range s.Validators() {
		if id != "" && v.ID != id {
			continue
		}
		u := v
		u.Error = ""
		if v.RPC == "" {
			u.Status = "no rpc"
		} else if st, err := fetchStatus(&client, v.RPC); err != nil {
			u.Healthy, u.Status, u.Error = false, "down", err.Error()
		} else {
			fmt.Sscan(st.Result.SyncInfo.LatestBlockHeight, &u.Height)
			u.Moniker = st.Result.NodeInfo.Moniker
			u.CatchingUp = st.Result.SyncInfo.CatchingUp
			u.ConsAddr = st.Result.ValidatorInfo.Address
			u.VotingPower = st.Result.ValidatorInfo.VotingPower
			if t, err := time.Parse(time.RFC3339Nano, st.Result.SyncInfo.LatestBlockTime); err == nil {
				u.LagMs = time.Since(t).Milliseconds()
			}
			u.Healthy = true
			switch {
			case st.Result.NodeInfo.Network != "" && v.ChainID != "" && st.Result.NodeInfo.Network != v.ChainID:
				u.Healthy, u.Status = false, "chain mismatch "+st.Result.NodeInfo.Network
			case u.CatchingUp:
				u.Status = "catching up"
			case u.VotingPower != "" && u.VotingPower != "0":
				if h, ok := committedIn(&client, v.RPC, u.ConsAddr); ok {
					u.LastCommit, u.lastCommitAt = h, time.Now()
				}
				u.Status = liveStatus(u.lastCommitAt, time.Now())
				if !u.lastCommitAt.IsZero() {
					u.LastCommitAgoS = int64(time.Since(u.lastCommitAt).Seconds())
				}
			default:
				u.Status = "synced, not in set"
			}
			if u.Jail = jailFor(v.RPC, u.ConsAddr); u.Jail != nil && u.Jail.Jailed {
				u.Status = "jailed"
				if u.Jail.Tombstoned {
					u.Status = "tombstoned"
				}
			}
		}
		s.vals.mu.Lock()
		for i := range s.vals.list {
			if s.vals.list[i].ID == v.ID {
				u.Active = s.vals.list[i].Active
				u.Engine, u.KeyID = s.vals.list[i].Engine, s.vals.list[i].KeyID
				u.Actions = actionsFor(u)
				s.vals.list[i] = u
			}
		}
		s.vals.mu.Unlock()
	}
}

func fetchStatus(c *http.Client, rpc string) (*nodeStatus, error) {
	resp, err := c.Get(rpc + "/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	var st nodeStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, err
	}
	return &st, nil
}

const validatorsJS = `(function(){
var main=document.querySelector("main"); if(!main) return;
var sec=document.createElement("section"); sec.id="vals"; sec.className="open";
sec.innerHTML='<button type="button" class="sum">Validators<small id="vals-sub">Every validator in the kms config</small></button>'+
'<div class="body"><table><thead><tr><th></th><th>Name</th><th>Chain</th><th>Node</th><th>Privval</th><th>Signer</th><th>Status</th><th>Height</th><th>Last signed</th><th></th></tr></thead><tbody id="vals-rows"></tbody></table><p id="vals-err"></p></div>';
var rail=main.querySelector(".rail"); if(rail&&rail.nextSibling){main.insertBefore(sec,rail.nextSibling);}else{main.appendChild(sec);}
function esc(t){var d=document.createElement("span");d.textContent=t==null?"":String(t);return d.innerHTML;}
function post(path,id){return fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:id})}).then(function(r){if(!r.ok){return r.text().then(function(t){throw new Error(t);});}return r.json();});}
function draw(d){
  var rows=(d.validators||[]).map(function(v){
    var acts=(v.actions||[]).map(function(a){return '<button data-act="'+esc(a)+'" data-id="'+esc(v.id)+'">'+(a==="select"?"Show":"Refresh")+'</button>';}).join(" ");
    return '<tr'+(v.active?' style="color:#9cf"':'')+'><td>'+(v.active?"●":"")+'</td><td>'+esc(v.name)+'</td><td>'+esc(v.chain_id)+'</td><td>'+esc(v.rpc||"—")+'</td><td>'+esc(v.privval)+'</td><td>'+esc(v.signer)+(v.signer_ref?' <small>'+esc(v.signer_ref)+'</small>':'')+'</td><td title="'+esc(v.error)+'">'+esc(v.status)+'</td><td>'+esc(v.height||"—")+'</td><td>'+esc(v.last_signed||"—")+'</td><td>'+acts+'</td></tr>';
  });
  document.getElementById("vals-rows").innerHTML=rows.join("");
  document.getElementById("vals-sub").textContent=(d.validators||[]).length+" configured";
}
function load(){fetch("/api/validators").then(function(r){return r.json();}).then(draw).catch(function(e){document.getElementById("vals-err").textContent=e.message;});}
sec.addEventListener("click",function(e){var b=e.target.closest("button[data-act]"); if(!b) return;
  var path=b.dataset.act==="select"?"/api/validators/select":"/api/validators/refresh";
  post(path,b.dataset.id).then(draw).catch(function(e){document.getElementById("vals-err").textContent=e.message;});});
load(); setInterval(load,3000);
})();`

// SetEngine records what the signing engine is doing for a config slot
// ("waiting for phone key", "dialing", "serving", "read-only", ...).
func (s *Server) SetEngine(source, slot, status, keyID string) {
	s.vals.mu.Lock()
	defer s.vals.mu.Unlock()
	for i := range s.vals.list {
		if s.vals.list[i].Slot == slot && (source == "" || s.vals.list[i].Source == source) {
			s.vals.list[i].Engine = status
			if keyID != "" {
				s.vals.list[i].KeyID = keyID
			}
		}
	}
}

// dedupeValidators keeps the first entry per slot. A slot is the chain plus
// its privval address, falling back to chain plus name, so a config passed
// both as --engine and --config lists each validator once.
func dedupeValidators(list []ValidatorView) []ValidatorView {
	seen := map[string]bool{}
	out := make([]ValidatorView, 0, len(list))
	for _, v := range list {
		k := v.ChainID + "|" + v.Privval
		if v.Privval == "" {
			k = v.ChainID + "|name:" + v.Name
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	return out
}

// signingWindow is how recent a commit signature must be to show "signing".
const signingWindow = 30 * time.Second

// liveStatus turns the last time this validator's signature appeared in a
// commit into a status. In the set but silent is not "signing".
func liveStatus(last, now time.Time) string {
	if last.IsZero() {
		return "in set, not signing"
	}
	if now.Sub(last) <= signingWindow {
		return "signing"
	}
	return "in set, not signing"
}

// committedIn reports whether the latest block's last_commit holds a commit
// signature from consAddr (hex), and that block's height minus one.
func committedIn(c *http.Client, rpc, consAddr string) (uint64, bool) {
	if consAddr == "" {
		return 0, false
	}
	resp, err := c.Get(strings.TrimRight(rpc, "/") + "/block")
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	var b blockResp
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return 0, false
	}
	return signedBy(b, consAddr)
}

type blockResp struct {
	Result struct {
		Block struct {
			LastCommit struct {
				Height     string `json:"height"`
				Signatures []struct {
					Flag    int    `json:"block_id_flag"`
					Address string `json:"validator_address"`
				} `json:"signatures"`
			} `json:"last_commit"`
		} `json:"block"`
	} `json:"result"`
}

func signedBy(b blockResp, consAddr string) (uint64, bool) {
	var h uint64
	fmt.Sscan(b.Result.Block.LastCommit.Height, &h)
	for _, sig := range b.Result.Block.LastCommit.Signatures {
		if sig.Flag == 2 && strings.EqualFold(sig.Address, consAddr) {
			return h, true
		}
	}
	return h, false
}
