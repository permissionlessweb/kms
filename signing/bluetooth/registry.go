package bluetooth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Device registry: the members of this KMS's phone mesh.
//
// peers/devices.json lists every phone this console has confirmed. It is the
// membership list a later threshold signer reads: each member is a Noise
// static (its mesh identity), the slots it serves, what it can do, and the
// message-type namespace it speaks. Pins stay the authority for signing;
// slots here are derived from peers/<slot>.peer (and the legacy global pin)
// on every read, so the registry can never authorize a phone by itself.
//
// Threshold signing plugs in as a capability, not a new trust path: a member
// that advertises CapFrost joins a signing group named in a group file next
// to the pins (members' device ids + threshold t-of-n); the coordinator
// sends round-1/round-2 frames in NamespaceFrost over the same per-device
// Noise sessions, and only to members of that group. Not built yet.

// Capabilities a member may advertise.
const (
	CapConsensusEd25519 = "consensus-ed25519" // whole-key CometBFT votes (0x12 frames)
	CapHandoffV2        = "handoff-v2"        // receive/export a slot key with a height floor
	CapFrost            = "frost-ed25519"     // future: threshold share holder
)

// Message-type namespaces. Each frame type on a session belongs to one.
const (
	NamespaceSign  = "zcinti.sign.v1"  // 0x50..0x5f session + vote frames
	NamespaceMove  = "zcinti.move.v2"  // 0x26 import, retire proofs
	NamespaceFrost = "zcinti.frost.v1" // future: threshold rounds
)

// Device is one mesh member.
type Device struct {
	ID    string   `json:"id"`    // 16 hex: sha256(noise)[:8]
	Noise string   `json:"noise"` // hex Noise static
	Label string   `json:"label"`
	Code  string   `json:"code,omitempty"` // last pairing code seen for it
	Caps  []string `json:"caps"`
	NS    []string `json:"ns"`
	Added string   `json:"added,omitempty"`
	// Slots is derived from the pins on read; it is not stored.
	Slots []string `json:"slots,omitempty"`
}

// DeviceID is the registry id of a Noise static.
func DeviceID(pub []byte) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

func registryPath(home string) (string, error) {
	pd, err := peersDir(home)
	if err != nil {
		return "", err
	}
	return filepath.Join(pd, "devices.json"), nil
}

func readRegistry(home string) []Device {
	p, err := registryPath(home)
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var out []Device
	_ = json.Unmarshal(raw, &out)
	return out
}

// RegisterDevice adds or updates pub in the registry. It does not pin.
func RegisterDevice(pub []byte, label, code string) error {
	return registerDevice(Dir, pub, label, code)
}

func registerDevice(home string, pub []byte, label, code string) error {
	if len(pub) != 32 {
		return errors.New("bluetooth: phone identity is not a public key")
	}
	slotMu.Lock()
	defer slotMu.Unlock()
	list := readRegistry(home)
	id := DeviceID(pub)
	found := false
	for i := range list {
		if list[i].ID == id {
			found = true
			if label != "" {
				list[i].Label = label
			}
			if code != "" {
				list[i].Code = code
			}
		}
	}
	if !found {
		if label == "" {
			label = "phone " + id[:4]
		}
		list = append(list, Device{
			ID: id, Noise: hex.EncodeToString(pub), Label: label, Code: code,
			Caps:  []string{CapConsensusEd25519, CapHandoffV2},
			NS:    []string{NamespaceSign, NamespaceMove},
			Added: time.Now().UTC().Format(time.RFC3339),
		})
	}
	for i := range list {
		list[i].Slots = nil
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	p, err := registryPath(home)
	if err != nil {
		return err
	}
	return writeAtomic(p, b)
}

// Devices lists the mesh: registered phones plus any pinned static that
// predates the registry, each with the slots its pins give it ("*" = the
// legacy global pin, every slot without its own pin).
func Devices() []Device { return devices(Dir) }

func devices(home string) []Device {
	slotMu.Lock()
	defer slotMu.Unlock()
	list := readRegistry(home)
	byID := map[string]int{}
	for i := range list {
		byID[list[i].ID] = i
		list[i].Slots = nil
	}
	add := func(pub []byte, slot string) {
		id := DeviceID(pub)
		i, ok := byID[id]
		if !ok {
			list = append(list, Device{ID: id, Noise: hex.EncodeToString(pub), Label: "phone " + id[:4],
				Caps: []string{CapConsensusEd25519}, NS: []string{NamespaceSign}})
			i = len(list) - 1
			byID[id] = i
		}
		if slot != "" {
			list[i].Slots = append(list[i].Slots, slot)
		}
	}
	if gp, err := globalPinPath(home); err == nil {
		if b := read32(gp); b != nil {
			add(b, "*")
		}
	}
	if pd, err := peersDir(home); err == nil {
		files, _ := filepath.Glob(filepath.Join(pd, "*.peer"))
		sort.Strings(files)
		for _, f := range files {
			if b := read32(f); b != nil {
				label := strings.TrimSuffix(filepath.Base(f), ".peer")
				if !isRetired(home, label, b) {
					add(b, label)
				}
			}
		}
	}
	return list
}

// DeviceByNoise finds the member with Noise static pub.
func deviceByNoise(home string, pub []byte) (Device, bool) {
	for _, d := range devices(home) {
		if b, err := hex.DecodeString(d.Noise); err == nil && bytes.Equal(b, pub) {
			return d, true
		}
	}
	return Device{}, false
}
