package uiserver

import (
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/skip2/go-qrcode"

	"github.com/cosmos/kms/signing/bluetooth"
)

// slotName is the slot part of a config chain id ("morocco-1/zcinti2" ->
// "zcinti2"); a chain id without a slot falls back to the validator name.
func slotName(v ValidatorView) string {
	if i := strings.LastIndex(v.Slot, "/"); i >= 0 && i < len(v.Slot)-1 {
		return v.Slot[i+1:]
	}
	return v.Name
}

// slotKeyLabel is where the scanner publishes this slot's phone key.
func slotKeyLabel(v ValidatorView) string { return strings.ReplaceAll(v.Slot, "/", "_") }

// readPublished reads a file the scanner publishes about the phone's keys.
// Single-link mode writes it under bluetooth.Dir; mesh mode writes it per
// link under Dir/links/<code>/. The root copy wins, then the newest link.
func readPublished(rel string) ([]byte, error) {
	if raw, err := os.ReadFile(filepath.Join(bluetooth.Dir, rel)); err == nil {
		return raw, nil
	}
	links, _ := filepath.Glob(filepath.Join(bluetooth.Dir, "links", "*", rel))
	var best []byte
	var bestT int64 = -1
	for _, p := range links {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if raw, err := os.ReadFile(p); err == nil && st.ModTime().UnixNano() > bestT {
			best, bestT = raw, st.ModTime().UnixNano()
		}
	}
	if best == nil {
		return nil, os.ErrNotExist
	}
	return best, nil
}

// phoneKey reads the public key the phone published for this slot, if any.
func phoneKey(v ValidatorView) (string, bool) {
	raw, err := readPublished(filepath.Join("keys", slotKeyLabel(v), "pub.hex"))
	if err != nil {
		return "", false
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != 32 {
		return "", false
	}
	return bluetooth.KeyIDHex(b), true
}

// SlotQRPayload names the slot so the phone creates (or finds) the key for
// this validator: zcinti:1:terp:<chain>:<slot>. Not a private key.
func SlotQRPayload(v ValidatorView) string {
	return "zcinti:1:terp:" + v.ChainID + ":" + slotName(v)
}

// fillPhoneKeys marks which phone-signed slots already have a key on the phone.
func fillPhoneKeys(list []ValidatorView) {
	for i := range list {
		list[i].SlotName = slotName(list[i])
		if list[i].Signer != "phone" || list[i].Slot == "" {
			continue
		}
		list[i].PhoneKeyID, list[i].PhoneKey = phoneKey(list[i])
	}
}

// slotQR serves /slot-qr.png?id=<validator id>: the 5-field chain QR for that
// validator's slot. /slot-qr.png?pair=1 serves the 4-field pairing QR of the
// first validator's chain (phone link only).
func (s *Server) slotQR(w http.ResponseWriter, r *http.Request) {
	list := s.Validators()
	var payload string
	if r.URL.Query().Get("pair") != "" {
		if len(list) > 0 {
			payload = "zcinti:1:terp:" + list[0].ChainID
		}
	} else if v, ok := s.lookup(r.URL.Query().Get("id")); ok {
		payload = SlotQRPayload(v)
	}
	if payload == "" {
		http.Error(w, "unknown validator", http.StatusNotFound)
		return
	}
	png, err := qrcode.Encode(payload, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-QR-Payload", payload)
	_, _ = w.Write(png)
}
