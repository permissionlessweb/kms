package uiserver

import (
	"bytes"
	"encoding/hex"
	"sort"

	"github.com/cosmos/kms/signing/bluetooth"
)

// deviceViews joins the registry, each link's session and the scanner's
// per-code radio state into one row per phone.
func (s *Server) deviceViews(codes []string) []DeviceView {
	mesh := bluetooth.DefaultMesh()
	_, seen, _ := s.radio.Snapshot()
	states := s.radio.LinkStates()
	links := mesh.Links()
	var out []DeviceView
	used := map[string]bool{}
	for _, d := range bluetooth.Devices() {
		pub, _ := hex.DecodeString(d.Noise)
		v := DeviceView{ID: d.ID, Label: d.Label, Noise: d.Noise, Fingerprint: bluetooth.Fingerprint(pub),
			Code: d.Code, Slots: d.Slots, Caps: d.Caps, Link: "down"}
		var l *bluetooth.Link
		for c, cand := range links {
			if bytes.Equal(cand.SessionStatic(), pub) || (l == nil && bytes.Equal(cand.Remote(), pub)) {
				l, v.Code = cand, c
			}
		}
		if l == nil && !mesh.Enabled() {
			if root := mesh.Root(); bytes.Equal(root.SessionStatic(), pub) {
				l = root
			}
		}
		if l != nil {
			used[v.Code] = true
			switch {
			case bytes.Equal(l.SessionStatic(), pub):
				v.Link = "up"
			default:
				v.Link = "connecting"
			}
			if r := l.Recent(); len(r) > 0 {
				v.LastMs, v.LastAt = r[len(r)-1].LatencyMs, r[len(r)-1].At
			}
		}
		if v.Code != "" {
			if st := states[v.Code]; st == "down" && v.Link != "up" {
				v.Link = "down"
			}
			if rs, ok := seen[v.Code]; ok {
				rs := rs
				v.RSSI = &rs
			}
		}
		if len(v.Slots) == 0 && v.Link != "up" {
			v.Link = "standby" // registered, no pin: no session until a move pins a slot
		}
		out = append(out, v)
	}
	if p := bluetooth.PendingPub(); p != nil {
		if _, known := indexByNoise(out, p); !known {
			v := DeviceView{ID: bluetooth.DeviceID(p), Label: "new phone", Noise: hex.EncodeToString(p),
				Fingerprint: bluetooth.Fingerprint(p), Link: "pending", Pending: true}
			for c, l := range links {
				if bytes.Equal(l.Remote(), p) {
					v.Code = c
					used[c] = true
				}
			}
			out = append(out, v)
		}
	}
	// A chosen code whose phone has not answered yet.
	for _, c := range codes {
		if used[c] {
			continue
		}
		v := DeviceView{ID: "code-" + c, Label: "linking", Code: c, Link: "connecting"}
		if states[c] == "down" {
			v.Link = "down"
		}
		if rs, ok := seen[c]; ok {
			rs := rs
			v.RSSI = &rs
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Pending == false && out[j].Pending })
	return out
}

func indexByNoise(in []DeviceView, pub []byte) (int, bool) {
	h := hex.EncodeToString(pub)
	for i, v := range in {
		if v.Noise == h {
			return i, true
		}
	}
	return -1, false
}
