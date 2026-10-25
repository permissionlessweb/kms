package bluetooth

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Refusal codes the phone (or the BLE bridge) may append after wireRefuse:
//
//	[0x5f]                                   bare refusal, no reason (older zigner)
//	[0x5f][code u8][detail...]               coded refusal
//	  code 0x01 stale:   detail = floor h u64 | r u32 | s u8   (the phone's high-water mark)
//	  code 0x02..0x7f:   detail = optional UTF-8 text
//
// resp.json may also carry "reason" (free text from the scanner).
const (
	RefuseStale      = byte(0x01)
	RefuseUnknownKey = byte(0x02)
	RefuseNoSession  = byte(0x03)
	RefuseLocked     = byte(0x04)
	RefuseChain      = byte(0x05)
	RefuseUser       = byte(0x06)
)

// RefusalError is a refusal with the request it answered and the stated reason.
type RefusalError struct {
	Key      string // "" for the single-key link
	Height   uint64
	Round    uint32
	Step     uint8
	Code     byte // 0 when the reply gave none
	Reason   string
	FloorH   uint64
	FloorR   uint32
	FloorS   uint8
	HasFloor bool
}

func (e *RefusalError) Error() string {
	who := "phone"
	if e.Key != "" {
		who = "phone (key " + e.Key + ")"
	}
	req := fmt.Sprintf("%d/%d/%d", e.Height, e.Round, e.Step)
	switch {
	case e.HasFloor:
		return fmt.Sprintf("bluetooth: %s refused h/r/s %s: at or below its floor %d/%d/%d", who, req, e.FloorH, e.FloorR, e.FloorS)
	case e.Reason != "":
		return fmt.Sprintf("bluetooth: %s refused h/r/s %s: %s", who, req, e.Reason)
	default:
		return fmt.Sprintf("bluetooth: %s or the BLE bridge refused h/r/s %s without giving a reason (zigner too old to report one)", who, req)
	}
}

func codeText(c byte) string {
	switch c {
	case RefuseStale:
		return "repeated or lower height"
	case RefuseUnknownKey:
		return "the phone does not hold this key"
	case RefuseNoSession:
		return "no sealed session (re-pair or reopen the app)"
	case RefuseLocked:
		return "the phone is locked or signing is not armed"
	case RefuseChain:
		return "wrong chain for this key"
	case RefuseUser:
		return "rejected on the phone"
	}
	return fmt.Sprintf("refusal code 0x%02x", c)
}

// parseRefusal reports whether raw is a refusal and, if so, its error.
func parseRefusal(raw []byte, bridgeReason, key string, h uint64, r uint32, s uint8) error {
	if len(raw) == 0 || raw[0] != wireRefuse {
		return nil
	}
	e := &RefusalError{Key: key, Height: h, Round: r, Step: s}
	if len(raw) >= 2 {
		e.Code = raw[1]
		detail := raw[2:]
		if e.Code == RefuseStale && len(detail) >= 13 {
			e.FloorH = binary.BigEndian.Uint64(detail[0:8])
			e.FloorR = binary.BigEndian.Uint32(detail[8:12])
			e.FloorS = detail[12]
			e.HasFloor = true
		} else {
			e.Reason = codeText(e.Code)
			if t := strings.TrimSpace(string(detail)); t != "" && isText(t) {
				e.Reason += ": " + t
			}
		}
	}
	if b := strings.TrimSpace(bridgeReason); b != "" {
		if e.Reason == "" && !e.HasFloor {
			e.Reason = b
		} else {
			e.Reason += " (bridge: " + b + ")"
		}
	}
	return e
}

func isText(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return len(s) <= 200
}
