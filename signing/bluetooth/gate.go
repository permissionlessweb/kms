package bluetooth

// Wire opcodes for one Noise session on the vote radio.
// Cleartext 0x10 and 0x30 are not votes and are not status.
const (
	wireHello  = byte(0x50)
	wireReply  = byte(0x51)
	wireFinish = byte(0x52)
	wireReady  = byte(0x53)
	wireVote   = byte(0x54)
	wireSig    = byte(0x55)
	wireRefuse = byte(0x5f)
)

// Admit says what a connected central is allowed to do.
// The advertisement code is not an authenticator. A vote or a key import
// requires a finished Noise session. Status is a different lane.
func Admit(sessionReady, statusLane bool, frame []byte) string {
	if len(frame) == 0 {
		return "reject"
	}
	op := frame[0]
	if statusLane {
		if sessionReady && op == 0x30 {
			return "status"
		}
		return "reject"
	}
	switch op {
	case wireHello:
		return "hello"
	case wireFinish:
		return "finish"
	case wireVote:
		if sessionReady {
			return "vote"
		}
		return "reject"
	case 0x20, 0x22, 0x24:
		if sessionReady {
			return "import"
		}
		return "reject"
	case msgSign, 0x30:
		return "reject"
	default:
		return "reject"
	}
}
