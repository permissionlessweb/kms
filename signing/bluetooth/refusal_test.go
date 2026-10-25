package bluetooth

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestRefusalReasons(t *testing.T) {
	if parseRefusal([]byte{wireSig, 1}, "", "", 1, 0, 2) != nil {
		t.Fatal("a signature is not a refusal")
	}
	bare := parseRefusal([]byte{wireRefuse}, "", "", 10, 0, 2).Error()
	if strings.Contains(bare, "repeated or lower") || !strings.Contains(bare, "10/0/2") {
		t.Fatalf("bare refusal must not guess a reason: %s", bare)
	}
	floor := make([]byte, 13)
	binary.BigEndian.PutUint64(floor, 12)
	binary.BigEndian.PutUint32(floor[8:], 1)
	floor[12] = 3
	err := parseRefusal(append([]byte{wireRefuse, RefuseStale}, floor...), "", "zcinti", 11, 0, 2)
	var re *RefusalError
	if !errors.As(err, &re) || !re.HasFloor || !strings.Contains(err.Error(), "floor 12/1/3") || !strings.Contains(err.Error(), "key zcinti") {
		t.Fatalf("stale: %v", err)
	}
	if e := parseRefusal([]byte{wireRefuse, RefuseLocked}, "", "", 5, 0, 1).Error(); !strings.Contains(e, "locked") {
		t.Fatal(e)
	}
	if e := parseRefusal([]byte{wireRefuse}, "no noise session", "", 5, 0, 1).Error(); !strings.Contains(e, "no noise session") {
		t.Fatal(e)
	}
}
