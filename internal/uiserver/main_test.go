package uiserver

import (
	"os"
	"testing"

	"github.com/cosmos/kms/signing/bluetooth"
)

// TestMain keeps every test off the live link directory: New writes a
// runtime key under bluetooth.Dir.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "kms-ble-test")
	if err != nil {
		panic(err)
	}
	bluetooth.Dir = dir
	bluetooth.SupportDir = dir + "/support"
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
