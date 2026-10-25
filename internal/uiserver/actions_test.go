package uiserver

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, err := New("127.0.0.1:0", "http://127.0.0.1:1", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	s.SetValidators([]ValidatorView{{Name: "zcinti", ChainID: "morocco-1", Slot: "morocco-1", RPC: "http://127.0.0.1:1", Privval: "tcp://127.0.0.1:27159"}})
	return s, "http://" + s.Addr()
}

func post(t *testing.T, url, token string, body any) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-KMS-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func TestTokenGuard(t *testing.T) {
	s, base := newTestServer(t)
	tok := s.EnableToken()
	if code, _ := post(t, base+"/api/actions/cancel", "", map[string]string{"id": "v0"}); code != http.StatusForbidden {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := post(t, base+"/api/actions/cancel", "wrong", map[string]string{"id": "v0"}); code != http.StatusForbidden {
		t.Fatalf("bad token: %d", code)
	}
	if code, body := post(t, base+"/api/actions/cancel", tok, map[string]string{"id": "v0"}); code != http.StatusOK {
		t.Fatalf("token: %d %s", code, body)
	}
	resp, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), tok) || !strings.Contains(string(page), `data-tab`) {
		t.Fatal("shell page must embed the token and tabs")
	}
	for _, gone := range []string{"/classic", "/signer", "/qr.png", "/kms-id.png", "/api/import", "/api/recover", "/api/takeoff"} {
		resp, err := http.Get(base + gone)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s should be gone, got %s", gone, resp.Status)
		}
	}
}

func TestReadOnlyRefusesStateChanges(t *testing.T) {
	s, base := newTestServer(t)
	s.SetReadOnly(true)
	for _, p := range []string{"/api/bluetooth", "/api/pair", "/api/confirm-phone", "/api/owners", "/api/actions/signature"} {
		if code, _ := post(t, base+p, "", map[string]any{}); code != http.StatusLocked {
			t.Fatalf("%s: %d, want 423", p, code)
		}
	}
	// review is pure planning and stays available; it validates before any rpc.
	code, body := post(t, base+"/api/actions/review", "", map[string]any{"id": "v0", "request": map[string]any{"action": "delegate", "granter": "nope"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, `"field":"granter"`) {
		t.Fatalf("review: %d %s", code, body)
	}
	code, body = post(t, base+"/api/actions/review", "", map[string]any{"id": "v0", "request": map[string]any{"action": "burn", "granter": "x"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, `"field":"action"`) {
		t.Fatalf("bad action: %d %s", code, body)
	}
}

func TestActionsNeedReviewFirst(t *testing.T) {
	_, base := newTestServer(t)
	if code, _ := post(t, base+"/api/actions/submit", "", map[string]string{"id": "v0", "fingerprint": "x"}); code == http.StatusOK || code == http.StatusConflict {
		t.Fatalf("the session submit endpoint must be gone: %d", code)
	}
	if code, _ := post(t, base+"/api/actions/signature", "", map[string]string{"id": "v0"}); code == http.StatusOK {
		t.Fatalf("broadcast without review: %d", code)
	}
	resp, _ := http.Get(base + "/api/actions/grant?id=v0")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("grant without review: %d", resp.StatusCode)
	}
}

func TestSetEngineAndNetworkSlot(t *testing.T) {
	s, _ := newTestServer(t)
	s.SetEngine("", "morocco-1", "serving", "ab12cd34ef567890")
	v, _ := s.lookup("v0")
	if v.Engine != "serving" || v.KeyID != "ab12cd34ef567890" {
		t.Fatalf("%+v", v)
	}
}
