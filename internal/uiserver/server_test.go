package uiserver

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestEnablePairAndSign(t *testing.T) {
	s, err := New("127.0.0.1:0", "http://127.0.0.1:1", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := "http://" + s.Addr()
	post := func(path, body string) *http.Response {
		t.Helper()
		res, err := http.Post(base+path, "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	res := post("/api/bluetooth", `{"enabled":true}`)
	res.Body.Close()
	if res.StatusCode != 500 {
		t.Fatalf("enable without a scanner: %s", res.Status)
	}
	res = post("/api/pair", `{}`)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 409 {
		t.Fatalf("pair before radio: %s %s", res.Status, body)
	}
	page, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer page.Body.Close()
	if page.StatusCode != 200 {
		t.Fatal(page.Status)
	}
	time.Sleep(10 * time.Millisecond)
}
