package uiserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const twoValidators = `chains:
  - id: morocco-1
validators:
  - chain_id: morocco-1
    name: zcinti
    addr: tcp://127.0.0.1:27159
    identity_key: identity.json
    rpc: RPC1
  - chain_id: morocco-1
    name: zcinti2
    addr: tcp://127.0.0.1:28159
    identity_key: identity.json
    rpc: RPC2
keys:
  - chain_ids: [morocco-1]
    backend: bluetooth
    peer: zigner-a
`

func fakeNode(t *testing.T, network, height string, power string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/block" {
			_, _ = w.Write([]byte(`{"result":{"block":{"last_commit":{"height":"` + height + `","signatures":[{"block_id_flag":2,"validator_address":"AB"}]}}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":{"node_info":{"network":"` + network + `","moniker":"m"},"sync_info":{"latest_block_height":"` + height + `","latest_block_time":"2026-01-01T00:00:00Z","catching_up":false},"validator_info":{"address":"AB","voting_power":"` + power + `"}}}`))
	}))
}

func TestValidatorsFromConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kms.yaml")
	if err := os.WriteFile(p, []byte(twoValidators), 0o600); err != nil {
		t.Fatal(err)
	}
	vs, err := ValidatorsFromConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 || vs[0].Name != "zcinti" || vs[1].Privval != "tcp://127.0.0.1:28159" {
		t.Fatalf("%+v", vs)
	}
	if vs[0].Signer != "phone" || vs[0].SignerRef != "zigner-a" || vs[1].RPC != "RPC2" {
		t.Fatalf("%+v", vs)
	}
}

func TestSignerOfFileKeyHidesPath(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kms.yaml")
	cfg := strings.Replace(twoValidators, "    backend: bluetooth\n    peer: zigner-a\n", "    key_file: /secret/dir/priv_validator_key.json\n", 1)
	_ = os.WriteFile(p, []byte(cfg), 0o600)
	vs, err := ValidatorsFromConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if vs[0].Signer != "file" || vs[0].SignerRef != "priv_validator_key.json" {
		t.Fatalf("%+v", vs[0])
	}
}

func TestSelectAndProbeValidators(t *testing.T) {
	n1 := fakeNode(t, "morocco-1", "100", "10")
	defer n1.Close()
	n2 := fakeNode(t, "other-1", "7", "0")
	defer n2.Close()
	s, err := New("127.0.0.1:0", n1.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetValidators([]ValidatorView{
		{Name: "a", ChainID: "morocco-1", RPC: n1.URL, Signer: "phone"},
		{Name: "b", ChainID: "morocco-1", RPC: n2.URL, Signer: "file"},
		{Name: "c", ChainID: "morocco-1", Signer: "file"},
	})
	s.probeValidators("")
	vs := s.Validators()
	if !vs[0].Active || vs[1].Active || vs[0].Status != "signing" || vs[0].Height != 100 {
		t.Fatalf("v0 %+v", vs[0])
	}
	if vs[1].Healthy || !strings.HasPrefix(vs[1].Status, "chain mismatch") {
		t.Fatalf("v1 %+v", vs[1])
	}
	if vs[2].Status != "no rpc" {
		t.Fatalf("v2 %+v", vs[2])
	}
	base := "http://" + s.Addr()
	post := func(path, id string) *http.Response {
		res, err := http.Post(base+path, "application/json", bytes.NewBufferString(`{"id":"`+id+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := post("/api/validators/select", "v9"); res.StatusCode != 404 {
		t.Fatal(res.Status)
	}
	if res := post("/api/validators/select", "v2"); res.StatusCode != 409 {
		t.Fatal(res.Status)
	}
	res := post("/api/validators/select", "v1")
	var out struct{ Validators []ValidatorView }
	_ = json.NewDecoder(res.Body).Decode(&out)
	res.Body.Close()
	if res.StatusCode != 200 || !out.Validators[1].Active || out.Validators[0].Active {
		t.Fatalf("%s %+v", res.Status, out)
	}
	s.mu.Lock()
	node, chain := s.node, s.chainID
	s.mu.Unlock()
	if node != n2.URL || chain != "morocco-1" {
		t.Fatalf("routed to %s %s", node, chain)
	}
	if res := post("/api/validators/refresh", "v0"); res.StatusCode != 200 {
		t.Fatal(res.Status)
	}
	js, err := http.Get(base + "/validators.js")
	if err != nil || js.StatusCode != 200 {
		t.Fatal(err)
	}
	js.Body.Close()
}
