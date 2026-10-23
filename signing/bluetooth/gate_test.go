package bluetooth

import "testing"

func TestAdmitRejectsACleartextVote(t *testing.T) {
	if Admit(false, false, []byte{msgSign, 1}) != "reject" {
		t.Fatal("cleartext vote before a session")
	}
	if Admit(true, false, []byte{msgSign, 1}) != "reject" {
		t.Fatal("cleartext vote after a session")
	}
	if Admit(false, true, []byte{0x30, 1}) != "reject" {
		t.Fatal("status before a session")
	}
	if Admit(true, true, []byte{0x30, 1}) != "status" {
		t.Fatal("status lane")
	}
	if Admit(true, false, []byte{0x30, 1}) != "reject" {
		t.Fatal("status on the vote lane")
	}
	if Admit(false, false, []byte{wireHello}) != "hello" {
		t.Fatal("hello")
	}
	if Admit(false, false, []byte{wireVote}) != "reject" {
		t.Fatal("vote before session")
	}
	if Admit(true, false, []byte{wireVote}) != "vote" {
		t.Fatal("sealed vote")
	}
	if Admit(false, false, []byte{0x20}) != "reject" {
		t.Fatal("import before session")
	}
	if Admit(true, false, []byte{0x24}) != "import" {
		t.Fatal("import after session")
	}
}
