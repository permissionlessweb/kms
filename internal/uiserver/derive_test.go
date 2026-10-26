package uiserver

import "testing"

func TestOwnerFromValoper(t *testing.T) {
	got, err := OwnerFromValoper("terpvaloper1fazvzt6pdpm4lg6t73h0j4dsyuc8tdxwjqt59r")
	if err != nil || got != "terp1fazvzt6pdpm4lg6t73h0j4dsyuc8tdxwrlwq9j" {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := OwnerFromValoper("terp1fazvzt6pdpm4lg6t73h0j4dsyuc8tdxwrlwq9j"); err == nil {
		t.Fatal("account address must not derive")
	}
	if _, err := OwnerFromValoper("terpvaloper1fazvzt6pdpm4lg6t73h0j4dsyuc8tdxwjqt59x"); err == nil {
		t.Fatal("bad checksum must fail")
	}
}
