package trust

import (
	"testing"

	"aead.dev/minisign"
)

func TestForAlpha(t *testing.T) {
	pk, ok := ForAlpha("0.28.0")
	if !ok {
		t.Fatal("missing")
	}
	if pk.ID() == 0 {
		t.Fatal("bad id")
	}
	if _, ok := ForAlpha("nope"); ok {
		t.Fatal("should not exist")
	}
}

func TestByIDResolvesLinuxLibertine(t *testing.T) {
	// linux-libertine entries map to keys in trust store
	for _, a := range []string{"0.0.23b", "0.0.24", "0.0.25", "0.0.26", "0.0.27"} {
		pk, ok := ForAlpha(a)
		if !ok {
			t.Fatalf("missing %s", a)
		}
		if _, ok := ByID(pk.ID()); !ok {
			t.Fatalf("byid failed for %s", a)
		}
	}
	var _ minisign.PublicKey
}
