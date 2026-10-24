package audit

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestInventoryHashesAndClassifies(t *testing.T) {
	p := writeZip(t,
		zipEntry{name: "mod/mod.json", body: `{"name":"x"}`},
		zipEntry{name: "mod/data/a.js", body: `Engine.Crash();`},
		zipEntry{name: "mod/art/a.dds", body: "DDS "},
	)
	s, err := Inventory(context.Background(), p, Limits{MaxEntries: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Entries) != 3 {
		t.Fatalf("entries = %d", len(s.Entries))
	}
	if s.Entries[1].Kind != KindJS {
		t.Fatalf("kind = %q", s.Entries[1].Kind)
	}
	want := fmt.Sprintf("%x", sha256.Sum256([]byte("Engine.Crash();")))
	if s.Entries[1].SHA256 != want {
		t.Fatalf("hash = %s want %s", s.Entries[1].SHA256, want)
	}
	if s.ZipSHA256 == "" {
		t.Fatal("missing archive hash")
	}
}

func TestInventoryAbortsOnEntryFlood(t *testing.T) {
	p := writeZip(t, floodEntries(10001)...)
	s, err := Inventory(context.Background(), p, Limits{MaxEntries: 10000})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Aborted || s.AbortCode != "ZIP_TOO_MANY_ENTRIES" {
		t.Fatalf("abort = %v %q", s.Aborted, s.AbortCode)
	}
	if len(s.Entries) > 10000 {
		t.Fatalf("kept %d entries", len(s.Entries))
	}
}
