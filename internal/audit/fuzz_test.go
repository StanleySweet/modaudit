package audit

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzNormalizeName(f *testing.F) {
	for _, s := range []string{"a/b", "../x", `a\b`, "/abs", `C:\x`, `..\..\x`, string([]byte{0xff})} {
		f.Add(s)
	}
	// NormalizeName keeps "/" and ".." so rulesArchive can flag them; the
	// property is that any name passing rulesArchive extracts inside the root.
	f.Fuzz(func(t *testing.T, name string) {
		s := &Scan{Entries: []Entry{{Name: name}}, Limits: testLimits()}
		rulesArchive(s)
		if hasBlocker(s) {
			return
		}
		norm, _ := NormalizeName(name)
		if strings.Contains(norm, `\`) {
			t.Fatalf("backslash survived: %q", norm)
		}
		if j := path.Join("/root", norm); j != "/root" && !strings.HasPrefix(j, "/root/") {
			t.Fatalf("%q escapes root as %q", name, j)
		}
	})
}

func FuzzRunOnArbitraryBytes(f *testing.F) {
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte("PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "m.zip")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = Run(context.Background(), p, Options{Limits: testLimits()})
	})
}
