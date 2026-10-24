package audit

import (
	"archive/zip"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

type zipEntry struct {
	name  string
	body  string
	mode  fs.FileMode
	flags uint16
}

func writeZip(t *testing.T, entries ...zipEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mod.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Flags: e.flags}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func floodEntries(n int) []zipEntry {
	out := make([]zipEntry, n)
	for i := range out {
		out[i] = zipEntry{name: "f/" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".txt", body: "x"}
	}
	return out
}
