package report

import (
	"archive/zip"
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stan/modaudit/internal/audit"
	"github.com/stan/modaudit/internal/config"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Lives in report, not audit: an audit test importing report would be a cycle.
func TestGoldenRepackage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mod.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range [][2]string{
		{"MyMod/mod.json", `{"name":"mymod","version":"1.0.0","label":"My Mod"}`},
		{"MyMod/simulation/templates/a.xml", `<root/>`},
		{"MyMod/.DS_Store", "junk"},
	} {
		w, err := zw.Create(e[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := audit.Run(context.Background(), p, audit.Options{Slug: "mymod", Limits: audit.Limits(config.Default().Limits)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Serialize(Build(s))
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("..", "..", "testdata", "golden", "repackage-report.json")
	if *update {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("report differs from %s; rerun with -update if intended\n%s", golden, got)
	}
}
