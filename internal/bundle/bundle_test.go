package bundle

import (
	"archive/zip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stan/modaudit/internal/config"
	"github.com/stan/modaudit/internal/report"
)

type zipEntry struct{ name, body string }

func writeZip(t *testing.T, entries ...zipEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mod.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range entries {
		w, err := zw.Create(e.name)
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

func bundleLimits() config.Limits { return config.Default().Limits }

func bundleLimitsWith(bytes, files int) config.Limits {
	l := config.Default().Limits
	l.MaxBundleBytes = bytes
	l.MaxBundleFiles = files
	return l
}

func TestBundleIncludesOnlyChangedScripts(t *testing.T) {
	p := writeZip(t, zipEntry{name: "a.js", body: "Engine.Crash();"}, zipEntry{name: "b.js", body: "ok();"})
	r := report.Report{Manifest: map[string]string{"a.js": "new", "b.js": "same"}}
	b, err := Build(context.Background(), p, r, map[string]string{"a.js": "old", "b.js": "same"}, bundleLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Files) != 1 || b.Files[0].Path != "a.js" {
		t.Fatalf("%+v", b.Files)
	}
	if !strings.Contains(b.Files[0].Content, "Engine.Crash") {
		t.Fatal("content missing")
	}
}

func TestBundleBudgetIsAnError(t *testing.T) {
	p := writeZip(t, zipEntry{name: "big.js", body: strings.Repeat("x", 4096)})
	r := report.Report{Manifest: map[string]string{"big.js": "h"}}
	_, err := Build(context.Background(), p, r, nil, bundleLimitsWith(1024, 10))
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("err = %v", err)
	}
}

func TestBundleOversizedScriptIsNotTruncated(t *testing.T) {
	p := writeZip(t, zipEntry{name: "min.js", body: strings.Repeat("x", 2048)})
	r := report.Report{Manifest: map[string]string{"min.js": "h"}}
	lim := bundleLimits()
	lim.MaxScriptBytes = 1024
	if _, err := Build(context.Background(), p, r, nil, lim); !errors.Is(err, ErrBudget) {
		t.Fatalf("err = %v", err)
	}
}

func TestBundleFileCountCap(t *testing.T) {
	p := writeZip(t, zipEntry{name: "a.js", body: "a"}, zipEntry{name: "b.js", body: "b"})
	r := report.Report{Manifest: map[string]string{"a.js": "1", "b.js": "2"}}
	if _, err := Build(context.Background(), p, r, nil, bundleLimitsWith(1024, 1)); !errors.Is(err, ErrBudget) {
		t.Fatalf("err = %v", err)
	}
}

func TestBundleManifestDiffAndSelection(t *testing.T) {
	p := writeZip(t,
		zipEntry{name: "m/simulation/templates/u.xml", body: "<a/>"},
		zipEntry{name: "m/gui/page.xml", body: "<b/>"},
		zipEntry{name: "m/art/t.png", body: "png"},
	)
	r := report.Report{Manifest: map[string]string{
		"m/simulation/templates/u.xml": "1",
		"m/gui/page.xml":               "2",
		"m/art/t.png":                  "3",
	}}
	b, err := Build(context.Background(), p, r, map[string]string{"m/art/t.png": "old", "gone.js": "x"}, bundleLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Files) != 1 || b.Files[0].Path != "m/simulation/templates/u.xml" || b.Files[0].Kind != "xml" {
		t.Fatalf("%+v", b.Files)
	}
	want := []string{"removed gone.js", "changed m/art/t.png", "added m/gui/page.xml", "added m/simulation/templates/u.xml"}
	if !slices.Equal(b.ManifestDiff, want) {
		t.Fatalf("%v", b.ManifestDiff)
	}
	if len(b.ReportDigest) != 64 {
		t.Fatalf("digest %q", b.ReportDigest)
	}
}
