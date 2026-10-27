package repackage

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stan/modaudit/internal/audit"
)

const appPyrogenesis = "/Applications/0 A.D..app/Contents/MacOS/pyrogenesis"

func limits() audit.Limits {
	return audit.Limits{MaxEntries: 100000, MaxUncompressed: 2 << 30, MaxRatio: 100, MaxFileSize: 64 << 20, MaxScriptBytes: 2 << 20, MaxBundleBytes: 200 * 1024, MaxBundleFiles: 50}
}

func writeZip(t *testing.T, files map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for n, body := range files {
		w, _ := zw.Create(n)
		w.Write([]byte(body))
	}
	zw.Close()
	f.Close()
	return p
}

// fakeArchivebuild zips the source tree and adds <name>.cached.xmb per .xml, like pyrogenesis 0.28.
func fakeArchivebuild(extra map[string]string) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "-version" {
			return []byte("Pyrogenesis 0.28.0\n"), nil
		}
		src := strings.TrimPrefix(args[0], "-archivebuild=")
		out := strings.TrimPrefix(args[1], "-archivebuild-output=")
		f, err := os.Create(out)
		if err != nil {
			return nil, err
		}
		zw := zip.NewWriter(f)
		filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			if d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(src, p)
			b, _ := os.ReadFile(p)
			w, _ := zw.Create(filepath.ToSlash(rel))
			w.Write(b)
			if strings.HasSuffix(rel, ".xml") {
				w, _ = zw.Create(filepath.ToSlash(rel) + ".cached.xmb")
				w.Write([]byte("XMB"))
			}
			return nil
		})
		for n, b := range extra {
			w, _ := zw.Create(n)
			w.Write([]byte(b))
		}
		zw.Close()
		return nil, f.Close()
	}
}

func useRunner(t *testing.T, r func(context.Context, string, ...string) ([]byte, error)) {
	old := runCommand
	runCommand = r
	t.Cleanup(func() { runCommand = old })
}

const template = `<?xml version="1.0" encoding="utf-8"?>
<Entity parent="template_unit"><Identity><GenericName>X</GenericName></Identity></Entity>
`

func TestNextPatch(t *testing.T) {
	for in, want := range map[string]string{"1.2": "1.2.1", "1.2.3": "1.2.4", "0.28.9": "0.28.10"} {
		if got, err := NextPatch(in); err != nil || got != want {
			t.Errorf("%s: got %q %v, want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"", "1", "1.2-beta", "2024-01-01", "a.b"} {
		if _, err := NextPatch(in); !errors.Is(err, ErrVersion) {
			t.Errorf("%q: want ErrVersion, got %v", in, err)
		}
	}
}

func TestRebuildWrapperJunkAndBump(t *testing.T) {
	useRunner(t, fakeArchivebuild(nil))
	in := writeZip(t, map[string]string{
		"mymod/mod.json":                     `{"name":"mymod", "version": "1.2", "label":"M","dependencies":["0ad=0.28.0"]}`,
		"mymod/simulation/templates/foo.xml": template,
		"mymod/.DS_Store":                    "junk",
	})
	res, err := Rebuild(context.Background(), in, Options{Pyrogenesis: "pyro", Alpha: "0.28.0", Limits: limits(), WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res.OldVersion != "1.2" || res.NewVersion != "1.2.1" {
		t.Fatalf("versions %s -> %s", res.OldVersion, res.NewVersion)
	}
	if len(res.Added) != 1 || res.Added[0] != "simulation/templates/foo.xml.cached.xmb" {
		t.Fatalf("added %v", res.Added)
	}
	mj := readEntry(t, res.ZipPath, "mod.json")
	if mj != `{"name":"mymod", "version": "1.2.1", "label":"M","dependencies":["0ad=0.28.0"]}` {
		t.Fatalf("mod.json rewritten beyond the version: %s", mj)
	}

	// same input twice gives the same bytes
	res2, err := Rebuild(context.Background(), in, Options{Pyrogenesis: "pyro", Alpha: "0.28.0", Limits: limits(), WorkDir: t.TempDir()})
	if err != nil || res2.SHA256 != res.SHA256 {
		t.Fatalf("not reproducible: %s vs %s (%v)", res.SHA256, res2.SHA256, err)
	}
}

func TestRebuildAbortsOnUnexpectedFile(t *testing.T) {
	useRunner(t, fakeArchivebuild(map[string]string{"extra.txt": "surprise"}))
	in := writeZip(t, map[string]string{"mod.json": `{"name":"m","version":"1.0","label":"M"}`})
	_, err := Rebuild(context.Background(), in, Options{Pyrogenesis: "pyro", Alpha: "0.28.0", Limits: limits(), WorkDir: t.TempDir()})
	if !errors.Is(err, ErrUnexpectedChange) || !strings.Contains(err.Error(), "added extra.txt") {
		t.Fatalf("got %v", err)
	}
}

func TestRebuildRefusesWrongEngine(t *testing.T) {
	useRunner(t, func(context.Context, string, ...string) ([]byte, error) { return []byte("Pyrogenesis 0.27.1"), nil })
	in := writeZip(t, map[string]string{"mod.json": `{"name":"m","version":"1.0","label":"M"}`})
	if _, err := Rebuild(context.Background(), in, Options{Pyrogenesis: "pyro", Alpha: "0.28.0", Limits: limits(), WorkDir: t.TempDir()}); !errors.Is(err, ErrEngineVersion) {
		t.Fatalf("got %v", err)
	}
}

func TestRebuildRefusesTraversal(t *testing.T) {
	useRunner(t, fakeArchivebuild(nil))
	in := writeZip(t, map[string]string{"mod.json": `{"name":"m","version":"1.0","label":"M"}`, "../evil.js": "x"})
	if _, err := Rebuild(context.Background(), in, Options{Pyrogenesis: "pyro", Alpha: "0.28.0", Limits: limits(), WorkDir: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("got %v", err)
	}
}

func TestRebuildRealPyrogenesis(t *testing.T) {
	if _, err := os.Stat(appPyrogenesis); err != nil {
		t.Skip("pyrogenesis 0.28.0 not installed")
	}
	in := writeZip(t, map[string]string{
		"mod.json":                     `{"name":"m","version":"1.0","label":"M","dependencies":["0ad=0.28.0"]}`,
		"simulation/templates/foo.xml": template,
	})
	res, err := Rebuild(context.Background(), in, Options{Pyrogenesis: appPyrogenesis, Alpha: "0.28.0", Limits: limits(), WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 1 {
		t.Fatalf("added %v", res.Added)
	}
}

func readEntry(t *testing.T, zipPath, name string) string {
	t.Helper()
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name == name {
			rc, _ := f.Open()
			defer rc.Close()
			b, _ := io.ReadAll(rc)
			return string(b)
		}
	}
	t.Fatalf("%s not in zip", name)
	return ""
}
