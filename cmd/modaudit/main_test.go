package main

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stan/modaudit/internal/report"
)

func fixtureZip(t *testing.T, modJSON string, extra ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mod.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	files := append([]string{"mod.json", modJSON}, extra...)
	for i := 0; i < len(files); i += 2 {
		w, err := zw.Create(files[i])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(files[i+1])); err != nil {
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

func TestAuditExitCodes(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.json")
	clean := fixtureZip(t, `{"name":"m","version":"1.0","label":"M"}`)
	if code := run([]string{"audit", "--zip", clean, "--slug", "m", "--out", out}); code != 0 {
		t.Fatalf("clean exit = %d", code)
	}

	bad := fixtureZip(t, `{"name":"m","version":"1.0","label":"M","ignoreInCompatibilityChecks":true}`, "simulation/components/a.js", "var a;")
	if got := run([]string{"audit", "--zip", bad, "--slug", "m", "--out", out}); got != 2 {
		t.Fatalf("refuse exit = %d", got)
	}

	unpackaged := fixtureZip(t, `{"name":"m","version":"1.0","label":"M"}`, "simulation/templates/a.xml", "<a/>")
	if got := run([]string{"audit", "--zip", unpackaged, "--out", out}); got != 4 {
		t.Fatalf("repackage exit = %d", got)
	}

	if got := run([]string{"audit", "--out", out}); got != 1 {
		t.Fatalf("missing --zip exit = %d", got)
	}
	if got := run([]string{"audit", "--zip", clean, "--out", out, "--config", filepath.Join(t.TempDir(), "nope.toml")}); got != 1 {
		t.Fatalf("missing --config exit = %d", got)
	}
}

func TestAuditBundleBudgetNeedsHuman(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, []byte("[limits]\nmax_bundle_bytes = 16\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := fixtureZip(t, `{"name":"m","version":"1.0","label":"M"}`, "a.js", strings.Repeat("x", 64))
	out := filepath.Join(dir, "report.json")
	bundlePath := filepath.Join(dir, "bundle.json")
	if got := run([]string{"audit", "--zip", p, "--out", out, "--bundle", bundlePath, "--config", cfg}); got != 3 {
		t.Fatalf("exit = %d", got)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var r report.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if r.Verdict != "NEEDS_HUMAN" {
		t.Fatalf("verdict = %s", r.Verdict)
	}
	if _, err := os.Stat(bundlePath); !os.IsNotExist(err) {
		t.Fatalf("bundle written despite budget: %v", err)
	}
}

func TestAuditWritesBundleAgainstBaseline(t *testing.T) {
	dir := t.TempDir()
	p := fixtureZip(t, `{"name":"m","version":"1.0","label":"M"}`, "a.js", "ok();")
	out := filepath.Join(dir, "report.json")
	if got := run([]string{"audit", "--zip", p, "--out", out}); got != 0 {
		t.Fatalf("exit = %d", got)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if got := run([]string{"audit", "--zip", p, "--out", filepath.Join(dir, "r2.json"), "--baseline", out, "--bundle", bundlePath}); got != 0 {
		t.Fatalf("exit = %d", got)
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "ok();") {
		t.Fatal("unchanged script was bundled")
	}
}
