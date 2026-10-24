package report

import (
	"strings"
	"testing"

	"github.com/stan/modaudit/internal/audit"
)

func TestBuildManifestAndStats(t *testing.T) {
	s := &audit.Scan{
		ZipSHA256: "abc",
		Verdict:   audit.VerdictRefuse,
		Entries: []audit.Entry{
			{Name: "mod.json", Size: 10, SHA256: "h1", Kind: audit.KindJSON},
			{Name: "a.js", Size: 20, SHA256: "h2", Kind: audit.KindJS},
			{Name: "a.xml", Size: 30, SHA256: "h3", Kind: audit.KindXML},
		},
	}
	r := Build(s)
	if r.Manifest["a.js"] != "h2" {
		t.Fatalf("%+v", r.Manifest)
	}
	if r.Stats.JavaScriptBytes != 20 || r.Stats.XMLBytes != 30 {
		t.Fatalf("%+v", r.Stats)
	}
}

func TestBulletsAreStableAndCapped(t *testing.T) {
	r := Report{
		Findings: []audit.Finding{
			{Code: "ZIP_SYMLINK", Severity: audit.SeverityBlocker, File: "a"},
			{Code: "ZIP_SYMLINK", Severity: audit.SeverityBlocker, File: "b"},
			{Code: "MODJSON_VERSION_FORMAT", Severity: audit.SeverityWarn},
		},
	}
	got := Bullets(r, 2)
	if len(got) != 2 {
		t.Fatalf("%v", got)
	}
	if !strings.Contains(got[0], "symlink") {
		t.Fatalf("%v", got)
	}
	again := Bullets(r, 2)
	if len(again) != len(got) || again[0] != got[0] {
		t.Fatal("unstable")
	}
}

func TestSerializeRejectsEmptyVerdict(t *testing.T) {
	_, err := Serialize(Report{SchemaVersion: 1, Manifest: map[string]string{}})
	if err == nil {
		t.Fatal("expected error")
	}
}
