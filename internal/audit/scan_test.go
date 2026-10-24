package audit

import (
	"context"
	"testing"
)

var validModJSON = []byte(`{"name":"mymod","version":"1.0.0","label":"My Mod"}`)

func TestVerdictMatrix(t *testing.T) {
	cases := []struct {
		name string
		s    *Scan
		want Verdict
	}{
		{"clean", &Scan{Entries: []Entry{{Name: "mod.json"}}, ModJSONRaw: validModJSON}, VerdictSign},
		{"blocker", &Scan{Findings: []Finding{{Code: "ZIP_PATH_TRAVERSAL", Severity: SeverityBlocker}}}, VerdictRefuse},
		{"packaging", &Scan{Findings: []Finding{{Code: "PACKAGE_MISSING_XMB", Severity: SeverityWarn}}}, VerdictRepackage},
		{"aborted", &Scan{Aborted: true, AbortCode: "ZIP_TOO_MANY_ENTRIES"}, VerdictRefuse},
		{"budget", &Scan{Findings: []Finding{{Code: "BUNDLE_BUDGET_EXCEEDED", Severity: SeverityWarn}}}, VerdictNeedsHuman},
	}
	for _, c := range cases {
		if got := VerdictOf(c.s); got != c.want {
			t.Errorf("%s: got %s", c.name, got)
		}
	}
}

func TestRunEndToEndRepackage(t *testing.T) {
	p := writeZip(t,
		zipEntry{name: "MyMod/mod.json", body: `{"name":"mymod","version":"1.0.0","label":"My Mod"}`},
		zipEntry{name: "MyMod/simulation/templates/a.xml", body: `<root/>`},
		zipEntry{name: "MyMod/.DS_Store", body: "junk"},
	)
	s, err := Run(context.Background(), p, Options{Slug: "mymod", Limits: testLimits()})
	if err != nil {
		t.Fatal(err)
	}
	if s.Verdict != VerdictRepackage {
		t.Fatalf("verdict = %s findings = %+v", s.Verdict, s.Findings)
	}
	if !hasCode(s.Findings, "PACKAGE_MISSING_XMB") {
		t.Fatalf("missing packaging finding: %+v", s.Findings)
	}
	if !hasCode(s.Findings, "LAYOUT_WRAPPER_DIR") {
		t.Fatalf("missing wrapper finding: %+v", s.Findings)
	}
}

func TestRunCleanModSigns(t *testing.T) {
	p := writeZip(t,
		zipEntry{name: "mod.json", body: `{"name":"okmod","version":"1.0.0","label":"Ok"}`},
		zipEntry{name: "simulation/templates/a.xmb", body: "XMBF"},
	)
	s, err := Run(context.Background(), p, Options{Slug: "okmod", Limits: testLimits()})
	if err != nil {
		t.Fatal(err)
	}
	if s.Verdict != VerdictSign {
		t.Fatalf("verdict = %s findings = %+v", s.Verdict, s.Findings)
	}
}

func testLimits() Limits {
	return Limits{MaxEntries: 10000, MaxUncompressed: 2 << 30, MaxRatio: 100, MaxFileSize: 64 << 20, MaxScriptBytes: 2 << 20, MaxBundleBytes: 200 * 1024, MaxBundleFiles: 50}
}
