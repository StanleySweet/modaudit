package audit

import "testing"

func TestLayoutDetectsWrapperAndJunk(t *testing.T) {
	s := &Scan{Entries: []Entry{
		{Name: "MyMod/mod.json"},
		{Name: "MyMod/.DS_Store"},
		{Name: "__MACOSX/._x"},
		{Name: "MyMod/.git/config"},
		{Name: "MyMod/backup.zip"},
		{Name: "MyMod/file.js~"},
	}}
	rulesLayout(s)
	for _, code := range []string{"LAYOUT_WRAPPER_DIR", "LAYOUT_JUNK_FILE", "LAYOUT_NESTED_ARCHIVE"} {
		if !hasCode(s.Findings, code) {
			t.Errorf("missing %s in %+v", code, s.Findings)
		}
	}
	if hasCode(s.Findings, "LAYOUT_NO_MODJSON") {
		t.Fatal("mod.json exists inside the wrapper; must not be a blocker")
	}
}

func TestLayoutMissingModJSON(t *testing.T) {
	s := &Scan{Entries: []Entry{{Name: "data/a.js"}}}
	rulesLayout(s)
	if !hasCode(s.Findings, "LAYOUT_NO_MODJSON") {
		t.Fatal(s.Findings)
	}
	f := findCode(s.Findings, "LAYOUT_NO_MODJSON")
	if f.Severity != SeverityBlocker {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestLayoutCleanArchiveHasNoFindings(t *testing.T) {
	s := &Scan{Entries: []Entry{{Name: "mod.json"}, {Name: "data/a.js"}}}
	rulesLayout(s)
	if len(s.Findings) != 0 {
		t.Fatal(s.Findings)
	}
}
