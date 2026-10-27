package audit

import (
	"testing"
)

func TestXMLWithoutXMB(t *testing.T) {
	s := &Scan{Entries: []Entry{
		{Name: "mod.json"},
		{Name: "simulation/templates/a.xml"},
	}}
	rulesPackaging(s)
	if !hasCode(s.Findings, "PACKAGE_MISSING_XMB") {
		t.Fatal(s.Findings)
	}
}

func TestXMLWithXMBIsPackaged(t *testing.T) {
	s := &Scan{Entries: []Entry{
		{Name: "mod.json"},
		{Name: "simulation/templates/a.xml"},
		{Name: "simulation/templates/a.xmb"},
	}}
	rulesPackaging(s)
	if hasCode(s.Findings, "PACKAGE_MISSING_XMB") {
		t.Fatal(s.Findings)
	}
}

func TestGUIXMLNotFlagged(t *testing.T) {
	s := &Scan{Entries: []Entry{
		{Name: "mod.json"},
		{Name: "gui/page/page.xml"},
	}}
	rulesPackaging(s)
	if hasCode(s.Findings, "PACKAGE_MISSING_XMB") {
		t.Fatal(s.Findings)
	}
}

func TestPackagingIssuesIgnoresBlockers(t *testing.T) {
	s := &Scan{Findings: []Finding{{Code: "ZIP_BOMB_RATIO", Severity: SeverityBlocker}}}
	if PackagingIssues(s) {
		t.Fatal("blocker counted as packaging")
	}
}

func TestXMLWithArchivebuildCacheIsPackaged(t *testing.T) {
	s := &Scan{Entries: []Entry{
		{Name: "mod.json"},
		{Name: "simulation/templates/a.xml"},
		{Name: "simulation/templates/a.xml.cached.xmb"},
	}}
	rulesPackaging(s)
	if hasCode(s.Findings, "PACKAGE_MISSING_XMB") {
		t.Fatal(s.Findings)
	}
}
