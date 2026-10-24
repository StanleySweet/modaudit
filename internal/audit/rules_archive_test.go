package audit

import (
	"io/fs"
	"testing"
)

func hasCode(fs []Finding, code string) bool {
	for _, f := range fs {
		if f.Code == code {
			return true
		}
	}
	return false
}

func findCode(fs []Finding, code string) *Finding {
	for i := range fs {
		if fs[i].Code == code {
			return &fs[i]
		}
	}
	return nil
}

func TestArchiveTraversalAndSymlinks(t *testing.T) {
	s := &Scan{
		Limits: Limits{MaxRatio: 100},
		Entries: []Entry{
			{Name: "../evil.js"},
			{Name: "/etc/passwd"},
			{Name: `..\evil.js`},
			{Name: "mod/link", Mode: fs.ModeSymlink, Link: "/etc/passwd"},
			{Name: "mod/a.js"},
			{Name: "mod/a.js"},
			{Name: string([]byte{0xff, 0xfe}) + ".js"},
			{Name: "mod/enc.js", Flags: 1},
		},
	}
	rulesArchive(s)
	want := []string{
		"ZIP_PATH_TRAVERSAL", "ZIP_ABSOLUTE_PATH", "ZIP_SYMLINK",
		"ZIP_DUPLICATE_NAME", "ZIP_NAME_ENCODING", "ZIP_ENCRYPTED",
	}
	for _, code := range want {
		if !hasCode(s.Findings, code) {
			t.Errorf("missing %s in %+v", code, s.Findings)
		}
	}
}

func TestArchiveBombRatio(t *testing.T) {
	s := &Scan{
		Limits:            Limits{MaxRatio: 100},
		Entries:           []Entry{{Name: "a", Size: 50 << 20, CompressedSize: 1024}},
		TotalUncompressed: 50 << 20,
	}
	rulesArchive(s)
	if !hasCode(s.Findings, "ZIP_BOMB_RATIO") {
		t.Fatal(s.Findings)
	}
}

func TestArchiveSingleLargeAssetIsWarning(t *testing.T) {
	s := &Scan{
		Limits:  Limits{MaxRatio: 100},
		Entries: []Entry{{Name: "a.dds", Size: 70 << 20, CompressedSize: 70 << 20}},
	}
	rulesArchive(s)
	if hasCode(s.Findings, "ZIP_BOMB_RATIO") {
		t.Fatal(s.Findings)
	}
}
