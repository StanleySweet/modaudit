package audit

import (
	"path"
	"strings"
)

var junkNames = map[string]bool{
	".DS_Store": true, "Thumbs.db": true, ".git": true, "__MACOSX": true,
	"__pycache__": true, ".svn": true, ".hg": true,
}

var junkSuffixes = []string{"~", ".orig", ".rej", ".bak", ".swp"}

var nestedArchiveExts = map[string]bool{".zip": true, ".pyromod": true, ".7z": true, ".rar": true}

func rulesLayout(s *Scan) {
	hasRoot, hasAny := false, false
	firstSegs := map[string]bool{}
	var wrapperModJSON string

	for _, e := range s.Entries {
		norm, _ := NormalizeName(e.Name)
		base := path.Base(norm)
		if norm == "mod.json" {
			hasRoot = true
		}
		if base == "mod.json" {
			hasAny = true
			if !hasRoot && wrapperModJSON == "" {
				wrapperModJSON = e.Name
			}
		}
		if isJunk(norm) {
			s.AddFinding("LAYOUT_JUNK_FILE", SeverityWarn, e.Name, "OS, editor or VCS file")
			continue
		}
		if nestedArchiveExts[strings.ToLower(path.Ext(norm))] {
			s.AddFinding("LAYOUT_NESTED_ARCHIVE", SeverityWarn, e.Name, "archive nested inside the mod")
		}
		seg := norm
		if i := strings.IndexByte(norm, '/'); i > 0 {
			seg = norm[:i]
		}
		firstSegs[seg] = true
	}

	if !hasAny {
		s.AddFinding("LAYOUT_NO_MODJSON", SeverityBlocker, "", "no mod.json anywhere in the archive")
	} else if !hasRoot && wrapperModJSON != "" {
		if len(s.ModJSONRaw) == 0 {
			if body, err := readLimited(s.Path, wrapperModJSON, maxModJSON); err == nil {
				s.ModJSONRaw = body
			}
		}
		s.AddFinding("LAYOUT_WRAPPER_DIR", SeverityWarn, "", "mod.json is inside a top-level directory")
	}

	if !hasRoot && wrapperModJSON == "" && len(firstSegs) == 1 {
		for seg := range firstSegs {
			if seg != "mod.json" {
				s.AddFinding("LAYOUT_WRAPPER_DIR", SeverityWarn, seg+"/", "single top-level directory")
			}
		}
	}
}

func isJunk(norm string) bool {
	for _, seg := range strings.Split(norm, "/") {
		if junkNames[seg] {
			return true
		}
	}
	base := path.Base(norm)
	if junkNames[base] {
		return true
	}
	for _, suf := range junkSuffixes {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	return false
}
