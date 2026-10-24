package audit

import (
	"path"
	"strings"
)

var compileDirs = []string{"simulation/templates", "simulation/data", "simulation/components"}

func hasBlocker(s *Scan) bool {
	for _, f := range s.Findings {
		if f.Severity == SeverityBlocker {
			return true
		}
	}
	return s.Aborted
}

func PackagingIssues(s *Scan) bool {
	if hasBlocker(s) {
		return false
	}
	for _, f := range s.Findings {
		if stringsHasPrefix(f.Code, "PACKAGE_") || stringsHasPrefix(f.Code, "LAYOUT_") {
			return true
		}
	}
	return false
}

func stringsHasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

func rulesPackaging(s *Scan) {
	if len(s.Entries) == 0 {
		return
	}
	names := map[string]bool{}
	for _, e := range s.Entries {
		norm, _ := NormalizeName(e.Name)
		names[norm] = true
		names[strings.ToLower(norm)] = true
	}

	for _, e := range s.Entries {
		norm, _ := NormalizeName(e.Name)
		if strings.ToLower(path.Ext(norm)) != ".xml" {
			continue
		}
		base := path.Base(norm)
		if base == "mod.json" {
			continue
		}
		lc := strings.ToLower(norm)
		inCompileDir := false
		for _, d := range compileDirs {
			if strings.HasPrefix(lc, strings.ToLower(d)+"/") {
				inCompileDir = true
				break
			}
		}
		if !inCompileDir {
			continue
		}
		xmb := strings.TrimSuffix(norm, ".xml") + ".xmb"
		if !names[xmb] && !names[strings.ToLower(xmb)] {
			s.AddFinding("PACKAGE_MISSING_XMB", SeverityWarn, e.Name,
				"simulation template XML has no compiled .xmb counterpart")
		}
	}
}
