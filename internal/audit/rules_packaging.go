package audit

import (
	"path"
	"strings"
)

var compileDirs = []string{"simulation/templates", "simulation/data", "simulation/components"}

func PackagingIssues(s *Scan) bool {
	if hasBlocker(s) {
		return false
	}
	for _, f := range s.Findings {
		if strings.HasPrefix(f.Code, "PACKAGE_") || strings.HasPrefix(f.Code, "LAYOUT_") {
			return true
		}
	}
	return false
}

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

	wrapper := ""
	for _, e := range s.Entries {
		norm, _ := NormalizeName(e.Name)
		if path.Base(norm) == "mod.json" && norm != "mod.json" {
			if i := strings.IndexByte(norm, '/'); i > 0 {
				wrapper = norm[:i+1]
			}
		}
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
		check := norm
		if wrapper != "" && strings.HasPrefix(norm, wrapper) {
			check = strings.TrimPrefix(norm, wrapper)
		}
		lc := strings.ToLower(check)
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
		// archivebuild (0.28) writes foo.xml.cached.xmb; foo.xmb is kept for older layouts
		xmb := strings.TrimSuffix(norm, ".xml") + ".xmb"
		cached := norm + ".cached.xmb"
		if !names[xmb] && !names[strings.ToLower(xmb)] && !names[cached] && !names[strings.ToLower(cached)] {
			s.AddFinding("PACKAGE_MISSING_XMB", SeverityWarn, e.Name,
				"simulation template XML has no compiled .xmb counterpart")
		}
	}
}
