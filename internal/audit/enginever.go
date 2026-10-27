package audit

import (
	"strconv"
	"strings"
)

// EngineAdmits reports whether alpha satisfies every 0ad constraint in deps;
// other mods' dependencies are ignored, and no 0ad constraint admits anything.
func EngineAdmits(deps []string, alpha string) bool {
	return EngineGap(deps, alpha) == ""
}

// EngineGap returns "" when deps admit alpha, "outdated" when a 0ad upper
// bound excludes it, and "unreleased" when a 0ad lower bound is above it.
func EngineGap(deps []string, alpha string) string {
	if alpha == "" {
		return ""
	}
	gap := ""
	for _, d := range deps {
		op, ver, ok := engineConstraint(d)
		if !ok {
			continue
		}
		c := CompareVersionStrings(alpha, ver)
		var admitted bool
		switch op {
		case "<=":
			admitted = c <= 0
		case "<":
			admitted = c < 0
		case ">=":
			admitted = c >= 0
		case ">":
			admitted = c > 0
		default: // "="
			admitted = c == 0
		}
		if admitted {
			continue
		}
		if op == "<" || op == "<=" || (op == "=" && c > 0) {
			return "outdated" // an upper bound excludes alpha
		}
		gap = "unreleased"
	}
	return gap
}

// engineConstraint parses "0ad<op><version>"; a bare "0ad" has no constraint.
func engineConstraint(dep string) (op, ver string, ok bool) {
	dep = strings.TrimSpace(dep)
	rest, found := strings.CutPrefix(dep, "0ad")
	if !found || rest == "" {
		return "", "", false
	}
	for _, o := range []string{"<=", ">=", "<", ">", "="} {
		if v, found := strings.CutPrefix(rest, o); found {
			return o, strings.TrimSpace(v), true
		}
	}
	return "", "", false // another mod whose name starts with 0ad
}

// CompareVersionStrings compares versions like engine does.
func CompareVersionStrings(a, b string) int {
	// split on -, _
	a = strings.Split(a, "-")[0]
	a = strings.Split(a, "_")[0]
	b = strings.Split(b, "-")[0]
	b = strings.Split(b, "_")[0]
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) < n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		ai, _ := strconv.Atoi(as[i])
		bi, _ := strconv.Atoi(bs[i])
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	if len(as) < len(bs) {
		return -1
	}
	if len(as) > len(bs) {
		return 1
	}
	return 0
}
