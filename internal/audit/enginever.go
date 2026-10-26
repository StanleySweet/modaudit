package audit

import (
	"strconv"
	"strings"
)

// EngineAdmits checks if alpha is admitted by deps.
func EngineAdmits(deps []string, alpha string) bool {
	if alpha == "" {
		return true
	}
	for _, d := range deps {
		if admitsOne(d, alpha) {
			return true
		}
	}
	// if no 0ad dep found, engine allows? but we need to check entries starting with 0ad
	if len(deps) == 0 {
		return true
	}
	// check all entries - if any 0ad entry exists, it must admit; if only other deps, different rule
	// but per spec only entries whose name before operator is 0ad checked; bare 0ad admits
	// if deps don't contain 0ad, return true?
	has0ad := false
	for _, d := range deps {
		if strings.HasPrefix(d, "0ad") {
			has0ad = true
			break
		}
	}
	if !has0ad {
		return true
	}
	// find first 0ad dep
	for _, d := range deps {
		if strings.HasPrefix(d, "0ad") {
			return admitsOne(d, alpha)
		}
	}
	return true
}

func admitsOne(dep, alpha string) bool {
	// bare 0ad admits
	if dep == "0ad" {
		return true
	}
	// operators in order: <= >= = < >
	// try <=
	if strings.Contains(dep, "<=") {
		parts := strings.Split(dep, "<=")
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == "0ad" {
			return cmp(le(parts[1], alpha))
		}
	}
	if strings.Contains(dep, ">=") {
		parts := strings.Split(dep, ">=")
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == "0ad" {
			return cmp(ge(parts[1], alpha))
		}
	}
	if strings.Contains(dep, "=") && !strings.Contains(dep, "<=") && !strings.Contains(dep, ">=") {
		parts := strings.Split(dep, "=")
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == "0ad" {
			return cmp(eq(parts[1], alpha))
		}
	}
	if strings.Contains(dep, "<") && !strings.Contains(dep, "<=") {
		parts := strings.Split(dep, "<")
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == "0ad" {
			return cmp(lt(parts[1], alpha))
		}
	}
	if strings.Contains(dep, ">") && !strings.Contains(dep, ">=") {
		parts := strings.Split(dep, ">")
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == "0ad" {
			return cmp(gt(parts[1], alpha))
		}
	}
	return true
}

type cmpRes int

const (
	cmpLess cmpRes = -1
	cmpEq   cmpRes = 0
	cmpGt   cmpRes = 1
)

func le(req, have string) cmpRes {
	// have <= req?
	if CompareVersionStrings(strings.TrimSpace(have), strings.TrimSpace(req)) <= 0 {
		return cmpEq
	}
	return cmpLess
}

func ge(req, have string) cmpRes {
	// have >= req?
	if CompareVersionStrings(strings.TrimSpace(have), strings.TrimSpace(req)) >= 0 {
		return cmpEq
	}
	return cmpLess
}

func eq(req, have string) cmpRes {
	if CompareVersionStrings(strings.TrimSpace(req), strings.TrimSpace(have)) == 0 {
		return cmpEq
	}
	return cmpLess
}

func lt(req, have string) cmpRes {
	if CompareVersionStrings(strings.TrimSpace(have), strings.TrimSpace(req)) < 0 {
		return cmpEq
	}
	return cmpLess
}

func gt(req, have string) cmpRes {
	if CompareVersionStrings(strings.TrimSpace(have), strings.TrimSpace(req)) > 0 {
		return cmpEq
	}
	return cmpLess
}

func cmp(r cmpRes) bool {
	return r == cmpEq
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
