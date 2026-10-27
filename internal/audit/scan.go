package audit

import (
	"context"
)

// Options control a full scan.
type Options struct {
	Slug        string
	Limits      Limits
	Baseline    map[string]string
	TargetAlpha string
}

// Run inventories the zip and applies all rules in order.
func Run(ctx context.Context, zipPath string, opts Options) (*Scan, error) {
	lim := opts.Limits.normalized()
	s, err := Inventory(ctx, zipPath, lim)
	if err != nil {
		return nil, err
	}
	s.Slug = opts.Slug
	s.Limits = lim
	s.TargetAlpha = opts.TargetAlpha
	if s.Aborted {
		s.AddFinding(s.AbortCode, SeverityBlocker, "", "audit stopped at a hard cap")
		s.Verdict = VerdictRefuse
		return s, nil
	}

	var names []string
	for _, e := range s.Entries {
		if e.Kind == KindJS {
			names = append(names, e.Name)
		}
	}
	bodies, err := LoadScriptBodies(ctx, zipPath, names, lim.MaxScriptBytes)
	if err != nil {
		return nil, err
	}

	rulesArchive(s)
	rulesLayout(s)
	rulesModJSON(s)
	rulesScript(s, bodies)
	rulesAsset(s, bodies)
	rulesPackaging(s)

	s.Findings = sortFindings(s.Findings)
	s.Verdict = VerdictOf(s)
	return s, nil
}

// VerdictOf computes the outcome from findings and scan state.
func VerdictOf(s *Scan) Verdict {
	if s == nil {
		return VerdictRefuse
	}
	if s.Aborted {
		return VerdictRefuse
	}
	if hasBlocker(s) {
		return VerdictRefuse
	}
	for _, f := range s.Findings {
		if f.Code == "BUNDLE_BUDGET_EXCEEDED" {
			return VerdictNeedsHuman
		}
	}
	if PackagingIssues(s) {
		return VerdictRepackage
	}
	return VerdictSign
}

func hasBlocker(s *Scan) bool {
	for _, f := range s.Findings {
		if f.Severity == SeverityBlocker {
			return true
		}
	}
	return s != nil && s.Aborted
}

var severityOrder = map[Severity]int{SeverityBlocker: 0, SeverityWarn: 1, SeverityInfo: 2}

func sortFindings(fs []Finding) []Finding {
	out := make([]Finding, len(fs))
	copy(out, fs)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if severityOrder[out[i].Severity] > severityOrder[out[j].Severity] ||
				(severityOrder[out[i].Severity] == severityOrder[out[j].Severity] && out[i].Code > out[j].Code) ||
				(out[i].Code == out[j].Code && out[i].File > out[j].File) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
