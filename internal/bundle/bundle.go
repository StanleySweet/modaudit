package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/stan/modaudit/internal/audit"
	"github.com/stan/modaudit/internal/config"
	"github.com/stan/modaudit/internal/report"
)

// ErrBudget means the changed files do not fit the bundle caps. The caller
// must turn this into NEEDS_HUMAN; the bundle is never truncated.
var ErrBudget = errors.New("bundle: budget exceeded")

// File is one changed script sent for review. Content is untrusted.
type File struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Content string `json:"content"`
}

// Bundle is the compact LLM input written as bundle.json.
type Bundle struct {
	SchemaVersion int             `json:"schema_version"`
	ModJSON       json.RawMessage `json:"mod_json"`
	Findings      []audit.Finding `json:"findings"`
	Files         []File          `json:"files"`
	ManifestDiff  []string        `json:"manifest_diff"`
	ReportDigest  string          `json:"report_digest"`
}

// Build collects added or changed scripts against baseline, within lim.
func Build(ctx context.Context, zipPath string, r report.Report, baseline map[string]string, lim config.Limits) (Bundle, error) {
	modJSON, err := json.Marshal(r.ModJSON)
	if err != nil {
		return Bundle{}, err
	}
	digest, err := json.Marshal(r)
	if err != nil {
		return Bundle{}, err
	}
	sum := sha256.Sum256(digest)
	b := Bundle{
		SchemaVersion: 1,
		ModJSON:       modJSON,
		Findings:      r.Findings,
		Files:         []File{},
		ManifestDiff:  manifestDiff(r.Manifest, baseline),
		ReportDigest:  hex.EncodeToString(sum[:]),
	}

	var names []string
	for name, h := range r.Manifest {
		if kindOf(name) != "" && baseline[name] != h {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return b, nil
	}
	if len(names) > lim.MaxBundleFiles {
		return Bundle{}, ErrBudget
	}

	// Read one byte past the cap so an oversized script is detected, not truncated.
	bodies, err := audit.LoadScriptBodies(ctx, zipPath, names, lim.MaxScriptBytes+1)
	if err != nil {
		return Bundle{}, err
	}
	total := 0
	for _, name := range names {
		body := bodies[name]
		total += len(body)
		if int64(len(body)) > lim.MaxScriptBytes || total > lim.MaxBundleBytes {
			return Bundle{}, ErrBudget
		}
		b.Files = append(b.Files, File{Path: name, Kind: kindOf(name), Content: string(body)})
	}
	return b, nil
}

// kindOf returns the bundle kind for executable content, or "" to skip.
func kindOf(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".js"):
		return string(audit.KindJS)
	case strings.HasSuffix(lower, ".xml") && strings.Contains(lower, "simulation/"):
		return string(audit.KindXML)
	}
	return ""
}

func manifestDiff(cur, base map[string]string) []string {
	out := []string{}
	for name, h := range cur {
		old, ok := base[name]
		switch {
		case !ok:
			out = append(out, "added "+name)
		case old != h:
			out = append(out, "changed "+name)
		}
	}
	for name := range base {
		if _, ok := cur[name]; !ok {
			out = append(out, "removed "+name)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return pathOf(out[i]) < pathOf(out[j]) || (pathOf(out[i]) == pathOf(out[j]) && out[i] < out[j])
	})
	return out
}

func pathOf(line string) string {
	_, p, _ := strings.Cut(line, " ")
	return p
}
