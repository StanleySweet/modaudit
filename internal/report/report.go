package report

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/stan/modaudit/internal/audit"
)

// Stats summarises the archive contents.
type Stats struct {
	Files           int   `json:"files"`
	TotalBytes      int64 `json:"total_bytes"`
	JavaScriptBytes int64 `json:"javascript_bytes"`
	XMLBytes        int64 `json:"xml_bytes"`
}

// Report is the JSON output of an audit.
type Report struct {
	SchemaVersion int               `json:"schema_version"`
	Slug          string            `json:"slug"`
	ZipSHA256     string            `json:"zip_sha256"`
	Verdict       audit.Verdict     `json:"verdict"`
	ModJSON       audit.ModInfo     `json:"mod_json"`
	Findings      []audit.Finding   `json:"findings"`
	Entries       []audit.Entry     `json:"entries"`
	Stats         Stats             `json:"stats"`
	Manifest      map[string]string `json:"manifest"`
}

// Build constructs a report from a scan.
func Build(s *audit.Scan) Report {
	if s == nil {
		return Report{SchemaVersion: 1, Manifest: map[string]string{}}
	}
	r := Report{
		SchemaVersion: 1,
		Slug:          s.Slug,
		ZipSHA256:     s.ZipSHA256,
		Verdict:       s.Verdict,
		ModJSON:       s.ModInfo,
		Findings:      s.Findings,
		Entries:       s.Entries,
		Manifest:      map[string]string{},
	}
	for _, e := range s.Entries {
		if e.Name == "" {
			continue
		}
		r.Manifest[e.Name] = e.SHA256
		r.Stats.Files++
		r.Stats.TotalBytes += e.Size
		if e.Kind == audit.KindJS {
			r.Stats.JavaScriptBytes += e.Size
		}
		if e.Kind == audit.KindXML {
			r.Stats.XMLBytes += e.Size
		}
	}
	return r
}

// Serialize writes indented JSON and rejects a report with no verdict.
func Serialize(r Report) ([]byte, error) {
	if r.Verdict == "" {
		return nil, errors.New("report: empty verdict")
	}
	return json.MarshalIndent(r, "", "  ")
}

var commentText = map[string]string{
	"ZIP_TOO_MANY_ENTRIES":   "Archive has too many entries; this is usually a packing issue or abuse.",
	"ZIP_BOMB_RATIO":         "Archive compression ratio is suspiciously high (possible zip bomb).",
	"ZIP_PATH_TRAVERSAL":     "Archive contains entries that escape the root directory.",
	"ZIP_SYMLINK":            "Archive contains symlinks which are not allowed.",
	"ZIP_DUPLICATE_NAME":     "Archive contains duplicate entry names.",
	"ZIP_NAME_ENCODING":      "Archive entry names are not valid UTF-8.",
	"ZIP_ABSOLUTE_PATH":      "Archive contains absolute paths.",
	"ZIP_ENCRYPTED":          "Archive contains encrypted entries.",
	"LAYOUT_NO_MODJSON":      "No mod.json found in the archive.",
	"LAYOUT_WRAPPER_DIR":     "mod.json is not at the archive root; files are in a single top-level folder.",
	"LAYOUT_JUNK_FILE":       "Archive contains OS or VCS junk files.",
	"LAYOUT_NESTED_ARCHIVE":  "Archive contains another archive file.",
	"MODJSON_INVALID":        "mod.json is not valid JSON.",
	"MODJSON_MISSING_FIELD":  "mod.json is missing required fields (name, version, label).",
	"MODJSON_NAME_MISMATCH":  "mod.json name does not match the mod identifier.",
	"MODJSON_VERSION_FORMAT": "mod.json version must be dotted numeric (e.g. 1.2 or 1.2.3).",
	"COMPAT_IGNORE_FLAG":     "mod.json sets ignoreInCompatibilityChecks but the mod changes simulation/ files. Simulation changes make players with different mods go out of sync and can be used to cheat, so the flag is only allowed for mods that do not affect gameplay (GUI, art, translations). Remove the flag or the simulation changes.",
	"COMPAT_IGNORE_FLAG_SET": "mod.json sets ignoreInCompatibilityChecks; a reviewer checks the mod gives no unfair advantage in multiplayer.",
	"SCRIPT_EVAL":            "Script uses eval/Function/string-based setTimeout.",
	"SCRIPT_CRASH":           "Script calls Engine.Crash().",
	"SCRIPT_NETWORK":         "Script uses network APIs.",
	"SCRIPT_FS":              "Script uses file system APIs.",
	"SCRIPT_DYNAMIC_LOAD":    "Script dynamically loads other scripts.",
	"SCRIPT_OBFUSCATED":      "Script shows obfuscation signals.",
	"ASSET_EXECUTABLE":       "Archive contains disallowed executable files.",
	"XML_MALFORMED":          "An XML file is not well-formed.",
	"PACKAGE_MISSING_XMB":    "Simulation template XML has no compiled .xmb counterpart; mod is unpackaged.",
	"BUNDLE_BUDGET_EXCEEDED": "Too many new scripts to review within the token budget.",
}

// Bullets returns templated comment bullets, deduplicated by code, capped and sorted.
func Bullets(r Report, max int) []string {
	type item struct {
		code, file string
		sev        audit.Severity
	}
	items := map[string]item{}
	for _, f := range r.Findings {
		it, ok := items[f.Code]
		if !ok {
			items[f.Code] = item{code: f.Code, file: f.File, sev: f.Severity}
			continue
		}
		if f.File != "" && it.file == "" {
			items[f.Code] = item{code: f.Code, file: f.File, sev: f.Severity}
			continue
		}
		if f.Severity == audit.SeverityBlocker && it.sev != audit.SeverityBlocker {
			items[f.Code] = item{code: f.Code, file: it.file, sev: f.Severity}
		}
	}
	list := make([]item, 0, len(items))
	for _, v := range items {
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool {
		si := severityRank(list[i].sev)
		sj := severityRank(list[j].sev)
		if si != sj {
			return si < sj
		}
		return list[i].code < list[j].code
	})
	count := map[string]int{}
	for _, f := range r.Findings {
		count[f.Code]++
	}
	out := make([]string, 0, max+1)
	for _, it := range list {
		if len(out) >= max {
			break
		}
		text, ok := commentText[it.code]
		if !ok {
			text = "Rule " + it.code + " was triggered."
		}
		if count[it.code] > 1 {
			text = text + " (" + strconv.Itoa(count[it.code]) + " files)"
		}
		out = append(out, "- "+text)
	}
	if len(list) > max && max > 0 {
		out = append(out, "- (+"+strconv.Itoa(len(list)-max)+" more problems)")
	}
	return out
}

func severityRank(s audit.Severity) int {
	if s == audit.SeverityBlocker {
		return 0
	}
	if s == audit.SeverityWarn {
		return 1
	}
	return 2
}
