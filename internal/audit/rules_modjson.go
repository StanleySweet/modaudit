package audit

import (
	"encoding/json"
	"regexp"
	"strings"
)

var modVersionRE = regexp.MustCompile(`^\d+(\.\d+)*$`)

var knownModJSON = map[string]bool{
	"name": true, "version": true, "label": true, "description": true,
	"dependencies": true, "url": true, "ignoreInCompatibilityChecks": true,
	"minEngineVersion": true, "type": true,
}

func parseModJSON(raw []byte) (ModInfo, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ModInfo{}, err
	}
	info := ModInfo{}
	if v, ok := m["name"].(string); ok {
		info.Name = v
	}
	if v, ok := m["version"].(string); ok {
		info.Version = v
	}
	if v, ok := m["label"].(string); ok {
		info.Label = v
	}
	if v, ok := m["ignoreInCompatibilityChecks"].(bool); ok {
		info.IgnoreCompat = v
	}
	if d, ok := m["dependencies"].([]any); ok {
		for _, x := range d {
			if s, ok := x.(string); ok {
				info.Dependencies = append(info.Dependencies, s)
			}
		}
	}
	for k := range m {
		if !knownModJSON[k] {
			info.UnknownFields = append(info.UnknownFields, k)
		}
	}
	return info, nil
}

func rulesModJSON(s *Scan) {
	if len(s.ModJSONRaw) == 0 {
		s.AddFinding("LAYOUT_NO_MODJSON", SeverityBlocker, "", "no mod.json anywhere in the archive")
		return
	}
	info, err := parseModJSON(s.ModJSONRaw)
	if err != nil {
		s.AddFinding("MODJSON_INVALID", SeverityBlocker, "mod.json", err.Error())
		return
	}
	s.ModInfo = info
	for _, u := range info.UnknownFields {
		s.AddFinding("MODJSON_UNKNOWN_FIELD", SeverityInfo, "mod.json", "unknown field: "+u)
	}
	if info.Name == "" {
		s.AddFinding("MODJSON_MISSING_FIELD", SeverityBlocker, "mod.json", "missing name")
	}
	if info.Version == "" {
		s.AddFinding("MODJSON_MISSING_FIELD", SeverityBlocker, "mod.json", "missing version")
	}
	if info.Label == "" {
		s.AddFinding("MODJSON_MISSING_FIELD", SeverityBlocker, "mod.json", "missing label")
	}
	if info.Version != "" && !modVersionRE.MatchString(info.Version) {
		s.AddFinding("MODJSON_VERSION_FORMAT", SeverityBlocker, "mod.json", "version must be dotted numeric (e.g. 1.2 or 1.2.3)")
	}
	if info.IgnoreCompat {
		s.AddFinding("COMPAT_IGNORE_FLAG", SeverityBlocker, "mod.json", "ignoreInCompatibilityChecks is not allowed")
	}
	if s.Slug != "" && info.Name != "" {
		if !strings.EqualFold(info.Name, s.Slug) {
			s.AddFinding("MODJSON_NAME_MISMATCH", SeverityWarn, "mod.json", "name does not match queue slug")
		}
	}
	// engine dependency check
	if s.TargetAlpha != "" {
		if !EngineAdmits(info.Dependencies, s.TargetAlpha) {
			s.AddFinding("MODJSON_ENGINE_MISMATCH", SeverityBlocker, "mod.json", "engine dependency does not admit target alpha")
		}
	}
}
