package audit

import (
	"archive/zip"
	"context"
	"io"
	"regexp"
	"strings"
)

// ScriptInfo describes a analysed script file.
type ScriptInfo struct {
	Path        string
	SHA256      string
	Bytes       int64
	EngineCalls []string
	Network     bool
	FileSystem  bool
	DynamicLoad bool
	Obfuscated  bool
	Signals     []string
}

// Has reports whether a signal was found.
func (s ScriptInfo) Has(code string) bool {
	for _, c := range s.Signals {
		if c == code {
			return true
		}
	}
	return false
}

var (
	reEval        = regexp.MustCompile(`\beval\s*\(`)
	reFunction    = regexp.MustCompile(`new\s+Function\s*\(`)
	reSetTimeoutS = regexp.MustCompile(`setTimeout\s*\(\s*["']`)
	reEngineCrash = regexp.MustCompile(`Engine\.Crash`)
	reEngineFS    = regexp.MustCompile(`Engine\.(Read|Write)File`)
	reNetwork     = regexp.MustCompile(`XMLHttpRequest|fetch\s*\(|WebSocket`)
	reDynamic     = regexp.MustCompile(`importScripts\s*\(`)
	reEngineLoad  = regexp.MustCompile(`Engine\.(Load|Include)Script`)
)

func analyzeScript(path string, body []byte) ScriptInfo {
	s := ScriptInfo{Path: path}
	text := string(body)
	if reEval.MatchString(text) || reFunction.MatchString(text) || reSetTimeoutS.MatchString(text) {
		s.Signals = append(s.Signals, "SCRIPT_EVAL")
	}
	if reEngineCrash.MatchString(text) {
		s.Signals = append(s.Signals, "SCRIPT_CRASH")
	}
	if reEngineFS.MatchString(text) {
		s.FileSystem = true
		s.Signals = append(s.Signals, "SCRIPT_FS")
	}
	if reNetwork.MatchString(text) {
		s.Network = true
		s.Signals = append(s.Signals, "SCRIPT_NETWORK")
	}
	if reDynamic.MatchString(text) || reEngineLoad.MatchString(text) {
		s.DynamicLoad = true
		s.Signals = append(s.Signals, "SCRIPT_DYNAMIC_LOAD")
	}
	if isObfuscated(text) {
		s.Obfuscated = true
		s.Signals = append(s.Signals, "SCRIPT_OBFUSCATED")
	}
	return s
}

func isObfuscated(text string) bool {
	if len(text) == 0 {
		return false
	}
	for _, line := range strings.Split(text, "\n") {
		if len(line) > 4000 {
			return true
		}
	}
	x := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '\\' && i+1 < len(text) && (text[i+1] == 'x' || text[i+1] == 'u') {
			x++
		}
	}
	if float64(x)/float64(len(text)) > 0.3 {
		return true
	}
	b64 := 0
	for _, line := range strings.Split(text, "\n") {
		b64 += countB64(line)
	}
	if b64 > 8000 {
		return true
	}
	return false
}

func countB64(s string) int {
	n := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			n++
		}
	}
	return n
}

// LoadScriptBodies reads requested entry bodies from the zip, capped per entry.
func LoadScriptBodies(ctx context.Context, zipPath string, names []string, maxBytes int64) (map[string][]byte, error) {
	if maxBytes <= 0 {
		return map[string][]byte{}, nil
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	out := map[string][]byte{}
	for _, zf := range zr.File {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if !want[zf.Name] {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(rc, maxBytes))
		rc.Close()
		out[zf.Name] = body
	}
	return out, nil
}

func rulesScript(s *Scan, bodies map[string][]byte) {
	for _, e := range s.Entries {
		if e.Kind != KindJS {
			continue
		}
		body, ok := bodies[e.Name]
		if !ok {
			continue
		}
		info := analyzeScript(e.Name, body)
		if info.Has("SCRIPT_EVAL") {
			s.AddFinding("SCRIPT_EVAL", SeverityBlocker, e.Name, "eval/Function/string setTimeout")
		}
		if info.Has("SCRIPT_CRASH") {
			s.AddFinding("SCRIPT_CRASH", SeverityBlocker, e.Name, "Engine.Crash")
		}
		if info.Has("SCRIPT_NETWORK") {
			s.AddFinding("SCRIPT_NETWORK", SeverityWarn, e.Name, "network API usage")
		}
		if info.Has("SCRIPT_FS") {
			s.AddFinding("SCRIPT_FS", SeverityWarn, e.Name, "file system API usage")
		}
		if info.Has("SCRIPT_DYNAMIC_LOAD") {
			s.AddFinding("SCRIPT_DYNAMIC_LOAD", SeverityWarn, e.Name, "dynamic script loading")
		}
		if info.Has("SCRIPT_OBFUSCATED") {
			s.AddFinding("SCRIPT_OBFUSCATED", SeverityWarn, e.Name, "obfuscation signals")
		}
	}
}
