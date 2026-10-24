package audit

import (
	"bytes"
	"encoding/xml"
	"path"
	"strings"
)

var execExt = map[string]bool{
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".node": true,
	".bat": true, ".cmd": true, ".ps1": true, ".sh": true, ".app": true,
}

func rulesAsset(s *Scan, bodies map[string][]byte) {
	for _, e := range s.Entries {
		body := bodies[e.Name]
		if len(body) == 0 {
			continue
		}
		ext := strings.ToLower(path.Ext(e.Name))
		if execExt[ext] {
			s.AddFinding("ASSET_EXECUTABLE", SeverityBlocker, e.Name, "executable file not allowed")
			continue
		}
		m := body
		if len(m) > 4 {
			m = m[:4]
		}
		if bytes.HasPrefix(body, []byte("MZ")) ||
			bytes.HasPrefix(body, []byte("\x7fELF")) ||
			bytes.HasPrefix(body, []byte("\xfe\xed\xfa")) ||
			bytes.HasPrefix(body, []byte("\xce\xfa\xed\xfe")) {
			if !execExt[ext] {
				s.AddFinding("ASSET_EXECUTABLE", SeverityBlocker, e.Name, "executable binary disguised by extension")
				continue
			}
		}
		if strings.HasPrefix(string(body), "#!") {
			s.AddFinding("ASSET_EXECUTABLE", SeverityBlocker, e.Name, "script with shebang")
			continue
		}
		if e.Kind == KindXML {
			if !isWellFormedXML(body) {
				s.AddFinding("XML_MALFORMED", SeverityWarn, e.Name, "XML is not well-formed")
			}
		}
		if e.Size > s.Limits.MaxFileSize/4 && (e.Kind == KindImage || e.Kind == KindBinary) {
			s.AddFinding("ASSET_OVERSIZED", SeverityInfo, e.Name, "large asset")
		}
	}
}

func isWellFormedXML(b []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		_, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				return true
			}
			return false
		}
	}
}
