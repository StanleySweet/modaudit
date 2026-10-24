package audit

import (
	"testing"
)

func TestExecutableDisguisedAsImage(t *testing.T) {
	s := &Scan{Entries: []Entry{{Name: "art/a.png", Kind: KindImage, SHA256: "x"}}}
	rulesAsset(s, map[string][]byte{"art/a.png": []byte("MZ\x90\x00")})
	if !hasCode(s.Findings, "ASSET_EXECUTABLE") {
		t.Fatal(s.Findings)
	}
}

func TestMalformedXML(t *testing.T) {
	s := &Scan{Entries: []Entry{{Name: "sim/a.xml", Kind: KindXML}}}
	rulesAsset(s, map[string][]byte{"sim/a.xml": []byte("<root><unclosed>")})
	if !hasCode(s.Findings, "XML_MALFORMED") {
		t.Fatal(s.Findings)
	}
}

func TestValidXMLHasNoFinding(t *testing.T) {
	s := &Scan{Entries: []Entry{{Name: "sim/a.xml", Kind: KindXML}}}
	rulesAsset(s, map[string][]byte{"sim/a.xml": []byte(`<root><a/></root>`)})
	if len(s.Findings) != 0 {
		t.Fatal(s.Findings)
	}
}

func TestExecutableExtensionBlocked(t *testing.T) {
	s := &Scan{Entries: []Entry{{Name: "run.exe", Kind: KindBinary}}}
	rulesAsset(s, map[string][]byte{"run.exe": []byte("hello")})
	if !hasCode(s.Findings, "ASSET_EXECUTABLE") {
		t.Fatal(s.Findings)
	}
}
