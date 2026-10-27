package audit

import (
	"strings"
	"testing"
)

func TestScriptSignals(t *testing.T) {
	cases := []struct {
		body, want string
	}{
		{"eval(\"x\")", "SCRIPT_EVAL"},
		{"new Function('return 1')", "SCRIPT_EVAL"},
		{"setTimeout(\"bad()\", 0)", "SCRIPT_EVAL"},
		{"Engine.Crash()", "SCRIPT_CRASH"},
		{"var r = new XMLHttpRequest();", "SCRIPT_NETWORK"},
		{"fetch('/x')", "SCRIPT_NETWORK"},
		{"Engine.WriteFile(\"x\", \"y\")", "SCRIPT_FS"},
		{"importScripts(\"http://x/y.js\")", "SCRIPT_DYNAMIC_LOAD"},
	}
	for _, c := range cases {
		info := analyzeScript("a.js", []byte(c.body))
		if !info.Has(c.want) {
			t.Errorf("%s: %+v", c.want, info)
		}
	}

	// obfuscation
	info := analyzeScript("a.js", []byte("var a=\""+strings.Repeat("QUJD", 4000)+"\";"))
	if !info.Has("SCRIPT_OBFUSCATED") {
		t.Fatalf("obfuscation not detected: %+v", info)
	}

	// base64 wrapped at 76 columns
	wrapped := strings.Repeat("\""+strings.Repeat("QUJD", 19)+"\" +\n", 120)
	if info := analyzeScript("a.js", []byte("var a="+wrapped+"\"\";")); !info.Has("SCRIPT_OBFUSCATED") {
		t.Fatalf("wrapped base64 not detected: %+v", info)
	}

	// long ordinary code is not obfuscation
	code := strings.Repeat("function updateModList(mods) {\n\tfor (let mod of mods)\n\t\tEngine.GetGUIObjectByName(\"modList\").list.push(mod.name);\n}\n", 400)
	if info := analyzeScript("a.js", []byte(code)); info.Has("SCRIPT_OBFUSCATED") {
		t.Fatalf("plain code flagged as obfuscated")
	}
}

func TestBenignScriptHasNoSignals(t *testing.T) {
	info := analyzeScript("a.js", []byte(`function Init(gameState) { return gameState; }`))
	if len(info.Signals) != 0 {
		t.Fatalf("%+v", info.Signals)
	}
}

func TestLoadScriptBodiesCaps(t *testing.T) {
	p := writeZip(t, zipEntry{name: "a.js", body: strings.Repeat("x", 10)}, zipEntry{name: "b.js", body: "y"})
	bodies, err := LoadScriptBodies(nil, p, []string{"a.js", "b.js"}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(bodies["a.js"]) != 5 {
		t.Fatalf("got %d", len(bodies["a.js"]))
	}
}
